use dmpf::{
    okvs::OkvsDmpf, Dmpf, DmpfKey, DpfOutput, EpsilonPercent, Node,
};
use rand::{thread_rng, RngCore, CryptoRng};
use std::fs;
use std::path::Path;
use std::time::Instant;
 
struct PsiProtocolSetup<const W: usize, Output: DpfOutput> {
    pub dmpf: OkvsDmpf<1, W, Output>,
    pub input_len: usize,
    pub threshold: usize,
}
 
impl<const W: usize, Output: DpfOutput> PsiProtocolSetup<W, Output> {
    pub fn new(input_len: usize, threshold: usize) -> Self {
        let dmpf = OkvsDmpf::<1, W, Output>::new(EpsilonPercent::Ten, 8);
        Self {
            dmpf,
            input_len,
            threshold,
        }
    }
}
 
fn additive_secret_share(x: u128, rng: &mut (impl RngCore + CryptoRng)) -> (u128, u128) {
    let share0 = rng.next_u64() as u128;
    let share1 = x.wrapping_sub(share0);
    (share0, share1)
}

fn reconstruct_secret(share0: u128, share1: u128) -> u128 {
    share0.wrapping_add(share1)
}
 
fn get_random_numeric_string_as_u128(length: usize, padding: bool, rng: &mut (impl RngCore + CryptoRng)) -> u128 {
    let mut output = String::with_capacity(length);
    
    if padding {
        output.push('1');
    } else {
        output.push('0');
    }
    
    for _ in 1..length {
        let digit = (rng.next_u32() % 10) as u8 + b'0';
        output.push(digit as char);
    }
    
    output.parse::<u128>().unwrap_or(0)
}
 
fn dealer_phase<const W: usize, Output: DpfOutput>(
    setup: &PsiProtocolSetup<W, Output>,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<u128>, Vec<u128>, Vec<u128>, Vec<u128>, dmpf::okvs::OkvsDmpfKey<1, W, Output>, dmpf::okvs::OkvsDmpfKey<1, W, Output>) {
    let threshold = setup.threshold;
    
    // 1. 生成R个随机数，R > T*T
    let mut random_x: Vec<u128> = Vec::with_capacity(threshold);
    let mut random_y: Vec<u128> = Vec::with_capacity(threshold);
    
    // 生成随机数rXi和rYj
    for _ in 0..threshold {
        random_x.push(rng.next_u64() as u128);
        random_y.push(rng.next_u64() as u128);
    }
    
    // 2. 构建多点函数fA,B
    let mut points: Vec<(u128, Output)> = Vec::new();
    let mut alpha_set = std::collections::HashSet::new();
    
    for i in 0..threshold {
        for j in 0..threshold {
            // 计算rX_i - rY_j
            let diff = random_x[i].wrapping_sub(random_y[j]);
            // 使用input_len位进行掩码
            let masked_diff = diff & ((1 << setup.input_len) - 1);
            // 编码为DMPF输入：左移到高位
            let alpha = masked_diff << (128 - setup.input_len);
            
            if alpha_set.insert(alpha) {
                let beta = Output::from(Node::from(1u128));
                points.push((alpha, beta));
            }
        }
    }
    
    // 按alpha值排序
    points.sort_by_key(|p| p.0);
    
    // 3. 使用DMPF的gen算法生成密钥k0、k1
    let (key0, key1) = setup.dmpf.try_gen(setup.input_len, &points, &mut *rng).unwrap();
    
    // 4. 将随机数进行加法秘密分享
    let mut random_x_share0: Vec<u128> = Vec::with_capacity(threshold);
    let mut random_x_share1: Vec<u128> = Vec::with_capacity(threshold);
    let mut random_y_share0: Vec<u128> = Vec::with_capacity(threshold);
    let mut random_y_share1: Vec<u128> = Vec::with_capacity(threshold);
    
    for &x in &random_x {
        let (share0, share1) = additive_secret_share(x, rng);
        random_x_share0.push(share0);
        random_x_share1.push(share1);
    }
    
    for &y in &random_y {
        let (share0, share1) = additive_secret_share(y, rng);
        random_y_share0.push(share0);
        random_y_share1.push(share1);
    }
    
    (random_x_share0, random_y_share0, random_x_share1, random_y_share1, key0, key1)
}
 
fn online_phase_computation<const W: usize, Output: DpfOutput>(
    key0: &dmpf::okvs::OkvsDmpfKey<1, W, Output>,
    key1: &dmpf::okvs::OkvsDmpfKey<1, W, Output>,
    random_x_share0: &[u128],
    random_y_share0: &[u128],
    random_x_share1: &[u128],
    random_y_share1: &[u128],
    set_x: &[u128],
    set_y: &[u128],
    input_len: usize,
    mut rng: &mut (impl RngCore + CryptoRng),
) -> usize {  // 修改返回类型为usize
    // 在线阶段步骤1：对集合元素进行秘密分享
    let mut set_x_share0: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut set_x_share1: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut set_y_share0: Vec<u128> = Vec::with_capacity(set_y.len());
    let mut set_y_share1: Vec<u128> = Vec::with_capacity(set_y.len());
    
    for &x in set_x {
        let (share0, share1) = additive_secret_share(x, &mut rng);
        set_x_share0.push(share0);
        set_x_share1.push(share1);
    }
    
    for &y in set_y {
        let (share0, share1) = additive_secret_share(y, &mut rng);
        set_y_share0.push(share0);
        set_y_share1.push(share1);
    }
    
    // 在线阶段步骤2：计算x'i = [xi]b + [rXi]b, y'j = [yj]b + [rYj]b
    let mut x0_prime_shares: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut y0_prime_shares: Vec<u128> = Vec::with_capacity(set_y.len());
    let mut x1_prime_shares: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut y1_prime_shares: Vec<u128> = Vec::with_capacity(set_y.len());
    
    for i in 0..set_x.len() {
        x0_prime_shares.push(set_x_share0[i].wrapping_add(random_x_share0[i]));
        x1_prime_shares.push(set_x_share1[i].wrapping_add(random_x_share1[i]));
    }
    
    for j in 0..set_y.len() {
        y0_prime_shares.push(set_y_share0[j].wrapping_add(random_y_share0[j]));
        y1_prime_shares.push(set_y_share1[j].wrapping_add(random_y_share1[j]));
    }
    
    // 在线阶段步骤3：双方重构x_i'和y_j'（交换份额后）
    let mut x_prime_reconstructed: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut y_prime_reconstructed: Vec<u128> = Vec::with_capacity(set_y.len());
    
    for i in 0..set_x.len() {
        let reconstructed = reconstruct_secret(x0_prime_shares[i], x1_prime_shares[i]);
        x_prime_reconstructed.push(reconstructed);
    }
    
    for j in 0..set_y.len() {
        let reconstructed = reconstruct_secret(y0_prime_shares[j], y1_prime_shares[j]);
        y_prime_reconstructed.push(reconstructed);
    }
    
    // 在线阶段步骤4：使用DMPF的eval算法计算[zij]b
    let mut results0 = Vec::new();
    let mut results1 = Vec::new();
    
    for &x_prime in &x_prime_reconstructed {
        for &y_prime in &y_prime_reconstructed {
            // 计算xi' - yj'
            let diff = x_prime.wrapping_sub(y_prime);
            // 使用input_len位进行掩码
            let masked_diff = diff & ((1 << input_len) - 1);
            // 编码为DMPF输入：左移到高位
            let eval_input = masked_diff << (128 - input_len);
            
            // 双方使用DMPF eval算法
            let mut output0 = Output::default();
            let mut output1 = Output::default();
            key0.eval(&eval_input, &mut output0);
            key1.eval(&eval_input, &mut output1);
            results0.push(output0);
            results1.push(output1);
        }
    }
    
    // 在线阶段步骤5：重构结果并统计交集大小（修改版）
    let mut intersection_count = 0;  // 改为计数器而不是向量
    
    for (i, (r0, r1)) in results0.iter().zip(results1.iter()).enumerate() {
        let sum = *r0 + *r1;
        // 检查是否为非零值（表示在交集中）
        if sum != Node::from(0u128).into() {
            let x_idx = i / set_y.len();
            let y_idx = i % set_y.len();
            if x_idx < set_x.len() && y_idx < set_y.len() {
                if set_x[x_idx] == set_y[y_idx] {
                    intersection_count += 1;  // 只计数，不存储元素
                }
            }
        }
    }
    
    intersection_count  // 返回计数而不是向量
}
 
fn generate_test_sets_with_intersection(
    set_size: usize,
    intersection_size: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<u128>, Vec<u128>, Vec<u128>) {
    const DEFAULT_LENGTH: usize = 16; // 默认16位数字字符串
    
    let mut set_x = Vec::with_capacity(set_size);
    let mut set_y = Vec::with_capacity(set_size);
    let mut intersection = Vec::with_capacity(intersection_size);
    
    // 生成交集元素（使用16位数字字符串，确保首位不为0）
    for _ in 0..intersection_size {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        intersection.push(elem);
        set_x.push(elem);
        set_y.push(elem);
    }
    
    // 生成X集合的独有元素
    for _ in 0..(set_size - intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        set_x.push(elem);
    }
    
    // 生成Y集合的独有元素
    for _ in 0..(set_size - intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        set_y.push(elem);
    }
    
    // 打乱集合顺序
    use rand::seq::SliceRandom;
    set_x.shuffle(rng);
    set_y.shuffle(rng);
    
    (set_x, set_y, intersection)
}

fn verify_psi_correctness(
    set_x: &[u128],
    set_y: &[u128],
    computed_count: usize,
    expected_count: usize,
) -> bool {
    let mut actual_intersection_size = 0;
    for &x in set_x {
        if set_y.contains(&x) {
            actual_intersection_size += 1;
        }
    }
    
    computed_count == expected_count && computed_count == actual_intersection_size
}

const PSI_INPUT_LENS: [usize; 1] = [8];
const PSI_THRESHOLDS: [usize; 1] = [10245];
const PSI_SET_SIZES: [usize; 1] = [10240];

struct SingleTestResult {
    offline_duration: std::time::Duration,
    online_duration: std::time::Duration,
    total_duration: std::time::Duration,
    intersection_size: usize,
}

impl SingleTestResult {
    fn print_and_save(&self, input_len: usize, threshold: usize, set_size: usize) {
        println!("\n=== PSI Protocol Test Result ===");
        println!("Input length: {}, Threshold: {}, Set size: {}", input_len, threshold, set_size);
        println!("Offline phase time: {:.2}ms", self.offline_duration.as_nanos() as f64 / 1_000_000.0);
        println!("Online phase time: {:.2}ms", self.online_duration.as_nanos() as f64 / 1_000_000.0);
        println!("Total time: {:.2}ms", self.total_duration.as_nanos() as f64 / 1_000_000.0);
        println!("Offline percentage: {:.2}%", self.offline_duration.as_nanos() as f64 / self.total_duration.as_nanos() as f64 * 100.0);
        println!("Online percentage: {:.2}%", self.online_duration.as_nanos() as f64 / self.total_duration.as_nanos() as f64 * 100.0);
        println!("Time ratio (offline/online): {:.2}", self.offline_duration.as_nanos() as f64 / self.online_duration.as_nanos() as f64);
        println!("Intersection size: {}", self.intersection_size);
        println!("================================\n");
        
        let param_dir = format!("data/psi_ca_okvs/input_{}_threshold_{}_set_{}", input_len, threshold, set_size);
        let summary_info = format!(
            "Input length: {}, Threshold: {}, Set size: {}\n\
            Offline phase time: {:.2}ms\n\
            Online phase time: {:.2}ms\n\
            Total time: {:.2}ms\n\
            Offline percentage: {:.2}%\n\
            Online percentage: {:.2}%\n\
            Time ratio (offline/online): {:.2}\n\
            Intersection size: {}",
            input_len, threshold, set_size,
            self.offline_duration.as_nanos() as f64 / 1_000_000.0,
            self.online_duration.as_nanos() as f64 / 1_000_000.0,
            self.total_duration.as_nanos() as f64 / 1_000_000.0,
            self.offline_duration.as_nanos() as f64 / self.total_duration.as_nanos() as f64 * 100.0,
            self.online_duration.as_nanos() as f64 / self.total_duration.as_nanos() as f64 * 100.0,
            self.offline_duration.as_nanos() as f64 / self.online_duration.as_nanos() as f64,
            self.intersection_size
        );
        fs::write(format!("{}/timing.txt", param_dir), summary_info).unwrap();
        
        fs::write(format!("{}/intersection_size.txt", param_dir), format!("{}", self.intersection_size)).unwrap();
    }
}

fn test_psi_protocol_once(input_len: usize, threshold: usize, set_size: usize) -> SingleTestResult {
    const W: usize = 49;
    
    let setup = PsiProtocolSetup::<W, Node>::new(input_len, threshold);
    let mut rng = thread_rng();
    
    let intersection_size = set_size / 4;
    let (set_x, set_y, expected_intersection) = 
        generate_test_sets_with_intersection(set_size, intersection_size, &mut rng);
    
    let param_dir = format!("data/psi_ca_okvs/input_{}_threshold_{}_set_{}", input_len, threshold, set_size);
    if !Path::new(&param_dir).exists() {
        fs::create_dir_all(&param_dir).unwrap();
    }
    
    fs::write(format!("{}/expected_intersection_size.txt", param_dir), 
             format!("{}", expected_intersection.len())).unwrap();
    
    println!("Starting PSI protocol test for input_{}_threshold_{}_set_{}", input_len, threshold, set_size);
    
    let total_start = Instant::now();
    
    let offline_start = Instant::now();
    let (rx0, ry0, rx1, ry1, key0, key1) = dealer_phase(&setup, &mut rng);
    let offline_duration = offline_start.elapsed();
    println!("Offline phase completed in {:.2}ms", offline_duration.as_nanos() as f64 / 1_000_000.0);
    
    let online_start = Instant::now();
    
    let computed_count = online_phase_computation( 
        &key0, &key1, &rx0, &ry0, &rx1, &ry1,
        &set_x, &set_y, input_len, &mut rng
    );
    
    let online_duration = online_start.elapsed();
    println!("Online phase completed in {:.2}ms", online_duration.as_nanos() as f64 / 1_000_000.0);
    
    let total_duration = total_start.elapsed();
    
    let is_correct = verify_psi_correctness(&set_x, &set_y, computed_count, expected_intersection.len());
    
    fs::write(format!("{}/computed_intersection_size.txt", param_dir), 
             format!("{}", computed_count)).unwrap();
    
    if !is_correct {
        panic!("PSI protocol verification failed for input_{}_threshold_{}_set_{}!", input_len, threshold, set_size);
    }
    
    println!("PSI protocol test passed! Intersection size: {}", computed_count);
    
    SingleTestResult {
        offline_duration,
        online_duration,
        total_duration,
        intersection_size: computed_count,
    }
}
 
fn main() {
        
    for &input_len in PSI_INPUT_LENS.iter() {
        for &threshold in PSI_THRESHOLDS.iter() {
            for &set_size in PSI_SET_SIZES.iter() {
                if set_size > threshold {
                    continue;
                }
                
                let result = test_psi_protocol_once(input_len, threshold, set_size);
                
                result.print_and_save(input_len, threshold, set_size);
            }
        }
    }

}