use dmpf::{
    okvs::OkvsDmpf, Dmpf, DmpfKey, DpfOutput, EpsilonPercent, Node,
};
use rand::{thread_rng, RngCore, CryptoRng};
use std::fs;
use std::path::Path;
use std::time::Instant;
 
// PSI协议相关结构体（保持不变）
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
 
// PSI协议结果结构体（新增）
struct PsiResult {
    intersection_count: usize,  // 交集元素个数
    weight_sum: u64,           // 权值和
}
 
impl PsiResult {
    fn new(intersection_count: usize, weight_sum: u64) -> Self {
        Self {
            intersection_count,
            weight_sum,
        }
    }
}
 
// 加法秘密分享
fn additive_secret_share(x: u128, rng: &mut (impl RngCore + CryptoRng)) -> (u128, u128) {
    let share0 = rng.next_u64() as u128;
    let share1 = x.wrapping_sub(share0);
    (share0, share1)
}
 
// 重构秘密
fn reconstruct_secret(share0: u128, share1: u128) -> u128 {
    share0.wrapping_add(share1)
}
 
// 生成固定长度的随机数字字符串并转换为u128
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
 
// Dealer角色：离线阶段密钥生成
fn dealer_phase<const W: usize, Output: DpfOutput>(
    setup: &PsiProtocolSetup<W, Output>,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<u128>, Vec<u128>, Vec<u128>, Vec<u128>, dmpf::okvs::OkvsDmpfKey<1, W, Output>, dmpf::okvs::OkvsDmpfKey<1, W, Output>) {
    let threshold = setup.threshold;
    
    let mut random_x: Vec<u128> = Vec::with_capacity(threshold);
    let mut random_y: Vec<u128> = Vec::with_capacity(threshold);
    
    for _ in 0..threshold {
        random_x.push(rng.next_u64() as u128);
        random_y.push(rng.next_u64() as u128);
    }
    
    let mut points: Vec<(u128, Output)> = Vec::new();
    let mut alpha_set = std::collections::HashSet::new();
    
    for i in 0..threshold {
        for j in 0..threshold {
            let diff = random_x[i].wrapping_sub(random_y[j]);
            let masked_diff = diff & ((1 << setup.input_len) - 1);
            let alpha = masked_diff << (128 - setup.input_len);
            
            if alpha_set.insert(alpha) {
                let beta = Output::from(Node::from(1u128));
                points.push((alpha, beta));
            }
        }
    }
    
    points.sort_by_key(|p| p.0);
    
    let (key0, key1) = setup.dmpf.try_gen(setup.input_len, &points, &mut *rng).unwrap();
    
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
 
// 参与方角色：在线阶段计算（修改版：同时返回交集个数和权值和）
fn online_phase_computation<const W: usize, Output: DpfOutput>(
    key0: &dmpf::okvs::OkvsDmpfKey<1, W, Output>,
    key1: &dmpf::okvs::OkvsDmpfKey<1, W, Output>,
    random_x_share0: &[u128],
    random_y_share0: &[u128],
    random_x_share1: &[u128],
    random_y_share1: &[u128],
    set_x: &[(u128, u64)],
    set_y: &[u128],
    input_len: usize,
    mut rng: &mut (impl RngCore + CryptoRng),
) -> PsiResult {  // 修改：返回PsiResult结构体
    
    // 在线阶段步骤1：对集合元素进行秘密分享
    let mut set_x_share0: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut set_x_share1: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut set_y_share0: Vec<u128> = Vec::with_capacity(set_y.len());
    let mut set_y_share1: Vec<u128> = Vec::with_capacity(set_y.len());
    
    // 对X集合的元素值进行秘密分享（权值不参与秘密分享）
    for (elem_value, _) in set_x {
        let (share0, share1) = additive_secret_share(*elem_value, &mut rng);
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
            let diff = x_prime.wrapping_sub(y_prime);
            let masked_diff = diff & ((1 << input_len) - 1);
            let eval_input = masked_diff << (128 - input_len);
            
            let mut output0 = Output::default();
            let mut output1 = Output::default();
            key0.eval(&eval_input, &mut output0);
            key1.eval(&eval_input, &mut output1);
            results0.push(output0);
            results1.push(output1);
        }
    }
    
    // 在线阶段步骤5：重构结果并计算交集个数和权值和（修改版）
    let mut intersection_count = 0usize;
    let mut weight_sum = 0u64;
    
    for (i, (r0, r1)) in results0.iter().zip(results1.iter()).enumerate() {
        let sum = *r0 + *r1;
        // 检查是否为非零值（表示在交集中）
        if sum != Node::from(0u128).into() {
            let x_idx = i / set_y.len();
            let y_idx = i % set_y.len();
            if x_idx < set_x.len() && y_idx < set_y.len() {
                // 检查元素值是否相等
                if set_x[x_idx].0 == set_y[y_idx] {
                    intersection_count += 1;      // 交集计数
                    weight_sum += set_x[x_idx].1;  // 累加权值
                }
            }
        }
    }
    
    PsiResult::new(intersection_count, weight_sum)  // 返回包含两个值的结构体
}
 
// 生成包含交集的测试数据（保持不变）
fn generate_test_sets_with_intersection(
    set_size: usize,
    intersection_size: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<(u128, u64)>, Vec<u128>, PsiResult) {  // 修改：返回PsiResult
    const DEFAULT_LENGTH: usize = 16;
    
    let mut set_x = Vec::with_capacity(set_size);
    let mut set_y = Vec::with_capacity(set_size);
    let mut expected_count = 0usize;
    let mut expected_weight_sum = 0u64;
    
    // 生成交集元素
    for _ in 0..intersection_size {
        let elem_value = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        let weight = (rng.next_u32() % 100) + 1;  // 权值范围1-100
        expected_count += 1;
        expected_weight_sum += weight as u64;
        
        set_x.push((elem_value, weight as u64));
        set_y.push(elem_value);
    }
    
    // 生成X集合的独有元素
    for _ in 0..(set_size - intersection_size) {
        let elem_value = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        let weight = (rng.next_u32() % 100) + 1;  // 权值范围1-100
        set_x.push((elem_value, weight as u64));
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
    
    let expected_result = PsiResult::new(expected_count, expected_weight_sum);
    (set_x, set_y, expected_result)
}
 
// 验证PSI协议正确性（修改版：验证交集个数和权值和）
fn verify_psi_correctness(
    set_x: &[(u128, u64)],
    set_y: &[u128],
    computed_result: &PsiResult,
    expected_result: &PsiResult,
) -> bool {
    // 计算实际的交集个数和权值和
    let mut actual_count = 0usize;
    let mut actual_weight_sum = 0u64;
    for (x_elem, x_weight) in set_x {
        if set_y.contains(x_elem) {
            actual_count += 1;
            actual_weight_sum += x_weight;
        }
    }
    
    // 验证计算结果
    computed_result.intersection_count == expected_result.intersection_count &&
    computed_result.weight_sum == expected_result.weight_sum &&
    computed_result.intersection_count == actual_count &&
    computed_result.weight_sum == actual_weight_sum
}
 
// PSI协议测试参数（保持不变）
const PSI_INPUT_LENS: [usize; 1] = [8];
const PSI_THRESHOLDS: [usize; 1] = [5];
const PSI_SET_SIZES: [usize; 1] = [4];
 
// 单次测试结果结构（修改版）
struct SingleTestResult {
    offline_duration: std::time::Duration,
    online_duration: std::time::Duration,
    total_duration: std::time::Duration,
    psi_result: PsiResult,  // 修改：存储PsiResult
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
        println!("Intersection count: {}", self.psi_result.intersection_count);
        println!("Weight sum: {}", self.psi_result.weight_sum);
        println!("Average weight per intersection element: {:.2}", 
                self.psi_result.weight_sum as f64 / self.psi_result.intersection_count.max(1) as f64);
        println!("================================\n");
        
        // 保存到参数特定的文件
        let param_dir = format!("data/psi_sum_okvs/input_{}_threshold_{}_set_{}", input_len, threshold, set_size);
        let summary_info = format!(
            "Input length: {}, Threshold: {}, Set size: {}\n\
            Offline phase time: {:.2}ms\n\
            Online phase time: {:.2}ms\n\
            Total time: {:.2}ms\n\
            Offline percentage: {:.2}%\n\
            Online percentage: {:.2}%\n\
            Time ratio (offline/online): {:.2}\n\
            Intersection count: {}\n\
            Weight sum: {}\n\
            Average weight per intersection element: {:.2}",
            input_len, threshold, set_size,
            self.offline_duration.as_nanos() as f64 / 1_000_000.0,
            self.online_duration.as_nanos() as f64 / 1_000_000.0,
            self.total_duration.as_nanos() as f64 / 1_000_000.0,
            self.offline_duration.as_nanos() as f64 / self.total_duration.as_nanos() as f64 * 100.0,
            self.online_duration.as_nanos() as f64 / self.total_duration.as_nanos() as f64 * 100.0,
            self.offline_duration.as_nanos() as f64 / self.online_duration.as_nanos() as f64,
            self.psi_result.intersection_count,
            self.psi_result.weight_sum,
            self.psi_result.weight_sum as f64 / self.psi_result.intersection_count.max(1) as f64
        );
        fs::write(format!("{}/timing.txt", param_dir), summary_info).unwrap();
        
        // 保存交集结果
        fs::write(format!("{}/intersection_count.txt", param_dir), 
                 format!("{}", self.psi_result.intersection_count)).unwrap();
        fs::write(format!("{}/weight_sum.txt", param_dir), 
                 format!("{}", self.psi_result.weight_sum)).unwrap();
    }
}
 
// 单次PSI协议测试（修改版）
fn test_psi_protocol_once(input_len: usize, threshold: usize, set_size: usize) -> SingleTestResult {
    const W: usize = 49;
    
    let setup = PsiProtocolSetup::<W, Node>::new(input_len, threshold);
    let mut rng = thread_rng();
    
    // 生成包含交集的测试数据
    let intersection_size = set_size / 4;
    let (set_x, set_y, expected_result) = 
        generate_test_sets_with_intersection(set_size, intersection_size, &mut rng);
    
    // 创建参数特定的子文件夹
    let param_dir = format!("data/psi_sum_okvs/input_{}_threshold_{}_set_{}", input_len, threshold, set_size);
    if !Path::new(&param_dir).exists() {
        fs::create_dir_all(&param_dir).unwrap();
    }
    
    // 保存期望的结果
    fs::write(format!("{}/expected_intersection_count.txt", param_dir), 
             format!("{}", expected_result.intersection_count)).unwrap();
    fs::write(format!("{}/expected_weight_sum.txt", param_dir), 
             format!("{}", expected_result.weight_sum)).unwrap();
    
    // 保存测试数据（可选，用于调试）
    fs::write(format!("{}/set_x.txt", param_dir), format!("{:?}", set_x)).unwrap();
    fs::write(format!("{}/set_y.txt", param_dir), format!("{:?}", set_y)).unwrap();
    
    println!("Starting PSI protocol test for input_{}_threshold_{}_set_{}", input_len, threshold, set_size);
    println!("Expected: {} intersection elements with total weight sum {}", 
            expected_result.intersection_count, expected_result.weight_sum);
    
    // 记录总时间开始
    let total_start = Instant::now();
    
    // ===== 离线阶段 =====
    let offline_start = Instant::now();
    let (rx0, ry0, rx1, ry1, key0, key1) = dealer_phase(&setup, &mut rng);
    let offline_duration = offline_start.elapsed();
    println!("Offline phase completed in {:.2}ms", offline_duration.as_nanos() as f64 / 1_000_000.0);
    
    // ===== 在线阶段 =====
    let online_start = Instant::now();
    
    let computed_result = online_phase_computation(
        &key0, &key1, &rx0, &ry0, &rx1, &ry1,
        &set_x, &set_y, input_len, &mut rng
    );
    
    let online_duration = online_start.elapsed();
    println!("Online phase completed in {:.2}ms", online_duration.as_nanos() as f64 / 1_000_000.0);
    
    // 记录总时间结束
    let total_duration = total_start.elapsed();
    
    // 验证正确性
    let is_correct = verify_psi_correctness(&set_x, &set_y, &computed_result, &expected_result);
    
    // 保存计算结果
    fs::write(format!("{}/computed_intersection_count.txt", param_dir), 
             format!("{}", computed_result.intersection_count)).unwrap();
    fs::write(format!("{}/computed_weight_sum.txt", param_dir), 
             format!("{}", computed_result.weight_sum)).unwrap();
    
    // 如果验证失败，panic以提醒用户
    if !is_correct {
        panic!("PSI protocol verification failed for input_{}_threshold_{}_set_{}!", input_len, threshold, set_size);
    }
    
    println!("PSI protocol test passed! Count: {}, Weight sum: {}", 
            computed_result.intersection_count, computed_result.weight_sum);
    
    SingleTestResult {
        offline_duration,
        online_duration,
        total_duration,
        psi_result: computed_result,
    }
}
 
fn main() {
    for &input_len in PSI_INPUT_LENS.iter() {
        for &threshold in PSI_THRESHOLDS.iter() {
            for &set_size in PSI_SET_SIZES.iter() {
                // 确保集合大小不超过门槛值
                if set_size > threshold {
                    continue;
                }
                
                // 执行单次测试
                let result = test_psi_protocol_once(input_len, threshold, set_size);
                
                // 打印并保存结果
                result.print_and_save(input_len, threshold, set_size);
            }
        }
    }
}