use dmpf::{
    okvs::OkvsDmpf, Dmpf, DmpfKey, DpfOutput, EpsilonPercent, Node,
};
use rand::{thread_rng, RngCore, CryptoRng};
use std::fs;
use std::path::Path;
use std::time::Instant;
use std::collections::HashSet;
 
// PSI协议相关结构体
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
 
// 加法秘密分享
fn additive_secret_share(x: u128, rng: &mut (impl RngCore + CryptoRng)) -> (u128, u128) {
    let share0 = rng.next_u64() as u128;
    let share1 = x.wrapping_sub(share0);
    (share0, share1)
}
 
// 重构秘密
fn reconstruct_secret(share0: u128, share1: u128) -> u128 {
    share0.wrapping_add(share0)
}
 
// 生成固定长度的随机数字字符串并转换为u128
fn get_random_numeric_string_as_u128(length: usize, padding: bool, rng: &mut (impl RngCore + CryptoRng)) -> u128 {
    let mut output = String::with_capacity(length);
    
    // 确保首位不是0（padding为true时）
    if padding {
        output.push('1');
    } else {
        output.push('0');
    }
    
    // 生成剩余的数字
    for _ in 1..length {
        let digit = (rng.next_u32() % 10) as u8 + b'0';
        output.push(digit as char);
    }
    
    // 将字符串转换为u128
    output.parse::<u128>().unwrap_or(0)
}
 
// Dealer角色：离线阶段密钥生成
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
    let mut alpha_set = HashSet::new();
    
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
 
// 参与方角色：在线阶段计算（修改版：只返回交集大小）
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
        // 确保索引不越界，使用模运算
        let random_idx = i % random_x_share0.len();
        x0_prime_shares.push(set_x_share0[i].wrapping_add(random_x_share0[random_idx]));
        x1_prime_shares.push(set_x_share1[i].wrapping_add(random_x_share1[random_idx]));
    }
    
    for j in 0..set_y.len() {
        // 确保索引不越界，使用模运算
        let random_idx = j % random_y_share0.len();
        y0_prime_shares.push(set_y_share0[j].wrapping_add(random_y_share0[random_idx]));
        y1_prime_shares.push(set_y_share1[j].wrapping_add(random_y_share1[random_idx]));
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
 
// PSI协议方法（修改版：返回交集大小）
fn psi_protocol<const W: usize, Output: DpfOutput>(
    setup: &PsiProtocolSetup<W, Output>,
    set_x: &[u128],
    set_y: &[u128],
    rng: &mut (impl RngCore + CryptoRng),
) -> (usize, std::time::Duration, std::time::Duration) {  // 修改返回类型
    // ===== 离线阶段 =====
    let offline_start = Instant::now();
    let (rx0, ry0, rx1, ry1, key0, key1) = dealer_phase(setup, rng);
    let offline_duration = offline_start.elapsed();
    
    // ===== 在线阶段 =====
    let online_start = Instant::now();
    let intersection_count = online_phase_computation(  // 使用新的函数名和返回值
        &key0, &key1, &rx0, &ry0, &rx1, &ry1,
        set_x, set_y, setup.input_len, rng
    );
    let online_duration = online_start.elapsed();
    
    (intersection_count, offline_duration, online_duration)  // 返回计数而不是向量
}
 
// UPSI协议相关结构体
struct UpsiProtocolSetup<const W: usize, Output: DpfOutput> {
    pub psi_setup: PsiProtocolSetup<W, Output>,
    pub total_set_size: usize,
    pub daily_update_size: usize,
}
 
impl<const W: usize, Output: DpfOutput> UpsiProtocolSetup<W, Output> {
    pub fn new(input_len: usize, threshold: usize, total_set_size: usize, daily_update_size: usize) -> Self {
        let psi_setup = PsiProtocolSetup::<W, Output>::new(input_len, threshold);
        Self {
            psi_setup,
            total_set_size,
            daily_update_size,
        }
    }
}
 
// 生成包含交集的测试数据（修改版：返回交集大小而不是具体元素）
fn generate_upsi_test_sets(
    total_set_size: usize,
    daily_update_size: usize,
    initial_intersection_size: usize,
    daily_intersection_size: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<u128>, Vec<u128>, Vec<u128>, Vec<u128>, usize, usize) {  // 修改返回类型
    const DEFAULT_LENGTH: usize = 16; // 使用16位数字字符串
    
    let mut x_total_prev = Vec::with_capacity(total_set_size);
    let mut y_total_prev = Vec::with_capacity(total_set_size);
    let mut x_daily = Vec::with_capacity(daily_update_size);
    let mut y_daily = Vec::with_capacity(daily_update_size);
    
    // 生成初始交集元素
    for _ in 0..initial_intersection_size {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        x_total_prev.push(elem);
        y_total_prev.push(elem);
    }
    
    // 生成初始集合的独有元素
    for _ in 0..(total_set_size - initial_intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        x_total_prev.push(elem);
    }
    for _ in 0..(total_set_size - initial_intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        y_total_prev.push(elem);
    }
    
    // 生成交集元素（当天更新）
    for _ in 0..daily_intersection_size {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        x_daily.push(elem);
        y_daily.push(elem);
    }
    
    // 生成X每日更新的独有元素
    for _ in 0..(daily_update_size - daily_intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        x_daily.push(elem);
    }
    
    // 生成Y每日更新的独有元素
    for _ in 0..(daily_update_size - daily_intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        y_daily.push(elem);
    }
    
    // 打乱集合顺序
    use rand::seq::SliceRandom;
    x_total_prev.shuffle(rng);
    y_total_prev.shuffle(rng);
    x_daily.shuffle(rng);
    y_daily.shuffle(rng);
    
    (x_total_prev, y_total_prev, x_daily, y_daily, initial_intersection_size, daily_intersection_size)  // 返回大小而不是向量
}
 
// UPSI协议实现（修改版：返回交集大小）
fn upsi_protocol<const W: usize, Output: DpfOutput>(
    setup: &UpsiProtocolSetup<W, Output>,
    x_total_prev: &[u128],  // X_[d-1]
    y_total_prev: &[u128],  // Y_[d-1]
    x_daily: &[u128],       // X_d
    y_daily: &[u128],       // Y_d
    intersection_prev_size: usize,  // 修改参数：传入之前的大小
    rng: &mut (impl RngCore + CryptoRng),
) -> (usize, std::time::Duration, std::time::Duration, std::time::Duration, std::time::Duration) {
    
    // 步骤1：更新集合 Y_[d] = Y_[d-1] ∪ Y_d
    let mut y_total_current = y_total_prev.to_vec();
    y_total_current.extend(y_daily);
    y_total_current.sort_unstable();
    y_total_current.dedup();
    
    // 步骤2：计算 X_d ∩ Y_[d] 的大小
    let (i_new_size, offline1, online1) = psi_protocol(&setup.psi_setup, x_daily, &y_total_current, rng);
    
    // 步骤3：计算 X_[d-1] ∩ Y_d 的大小
    let (i_old_size, offline2, online2) = psi_protocol(&setup.psi_setup, x_total_prev, y_daily, rng);
    
    // 步骤4：产生结果 I_d = |I_old| + |I_new| - |I_old ∩ I_new| + |I_d-1|
    // 注意：这里需要考虑重叠部分，简化版本假设没有重叠
    let final_intersection_size = i_new_size + i_old_size + intersection_prev_size;
    
    (final_intersection_size, offline1, offline2, online1, online2)
}
 
// 验证UPSI协议正确性（修改版：验证交集大小）
fn verify_upsi_correctness(
    x_total_prev: &[u128],
    y_total_prev: &[u128],
    x_daily: &[u128],
    y_daily: &[u128],
    computed_size: usize,  // 修改参数类型
    expected_size: usize,  // 修改参数类型
) -> bool {
    // 计算实际的总集合
    let mut x_total_current = x_total_prev.to_vec();
    let mut y_total_current = y_total_prev.to_vec();
    x_total_current.extend(x_daily);
    y_total_current.extend(y_daily);
    x_total_current.sort_unstable();
    x_total_current.dedup();
    y_total_current.sort_unstable();
    y_total_current.dedup();
    
    // 计算实际的交集大小
    let mut actual_intersection_size = 0;
    for &x in &x_total_current {
        if y_total_current.contains(&x) {
            actual_intersection_size += 1;
        }
    }
    
    computed_size == expected_size && computed_size == actual_intersection_size
}
 
// UPSI协议测试参数
const UPSI_INPUT_LENS: [usize; 1] = [8];
const UPSI_THRESHOLDS: [usize; 1] = [65540];
const UPSI_TOTAL_SET_SIZES: [usize; 1] = [65536];
const UPSI_DAILY_UPDATE_SIZES: [usize; 1] = [1024];  
 
// 单次测试结果结构（修改版）
struct SingleTestResult {
    offline1_duration: std::time::Duration,
    offline2_duration: std::time::Duration,
    online1_duration: std::time::Duration,
    online2_duration: std::time::Duration,
    total_offline_duration: std::time::Duration,
    total_online_duration: std::time::Duration,
    total_duration: std::time::Duration,
    intersection_size: usize,  // 保持不变，因为本来就是大小
}
 
impl SingleTestResult {
    fn print_and_save(&self, total_set_size: usize, daily_update_size: usize) {
        println!("\n=== UPSI Protocol Test Result ===");
        println!("Total set size: {}, Daily update size: {}", total_set_size, daily_update_size);
        println!("Offline phase 1 time (X_d ∩ Y_[d]): {:.2}ms", self.offline1_duration.as_nanos() as f64 / 1_000_000.0);
        println!("Offline phase 2 time (X_[d-1] ∩ Y_d): {:.2}ms", self.offline2_duration.as_nanos() as f64 / 1_000_000.0);
        println!("Online phase 1 time (X_d ∩ Y_[d]): {:.2}ms", self.online1_duration.as_nanos() as f64 / 1_000_000.0);
        println!("Online phase 2 time (X_[d-1] ∩ Y_d): {:.2}ms", self.online2_duration.as_nanos() as f64 / 1_000_000.0);
        println!("Total offline time: {:.2}ms", self.total_offline_duration.as_nanos() as f64 / 1_000_000.0);
        println!("Total online time: {:.2}ms", self.total_online_duration.as_nanos() as f64 / 1_000_000.0);
        println!("Total time: {:.2}ms", self.total_duration.as_nanos() as f64 / 1_000_000.0);
        println!("Total offline percentage: {:.2}%", self.total_offline_duration.as_nanos() as f64 / self.total_duration.as_nanos() as f64 * 100.0);
        println!("Total online percentage: {:.2}%", self.total_online_duration.as_nanos() as f64 / self.total_duration.as_nanos() as f64 * 100.0);
        println!("Intersection size: {}", self.intersection_size);
        println!("====================================\n");
        
        // 保存到参数特定的文件
        let param_dir = format!("data/upsi_ca_okvs/total_{}_daily_{}", total_set_size, daily_update_size);
        let summary_info = format!(
            "Total set size: {}, Daily update size: {}\n\
            Offline phase 1 time (X_d ∩ Y_[d]): {:.2}ms\n\
            Offline phase 2 time (X_[d-1] ∩ Y_d): {:.2}ms\n\
            Online phase 1 time (X_d ∩ Y_[d]): {:.2}ms\n\
            Online phase 2 time (X_[d-1] ∩ Y_d): {:.2}ms\n\
            Total offline time: {:.2}ms\n\
            Total online time: {:.2}ms\n\
            Total time: {:.2}ms\n\
            Total offline percentage: {:.2}%\n\
            Total online percentage: {:.2}%\n\
            Intersection size: {}",
            total_set_size, daily_update_size,
            self.offline1_duration.as_nanos() as f64 / 1_000_000.0,
            self.offline2_duration.as_nanos() as f64 / 1_000_000.0,
            self.online1_duration.as_nanos() as f64 / 1_000_000.0,
            self.online2_duration.as_nanos() as f64 / 1_000_000.0,
            self.total_offline_duration.as_nanos() as f64 / 1_000_000.0,
            self.total_online_duration.as_nanos() as f64 / 1_000_000.0,
            self.total_duration.as_nanos() as f64 / 1_000_000.0,
            self.total_offline_duration.as_nanos() as f64 / self.total_duration.as_nanos() as f64 * 100.0,
            self.total_online_duration.as_nanos() as f64 / self.total_duration.as_nanos() as f64 * 100.0,
            self.intersection_size
        );
        fs::write(format!("{}/timing.txt", param_dir), summary_info).unwrap();
        
        // 只保存交集大小，不保存具体元素
        fs::write(format!("{}/intersection_size.txt", param_dir), format!("{}", self.intersection_size)).unwrap();
    }
}
 
// 单次UPSI协议测试（修改版）
fn test_upsi_protocol_once(input_len: usize, threshold: usize, total_set_size: usize, daily_update_size: usize) -> SingleTestResult {
    const W: usize = 49;
    
    let setup = UpsiProtocolSetup::<W, Node>::new(input_len, threshold, total_set_size, daily_update_size);
    let mut rng = thread_rng();
    
    // 生成初始测试数据
    let initial_intersection_size = total_set_size / 4;
    let daily_intersection_size = daily_update_size / 3;
    let (x_total_prev, y_total_prev, x_daily, y_daily, initial_intersection, daily_intersection) = 
        generate_upsi_test_sets(total_set_size, daily_update_size, initial_intersection_size, daily_intersection_size, &mut rng);
    
    // 计算期望的总交集大小
    let expected_total_intersection_size = initial_intersection + daily_intersection;
    
    // 创建参数特定的子文件夹
    let param_dir = format!("data/upsi_ca_okvs/total_{}_daily_{}", total_set_size, daily_update_size);
    if !Path::new(&param_dir).exists() {
        fs::create_dir_all(&param_dir).unwrap();
    }
    
    // 保存期望的交集大小
    fs::write(format!("{}/expected_intersection_size.txt", param_dir), format!("{}", expected_total_intersection_size)).unwrap();
    fs::write(format!("{}/initial_intersection_size.txt", param_dir), format!("{}", initial_intersection)).unwrap();
    fs::write(format!("{}/daily_intersection_size.txt", param_dir), format!("{}", daily_intersection)).unwrap();
    
    println!("Starting UPSI protocol test for input_{}_threshold_{}_total_{}_daily_{}", input_len, threshold, total_set_size, daily_update_size);
    
    // 记录总时间开始
    let total_start = Instant::now();
    
    // 运行UPSI协议
    let (computed_intersection_size, offline1, offline2, online1, online2) = 
        upsi_protocol(
            &setup,
            &x_total_prev,
            &y_total_prev,
            &x_daily,
            &y_daily,
            initial_intersection,  // 传入之前交集的大小
            &mut rng
        );
    
    // 计算总时间
    let total_offline = offline1 + offline2;
    let total_online = online1 + online2;
    let total_duration = total_start.elapsed();
    
    // 验证正确性
    let is_correct = verify_upsi_correctness(
        &x_total_prev,
        &y_total_prev,
        &x_daily,
        &y_daily,
        computed_intersection_size,
        expected_total_intersection_size
    );
    
    // 保存结果
    fs::write(format!("{}/computed_intersection_size.txt", param_dir), format!("{}", computed_intersection_size)).unwrap();
    
    // 如果验证失败，panic以提醒用户
    if !is_correct {
        panic!("UPSI protocol verification failed for input_{}_threshold_{}_total_{}_daily_{}!", input_len, threshold, total_set_size, daily_update_size);
    }
    
    println!("UPSI protocol test passed! Intersection size: {}", computed_intersection_size);
    
    SingleTestResult {
        offline1_duration: offline1,
        offline2_duration: offline2,
        online1_duration: online1,
        online2_duration: online2,
        total_offline_duration: total_offline,
        total_online_duration: total_online,
        total_duration,
        intersection_size: computed_intersection_size,
    }
}
 
fn main() {
    for &input_len in UPSI_INPUT_LENS.iter() {
        for &threshold in UPSI_THRESHOLDS.iter() {
            for &total_set_size in UPSI_TOTAL_SET_SIZES.iter() {
                for &daily_update_size in UPSI_DAILY_UPDATE_SIZES.iter() {
                    // 确保集合大小不超过门槛值
                    if total_set_size > threshold {
                        continue;
                    }
                    
                    // 执行单次测试
                    let result = test_upsi_protocol_once(input_len, threshold, total_set_size, daily_update_size);
                    
                    // 打印并保存结果
                    result.print_and_save(total_set_size, daily_update_size);
                }
            }
        }
    }
}