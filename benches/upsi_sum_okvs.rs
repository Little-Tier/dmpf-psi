use dmpf::{
    okvs::OkvsDmpf, Dmpf, DmpfKey, DpfOutput, EpsilonPercent, Node,
};
use rand::{thread_rng, RngCore, CryptoRng};
use std::fs;
use std::path::Path;
use std::time::Instant;
use std::collections::HashSet;

type WeightedElement = (u128, u64);

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

fn get_random_weight(rng: &mut (impl RngCore + CryptoRng)) -> u64 {
    rng.next_u64()
}

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
    let mut alpha_set = HashSet::new();
    
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

fn online_phase_computation<const W: usize, Output: DpfOutput>(
    key0: &dmpf::okvs::OkvsDmpfKey<1, W, Output>,
    key1: &dmpf::okvs::OkvsDmpfKey<1, W, Output>,
    random_x_share0: &[u128],
    random_y_share0: &[u128],
    random_x_share1: &[u128],
    random_y_share1: &[u128],
    set_x: &[WeightedElement],
    set_y: &[u128],
    input_len: usize,
    mut rng: &mut (impl RngCore + CryptoRng),
) -> (usize, u64) {
    let mut set_x_share0: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut set_x_share1: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut set_y_share0: Vec<u128> = Vec::with_capacity(set_y.len());
    let mut set_y_share1: Vec<u128> = Vec::with_capacity(set_y.len());
    
    for (element, _) in set_x {
        let (share0, share1) = additive_secret_share(*element, &mut rng);
        set_x_share0.push(share0);
        set_x_share1.push(share1);
    }
    
    for &y in set_y {
        let (share0, share1) = additive_secret_share(y, &mut rng);
        set_y_share0.push(share0);
        set_y_share1.push(share1);
    }
    
    let mut x0_prime_shares: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut y0_prime_shares: Vec<u128> = Vec::with_capacity(set_y.len());
    let mut x1_prime_shares: Vec<u128> = Vec::with_capacity(set_x.len());
    let mut y1_prime_shares: Vec<u128> = Vec::with_capacity(set_y.len());
    
    for i in 0..set_x.len() {
        let random_idx = i % random_x_share0.len();
        x0_prime_shares.push(set_x_share0[i].wrapping_add(random_x_share0[random_idx]));
        x1_prime_shares.push(set_x_share1[i].wrapping_add(random_x_share1[random_idx]));
    }
    
    for j in 0..set_y.len() {
        let random_idx = j % random_y_share0.len();
        y0_prime_shares.push(set_y_share0[j].wrapping_add(random_y_share0[random_idx]));
        y1_prime_shares.push(set_y_share1[j].wrapping_add(random_y_share1[random_idx]));
    }
    
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
    
    let mut intersection_count = 0;
    let mut weight_sum = 0u64;
    
    for (i, (r0, r1)) in results0.iter().zip(results1.iter()).enumerate() {
        let sum = *r0 + *r1;
        if sum != Node::from(0u128).into() {
            let x_idx = i / set_y.len();
            let y_idx = i % set_y.len();
            if x_idx < set_x.len() && y_idx < set_y.len() {
                if set_x[x_idx].0 == set_y[y_idx] {
                    intersection_count += 1;
                    weight_sum += set_x[x_idx].1;
                }
            }
        }
    }
    
    (intersection_count, weight_sum)
}
 
fn psi_protocol<const W: usize, Output: DpfOutput>(
    setup: &PsiProtocolSetup<W, Output>,
    set_x: &[WeightedElement],
    set_y: &[u128],
    rng: &mut (impl RngCore + CryptoRng),
) -> ((usize, u64), std::time::Duration, std::time::Duration) {
    let offline_start = Instant::now();
    let (rx0, ry0, rx1, ry1, key0, key1) = dealer_phase(setup, rng);
    let offline_duration = offline_start.elapsed();
    
    let online_start = Instant::now();
    let result = online_phase_computation(
        &key0, &key1, &rx0, &ry0, &rx1, &ry1,
        set_x, set_y, setup.input_len, rng
    );
    let online_duration = online_start.elapsed();
    
    (result, offline_duration, online_duration)
}

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

fn generate_upsi_test_sets(
    total_set_size: usize,
    daily_update_size: usize,
    initial_intersection_size: usize,
    daily_intersection_size: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<WeightedElement>, Vec<u128>, Vec<WeightedElement>, Vec<u128>, (usize, u64), (usize, u64)) {  // 修改返回类型
    const DEFAULT_LENGTH: usize = 16;
    
    let mut x_total_prev = Vec::with_capacity(total_set_size);
    let mut y_total_prev = Vec::with_capacity(total_set_size);
    let mut x_daily = Vec::with_capacity(daily_update_size);
    let mut y_daily = Vec::with_capacity(daily_update_size);
    
    let mut initial_weight_sum = 0u64;
    let mut daily_weight_sum = 0u64;
    
    for _ in 0..initial_intersection_size {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        let weight = get_random_weight(rng);
        initial_weight_sum += weight;
        x_total_prev.push((elem, weight));
        y_total_prev.push(elem);
    }
    
    for _ in 0..(total_set_size - initial_intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        let weight = get_random_weight(rng);
        x_total_prev.push((elem, weight));
    }
    
    for _ in 0..(total_set_size - initial_intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        y_total_prev.push(elem);
    }
    
    for _ in 0..daily_intersection_size {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        let weight = get_random_weight(rng);
        daily_weight_sum += weight;
        x_daily.push((elem, weight));
        y_daily.push(elem);
    }
    
    for _ in 0..(daily_update_size - daily_intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        let weight = get_random_weight(rng);
        x_daily.push((elem, weight));
    }
    
    for _ in 0..(daily_update_size - daily_intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        y_daily.push(elem);
    }
    
    use rand::seq::SliceRandom;
    x_total_prev.shuffle(rng);
    y_total_prev.shuffle(rng);
    x_daily.shuffle(rng);
    y_daily.shuffle(rng);
    
    (
        x_total_prev, y_total_prev, x_daily, y_daily, 
        (initial_intersection_size, initial_weight_sum), 
        (daily_intersection_size, daily_weight_sum)
    )
}

fn upsi_protocol<const W: usize, Output: DpfOutput>(
    setup: &UpsiProtocolSetup<W, Output>,
    x_total_prev: &[WeightedElement],
    y_total_prev: &[u128],
    x_daily: &[WeightedElement],
    y_daily: &[u128],
    intersection_prev: (usize, u64),
    rng: &mut (impl RngCore + CryptoRng),
) -> ((usize, u64), std::time::Duration, std::time::Duration, std::time::Duration, std::time::Duration) {
    
    let mut y_total_current = y_total_prev.to_vec();
    y_total_current.extend(y_daily);
    y_total_current.sort_unstable();
    y_total_current.dedup();
    
    let (i_new_result, offline1, online1) = psi_protocol(&setup.psi_setup, x_daily, &y_total_current, rng);
    
    let (i_old_result, offline2, online2) = psi_protocol(&setup.psi_setup, x_total_prev, y_daily, rng);

    let final_intersection_size = i_new_result.0 + i_old_result.0 + intersection_prev.0;
    let final_weight_sum = i_new_result.1 + i_old_result.1 + intersection_prev.1;
    
    ((final_intersection_size, final_weight_sum), offline1, offline2, online1, online2)
}

fn verify_upsi_correctness(
    x_total_prev: &[WeightedElement],
    y_total_prev: &[u128],
    x_daily: &[WeightedElement],
    y_daily: &[u128],
    computed_result: (usize, u64),
    expected_result: (usize, u64),
) -> bool {
    let mut x_total_current = x_total_prev.to_vec();
    let mut y_total_current = y_total_prev.to_vec();
    x_total_current.extend(x_daily);
    y_total_current.extend(y_daily);
    
    y_total_current.sort_unstable();
    y_total_current.dedup();
    
    let mut actual_intersection_size = 0;
    let mut actual_weight_sum = 0u64;
    
    for (x_elem, x_weight) in &x_total_current {
        if y_total_current.contains(x_elem) {
            actual_intersection_size += 1;
            actual_weight_sum += x_weight;
        }
    }
    
    computed_result == expected_result && 
    computed_result == (actual_intersection_size, actual_weight_sum)
}

const UPSI_INPUT_LENS: [usize; 1] = [8];
const UPSI_THRESHOLDS: [usize; 1] = [262145];
const UPSI_TOTAL_SET_SIZES: [usize; 1] = [262144];
const UPSI_DAILY_UPDATE_SIZES: [usize; 1] = [256];  

struct SingleTestResult {
    offline1_duration: std::time::Duration,
    offline2_duration: std::time::Duration,
    online1_duration: std::time::Duration,
    online2_duration: std::time::Duration,
    total_offline_duration: std::time::Duration,
    total_online_duration: std::time::Duration,
    total_duration: std::time::Duration,
    intersection_size: usize,
    weight_sum: u64,
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
        println!("Weight sum: {}", self.weight_sum);
        println!("====================================\n");
    
        let param_dir = format!("data/upsi_sum_okvs/total_{}_daily_{}", total_set_size, daily_update_size);
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
            Intersection size: {}\n\
            Weight sum: {}",
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
            self.intersection_size,
            self.weight_sum
        );
        fs::write(format!("{}/timing.txt", param_dir), summary_info).unwrap();
        fs::write(format!("{}/intersection_size.txt", param_dir), format!("{}", self.intersection_size)).unwrap();
        fs::write(format!("{}/weight_sum.txt", param_dir), format!("{}", self.weight_sum)).unwrap();
    }
}

fn test_upsi_protocol_once(input_len: usize, threshold: usize, total_set_size: usize, daily_update_size: usize) -> SingleTestResult {
    const W: usize = 49;
    
    let setup = UpsiProtocolSetup::<W, Node>::new(input_len, threshold, total_set_size, daily_update_size);
    let mut rng = thread_rng();
    
    let initial_intersection_size = total_set_size / 4;
    let daily_intersection_size = daily_update_size / 3;
    let (x_total_prev, y_total_prev, x_daily, y_daily, initial_intersection, daily_intersection) = 
        generate_upsi_test_sets(total_set_size, daily_update_size, initial_intersection_size, daily_intersection_size, &mut rng);
    
    let expected_total_intersection_size = initial_intersection.0 + daily_intersection.0;
    let expected_total_weight_sum = initial_intersection.1 + daily_intersection.1;
    
    let param_dir = format!("data/upsi_sum_okvs/total_{}_daily_{}", total_set_size, daily_update_size);
    if !Path::new(&param_dir).exists() {
        fs::create_dir_all(&param_dir).unwrap();
    }
    
    fs::write(format!("{}/expected_intersection_size.txt", param_dir), format!("{}", expected_total_intersection_size)).unwrap();
    fs::write(format!("{}/expected_weight_sum.txt", param_dir), format!("{}", expected_total_weight_sum)).unwrap();
    fs::write(format!("{}/initial_intersection_size.txt", param_dir), format!("{}", initial_intersection.0)).unwrap();
    fs::write(format!("{}/initial_weight_sum.txt", param_dir), format!("{}", initial_intersection.1)).unwrap();
    fs::write(format!("{}/daily_intersection_size.txt", param_dir), format!("{}", daily_intersection.0)).unwrap();
    fs::write(format!("{}/daily_weight_sum.txt", param_dir), format!("{}", daily_intersection.1)).unwrap();
    
    println!("Starting UPSI protocol test for input_{}_threshold_{}_total_{}_daily_{}", input_len, threshold, total_set_size, daily_update_size);
    
    let total_start = Instant::now();
    
    let (computed_result, offline1, offline2, online1, online2) = 
        upsi_protocol(
            &setup,
            &x_total_prev,
            &y_total_prev,
            &x_daily,
            &y_daily,
            initial_intersection,
            &mut rng
        );
    
    let total_offline = offline1 + offline2;
    let total_online = online1 + online2;
    let total_duration = total_start.elapsed();
    
    let expected_result = (expected_total_intersection_size, expected_total_weight_sum);
    let is_correct = verify_upsi_correctness(
        &x_total_prev,
        &y_total_prev,
        &x_daily,
        &y_daily,
        computed_result,
        expected_result
    );
    
    fs::write(format!("{}/computed_intersection_size.txt", param_dir), format!("{}", computed_result.0)).unwrap();
    fs::write(format!("{}/computed_weight_sum.txt", param_dir), format!("{}", computed_result.1)).unwrap();
    
    if !is_correct {
        panic!("UPSI protocol verification failed for input_{}_threshold_{}_total_{}_daily_{}!", input_len, threshold, total_set_size, daily_update_size);
    }
    
    println!("UPSI protocol test passed! Intersection size: {}, Weight sum: {}", computed_result.0, computed_result.1);
    
    SingleTestResult {
        offline1_duration: offline1,
        offline2_duration: offline2,
        online1_duration: online1,
        online2_duration: online2,
        total_offline_duration: total_offline,
        total_online_duration: total_online,
        total_duration,
        intersection_size: computed_result.0,
        weight_sum: computed_result.1,
    }
}
 
fn main() {
    for &input_len in UPSI_INPUT_LENS.iter() {
        for &threshold in UPSI_THRESHOLDS.iter() {
            for &total_set_size in UPSI_TOTAL_SET_SIZES.iter() {
                for &daily_update_size in UPSI_DAILY_UPDATE_SIZES.iter() {
                    if total_set_size > threshold {
                        continue;
                    }
                    let result = test_upsi_protocol_once(input_len, threshold, total_set_size, daily_update_size);
                    result.print_and_save(total_set_size, daily_update_size);
                }
            }
        }
    }
}