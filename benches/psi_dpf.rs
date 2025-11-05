use dmpf::{
    Dmpf, DmpfKey, DpfOutput, DpfDmpf, DpfKey, Node,
};
use rand::{thread_rng, RngCore, CryptoRng};
use std::fs;
use std::path::Path;
use std::time::Instant;
use std::marker::PhantomData;
 
struct PsiProtocolSetup<Output: DpfOutput> {
    pub dmpf: DpfDmpf,
    pub input_len: usize,
    pub threshold: usize,
    pub _phantom: PhantomData<Output>,
}
 
impl<Output: DpfOutput> PsiProtocolSetup<Output> {
    pub fn new(input_len: usize, threshold: usize) -> Self {
        let dmpf = DpfDmpf::new();
        Self {
            dmpf,
            input_len,
            threshold,
            _phantom: PhantomData,
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
 
fn dealer_phase<Output: DpfOutput>(
    setup: &PsiProtocolSetup<Output>,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<u128>, Vec<u128>, Vec<u128>, Vec<u128>, <DpfDmpf as Dmpf<Output>>::Key, <DpfDmpf as Dmpf<Output>>::Key) {
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
 
fn online_phase_computation<Output: DpfOutput>(
    key0: &<DpfDmpf as Dmpf<Output>>::Key,
    key1: &<DpfDmpf as Dmpf<Output>>::Key,
    random_x_share0: &[u128],
    random_y_share0: &[u128],
    random_x_share1: &[u128],
    random_y_share1: &[u128],
    set_x: &[u128],
    set_y: &[u128],
    input_len: usize,
    mut rng: &mut (impl RngCore + CryptoRng),
) -> Vec<u128> {
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
    
    let mut intersection = Vec::new();
    for (i, (r0, r1)) in results0.iter().zip(results1.iter()).enumerate() {
        let sum = *r0 + *r1;
        if sum != Node::from(0u128).into() {
            let x_idx = i / set_y.len();
            let y_idx = i % set_y.len();
            if x_idx < set_x.len() && y_idx < set_y.len() {
                if set_x[x_idx] == set_y[y_idx] {
                    intersection.push(set_x[x_idx]);
                }
            }
        }
    }
    
    intersection
}
 
fn generate_test_sets_with_intersection(
    set_size: usize,
    intersection_size: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<u128>, Vec<u128>, Vec<u128>) {
    const DEFAULT_LENGTH: usize = 16;
    
    let mut set_x = Vec::with_capacity(set_size);
    let mut set_y = Vec::with_capacity(set_size);
    let mut intersection = Vec::with_capacity(intersection_size);
    
    for _ in 0..intersection_size {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        intersection.push(elem);
        set_x.push(elem);
        set_y.push(elem);
    }
    
    for _ in 0..(set_size - intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        set_x.push(elem);
    }
    
    for _ in 0..(set_size - intersection_size) {
        let elem = get_random_numeric_string_as_u128(DEFAULT_LENGTH, true, rng);
        set_y.push(elem);
    }
    
    use rand::seq::SliceRandom;
    set_x.shuffle(rng);
    set_y.shuffle(rng);
    
    (set_x, set_y, intersection)
}
 
fn verify_psi_correctness(
    set_x: &[u128],
    set_y: &[u128],
    computed_intersection: &[u128],
    expected_intersection: &[u128],
) -> bool {
    let mut actual_intersection = std::collections::HashSet::new();
    for &x in set_x {
        if set_y.contains(&x) {
            actual_intersection.insert(x);
        }
    }
    
    let computed_set: std::collections::HashSet<u128> = computed_intersection.iter().cloned().collect();
    let expected_set: std::collections::HashSet<u128> = expected_intersection.iter().cloned().collect();
    
    computed_set == expected_set && computed_set == actual_intersection
}

const PSI_INPUT_LENS: [usize; 1] = [8];
const PSI_THRESHOLDS: [usize; 1] = [4100];
const PSI_SET_SIZES: [usize; 1] = [4096];

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
        
        let param_dir = format!("data/psi_dpf/input_{}_threshold_{}_set_{}", input_len, threshold, set_size);
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
    }
}

fn test_psi_protocol_once(input_len: usize, threshold: usize, set_size: usize) -> SingleTestResult {
    let setup: PsiProtocolSetup<Node> = PsiProtocolSetup::<Node>::new(input_len, threshold);
    let mut rng = thread_rng();
    
    let intersection_size = set_size / 4;
    let (set_x, set_y, expected_intersection) = 
        generate_test_sets_with_intersection(set_size, intersection_size, &mut rng);
    
    let param_dir = format!("data/psi_dpf/input_{}_threshold_{}_set_{}", input_len, threshold, set_size);
    if !Path::new(&param_dir).exists() {
        fs::create_dir_all(&param_dir).unwrap();
    }
    
    fs::write(format!("{}/expected_intersection.txt", param_dir), format!("{:?}", expected_intersection)).unwrap();
    
    println!("Starting PSI protocol test for input_{}_threshold_{}_set_{}", input_len, threshold, set_size);
    
    let total_start = Instant::now();
    
    let offline_start = Instant::now();
    let (rx0, ry0, rx1, ry1, key0, key1) = dealer_phase::<Node>(&setup, &mut rng);
    let offline_duration = offline_start.elapsed();
    println!("Offline phase completed in {:.2}ms", offline_duration.as_nanos() as f64 / 1_000_000.0);
    
    let online_start = Instant::now();
    
    let intersection = online_phase_computation::<Node>(
        &key0, &key1, &rx0, &ry0, &rx1, &ry1,
        &set_x, &set_y, input_len, &mut rng
    );
    
    let online_duration = online_start.elapsed();
    println!("Online phase completed in {:.2}ms", online_duration.as_nanos() as f64 / 1_000_000.0);
    
    let total_duration = total_start.elapsed();
    
    let is_correct = verify_psi_correctness(&set_x, &set_y, &intersection, &expected_intersection);
    
    fs::write(format!("{}/computed_intersection.txt", param_dir), format!("{:?}", intersection)).unwrap();
    
    if !is_correct {
        panic!("PSI protocol verification failed for input_{}_threshold_{}_set_{}!", input_len, threshold, set_size);
    }
    
    println!("PSI protocol test passed! Intersection size: {}", intersection.len());
    
    SingleTestResult {
        offline_duration,
        online_duration,
        total_duration,
        intersection_size: intersection.len(),
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