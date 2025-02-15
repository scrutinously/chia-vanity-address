use bip39::Mnemonic;
use chia_bls::{SecretKey, PublicKey, derive_keys};
use chia_wallet::{standard::standard_puzzle_hash, standard::DEFAULT_HIDDEN_PUZZLE_HASH};
use chia_wallet::DeriveSynthetic;
use rand_core::{OsRng, RngCore};
use bech32::ToBase32;
use sha2::{digest::FixedOutput, Sha256, Digest};
use std::fs::File;
use std::io::Write;
use inquire::{Text, Confirm, MultiSelect};
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::thread;
use num_cpus;
use std::time::{Instant, Duration};

pub struct Key {
    mnemonic: String,
    secret_key: SecretKey,
    public_key: PublicKey,
    wallet: PublicKey,
}
fn derive_path_hardened(key: &SecretKey, path: &[u32]) -> SecretKey {
    let mut derived = key.derive_hardened(path[0]);
    for idx in &path[1..] {
        derived = derived.derive_hardened(*idx);
    }
    derived
}
impl Key {
    pub fn generate(user_entropy: &mut String) -> Key {
        // user inputs a phrase to be used as additional entropy to RNG
        
        let mut hasher = Sha256::new();
        hasher.update(user_entropy);
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        // combine entropy with user_entropy
        hasher.update(entropy);
        let result: [u8; 32] = hasher.finalize_fixed().into();
        let mnemonic = Mnemonic::from_entropy(&result).expect("could not generate mnemonic");
        let seed = mnemonic.to_seed("");
        let sk = SecretKey::from_seed(&seed);
        let pk = sk.public_key();
        let wallet = derive_keys::master_to_wallet_unhardened_intermediate(&pk);
        Key {
            mnemonic: mnemonic.to_string(),
            secret_key: sk,
            public_key: pk,
            wallet: wallet,
        }
    }

    pub fn vanity_address(&self, desired: &Vec<String>, maxindex: &u32) -> Option<(String, u32)> {
        
        let mut index: u32 = 0;
        while &index < maxindex {
            let add_pk = derive_keys::master_to_wallet_unhardened(&self.public_key, index);
            let pk_syn = add_pk.derive_synthetic(&DEFAULT_HIDDEN_PUZZLE_HASH);
            let ph = standard_puzzle_hash(&pk_syn);
            let cur_address = bech32::encode("xch", ph.to_base32(), bech32::Variant::Bech32m).unwrap();
            
            if desired.iter().any(|variant| cur_address.ends_with(variant)) {
                return Some((cur_address, index));
            }
            index += 1;
        }
        None
    }

    // Create an option to export the public keys and address list
    pub fn export(&self, address: &String) {
        let mut export = String::new();
        export.push_str(&format!("Master Public Key:   {}", hex::encode(self.public_key.to_bytes())));
        export.push_str("\n");
        export.push_str(&format!("Wallet Observer Key: {}", hex::encode(self.wallet.to_bytes())));
        export.push_str("\n");
        export.push_str(&format!("Address:             {}", address));
        export.push_str("\n");
        let filename = format!("{}.txt", &self.public_key.get_fingerprint());
        let mut file = File::create(filename).expect("Unable to create file");
        file.write_all(export.as_bytes()).expect("Unable to write data");
    }
}
pub fn generate_variants(target: &str) -> Vec<String> {
    let target = target.to_lowercase();
    let mut variants = vec![String::new()];
    for ch in target.chars() {
        let mut options = vec![ch];
        if ch == 'o' {
            options.push('0');
        } else if ch == 'i' || ch == 'l' {
            options.push('1');
        } else if ch == 's' {
            options.push('5');
        } else if ch == 'a' {
            options.push('4');
        } else if ch == 'e' {
            options.push('3');
        } else if ch == 'z' {
            options.push('2');
        }
        let mut new_variants = vec![];
        for variant in variants {
            for opt in &options {
                let mut new_variant = variant.clone();
                new_variant.push(*opt);
                new_variants.push(new_variant);
            }
        }
        variants = new_variants;
    }
    variants
}

fn main() {
    let input_entropy = Text::new("Enter entropy for the mnemonic:").prompt().unwrap();
    let vanity = Text::new("Enter the vanity text you want in your address:").prompt().unwrap();
    let use_variants = Confirm::new("Do you want to accept 1337 speak variations?")
            .with_default(false).prompt().unwrap();
    let desired_variants: Vec<String> = if use_variants {
        let variants_list = generate_variants(&vanity);
        // Let the user select one or more variants from the list.
        MultiSelect::new("Select the variants you want:", variants_list)
            .prompt()
            .unwrap_or_else(|_| vec![])
    } else {
        vec![vanity]
    };
    
    let mut handles = vec![];
    let derivations: u32 = 500; // 500 chosen for ease of reference wallet compatibility
    let found = Arc::new(AtomicBool::new(false)); // shared flag to break loop
    let threads = num_cpus::get();
    println!("Spawning {} threads", threads);
    let start = Instant::now();

    // Global counter for keys checked
    let global_keys = Arc::new(AtomicUsize::new(0));

    { // Use 1 thread to track statistics
        let found_mon = Arc::clone(&found);
        let keys_mon = Arc::clone(&global_keys);
        let start_mon = start.clone();
        thread::spawn(move || {
            while !found_mon.load(Ordering::Relaxed) {
                let elapsed = start_mon.elapsed().as_secs_f64();
                let keys = keys_mon.load(Ordering::Relaxed);
                let keys32: u32 = keys as u32;
                let addresses = &keys32  * &derivations;
                let keys_per_sec = keys as f64 / elapsed;
                let addresses_per_sec = addresses as f64 / elapsed;
                print!(
                    "\rKeys checked: {} | Keys/s: {:.0} | Addresses/s: {:.0}  ",
                    keys, keys_per_sec, addresses_per_sec
                );
                std::io::stdout().flush().unwrap();
                thread::sleep(Duration::from_secs(1));
            }
        });
    }

    for _ in 0..threads { // Change this number to the number of threads you want to spawn
        let input_entropy_clone = input_entropy.clone(); // clone for each thread
        let vanity_list = desired_variants.clone();
        let found = Arc::clone(&found); // clone for each thread
        let keys_counter = Arc::clone(&global_keys);
        let handle = std::thread::spawn(move || {
            
            let mut user_entropy = String::new();// kept getting warnings when trying to use the clone directly
            user_entropy.push_str(&input_entropy_clone);
            let mut count = 0; 
            loop {
                if found.load(Ordering::Relaxed) { // check the flag
                    break;
                }
                count += 1;
                keys_counter.fetch_add(1, Ordering::Relaxed);
                // Optionally show current key count in this thread:
                // print!("\rLocal iteration: {} ", count);
                // std::io::stdout().flush().unwrap();

                let key = Key::generate(&mut user_entropy);                
                // print!("\r{} ", &count); let _ = std::io::stdout().flush(); 
                if let Some((address, index)) = key.vanity_address(&vanity_list, &derivations) {
                    // Only allow the thread that successfully changes found from false to true to print
                    if found.compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                        println!("Vanity Address: {}", address);
                        println!("Found at index: {}", index);
                        println!("Took {} iterations", count);
                        println!("Total time: {:.2?}", start.elapsed());
                        println!("Mnemonic: {}", key.mnemonic);
                        if Confirm::new("Do you want to export the public keys and address list (program will exit after response)?")
                            .with_default(false)
                            .prompt()
                            .unwrap() {
                            key.export(&address);
                    }
                }
                    break;
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
