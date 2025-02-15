# Chia Vanity Address Finder
This program will generate numerous chia keys and check if any of the first 500 addresses for each key match a given pattern. If a match is found, it will print the mnemonic key and address.

## Usage
Either download one of the pre-compiled binaries from releases, or compile from source using rust (see "Building from source" below).

Running the program you will be presented with a prompt to enter some additional entropy for key generation, this can be anything at all (even nothing). The only purpose is to add additional randomness to the key generation process. Next you will be prompted for the search pattern. I have had decent success with patterns up to 4 characters long, and *some* success with 5 characters. The longer you make the pattern, the longer it will take to find a match. The third prompt will ask if you want to allow 1337speak characters as options. This will present you with a list possible search terms to use. This does not add any significant time to run the search, but may result in a quicker match. 

While the program is running, it will show a tally of the number of keys generated and checked, the rate of keys generated per second, and the rate of addresses generated per second. If a match is found, the program will print the mnemonic and address, and prompt you to export the mnemonic to a file. If you choose to export, the Master public key, a wallet observer key, and the address will be written to a text file named after the fingerprint of the key (ex: 3866274326.txt).

In windows, double clicking the exe file will open the program in command prompt, alternatively you can open command prompt or powershell and run the exe file from there. If you simply double clicked the exe file, ensure you write down the mnemonic before responding to the export prompt at the end, as the program will close the command prompt window immediately after.

## Building from source
1. Install Rust and Cargo using rustup. Follow the instructions here: https://www.rust-lang.org/tools/install
2. Clone this repository to your local machine:
   ```bash
git clone https://github.com/scrutinously/chia-vanity-address.git
cd chia-vanity-address
cargo build --release (or cargo run)
```