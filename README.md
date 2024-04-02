![Crates.io Version](https://img.shields.io/crates/v/signature-verifier)
![Crates.io Total Downloads](https://img.shields.io/crates/d/signature-verifier)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/0xtmphey/signature-verifier/rust.yml)

# signature-verifier
This crate provide an easy way to verify Solana and Ethereum wallet-signed messages.

# Installation
Add the crate to your `Cargo.toml` and specify the needed features.
By default it doesn't include anything.
```toml
[dependencies]
signature-verifier = { version = "1.0.0", features = ["solana", "ethereum"]}
```

# Usage
```rust
use signature_verifier::ethereum::EthereumVerifier;
// or
// use signature_verifier::solana::SolanaVerifier;
use signature_verifier::SignatureVerifier;

fn main() {
    let message = "hello, world!";
    let signature = "7c7240d970b40d0b7a7a798584fee5dbc3e64a7fd276eb068c9139e84bda6b57383276bf73f32ef7055969d0c896884350fc5e899a17904a5f728c5055d8c70d1b";
    let account = "0x099dC008292EF1FEb96fBF67eA47fB71fde142C3";

    let verification_result = EthereumVerifier::verify(signature, message, account);

    match verification_result {
        Ok(_) => println!("Signature is valid!"),
        Err(e) => eprintln!("{}", e),
    };
}

```
