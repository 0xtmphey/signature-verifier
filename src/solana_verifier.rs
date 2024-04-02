use std::str::FromStr;

use anyhow::{anyhow, Ok};
use nacl::sign::verify;
use solana_sdk::pubkey::Pubkey;

use crate::signature_verifier::SignatureVerifier;

pub struct SolanaVerifier;

impl SignatureVerifier for SolanaVerifier {
    fn verify<S: AsRef<str>>(
        signature: S,
        message: S,
        signer_pubkey: S,
    ) -> Result<(), anyhow::Error> {
        let message = message.as_ref();
        let signature = signature.as_ref();
        let signer_pubkey = signer_pubkey.as_ref();

        let signature_bytes = bs58::decode(signature).into_vec()?;
        let signer_pubkey_bytes = Pubkey::from_str(signer_pubkey)?.to_bytes();

        let res = verify(&signature_bytes, message.as_bytes(), &signer_pubkey_bytes)
            .map_err(|_| anyhow!("Invalid signature!"))?;

        if res {
            Ok(())
        } else {
            Err(anyhow!("Invalid signature!"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_signature_is_ok() {
        let msg = "hello, world!";
        let sig = "v6qvVankHP2h3zEH2P4n1yiW3QnXWWSpVYTGfWUnheYG6bUeTsh1mQj7SUpTn54t2PUgwD7vhFZ9Tso5yypv9pCDDUJ6UQRkoQS6CfFxt";
        let pk = "9F5eiDYrZ4X9Eas4ovxaM6LgGhFXc4aRXPUFnuxP2P7U";

        let res = SolanaVerifier::verify(sig, msg, pk);

        assert!(res.is_ok())
    }

    #[test]
    fn wrong_message_declined() {
        let msg = "helloworld!";
        let sig = "v6qvVankHP2h3zEH2P4n1yiW3QnXWWSpVYTGfWUnheYG6bUeTsh1mQj7SUpTn54t2PUgwD7vhFZ9Tso5yypv9pCDDUJ6UQRkoQS6CfFxt";
        let pk = "9F5eiDYrZ4X9Eas4ovxaM6LgGhFXc4aRXPUFnuxP2P7U";

        let res = SolanaVerifier::verify(sig, msg, pk);

        assert!(res.is_err())
    }

    #[test]
    fn wrong_signature_declined() {
        let msg = "hello, world!";
        let sig = "xxxvVankHP2h3zEH2P4n1yiW3QnXWWSpVYTGfWUnheYG6bUeTsh1mQj7SUpTn54t2PUgwD7vhFZ9Tso5yypv9pCDDUJ6UQRkoQS6CfFxt";
        let pk = "9F5eiDYrZ4X9Eas4ovxaM6LgGhFXc4aRXPUFnuxP2P7U";

        let res = SolanaVerifier::verify(sig, msg, pk);

        assert!(res.is_err())
    }
}
