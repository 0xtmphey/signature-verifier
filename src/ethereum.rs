use web3::signing::{keccak256, recover};

use crate::error::VerifyError;
use crate::signature_verifier::SignatureVerifier;

/// Verifies Ethereum-signed messages.
///
/// # Examples
/// You should ensure the hexadecimal inputs are correctly formatted and represent valid
/// Ethereum addresses and signatures. Malformed or invalid inputs will result in a verification
/// failure.
///
/// ```rust
/// let verifier = EthereumSignatureVerifier;
/// let signature = "7c7240d970b40d0b7a7a798584fee..."; // Signature in hex format
/// let message = "Message to verify";
/// let signer_pubkey = "0x1234..."; // Public key in hex format
///
/// match verifier.verify(signature, message, signer_pubkey) {
///     Ok(()) => println!("Signature verified successfully."),
///     Err(e) => println!("Verification failed: {:?}", e),
/// }
/// ```
pub struct EthereumVerifier;

impl SignatureVerifier for EthereumVerifier {
    fn verify<M: AsRef<str>>(
        signature: M,
        message: M,
        signer_pubkey: M,
    ) -> Result<(), VerifyError> {
        let message = message.as_ref();
        let signature = signature.as_ref();
        let signer_pubkey = signer_pubkey.as_ref();

        let message_hash = keccak256(
            format!(
                "{}{}{}",
                "\x19Ethereum Signed Message:\n",
                message.len(),
                message,
            )
            .as_bytes(),
        );

        let signature_bytes = hex::decode(signature)?;
        if signature_bytes.len() != 65 {
            return Err(VerifyError::InvalidEncoding(format!(
                "The signature has wrong length: {}, Expected: 65",
                signature_bytes.len(),
            )));
        }

        let recovery_id = signature_bytes[64] as i32 - 27;

        let extracted_signer = recover(&message_hash, &signature_bytes[..64], recovery_id)
            .map(|pubkey| format!("{:02x?}", pubkey))?;

        if signer_pubkey.to_lowercase() == extracted_signer {
            Ok(())
        } else {
            Err(VerifyError::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_signature_is_ok() {
        let msg = "hello, world!";
        let signature = "7c7240d970b40d0b7a7a798584fee5dbc3e64a7fd276eb068c9139e84bda6b57383276bf73f32ef7055969d0c896884350fc5e899a17904a5f728c5055d8c70d1b";
        let pk = "0x099dC008292EF1FEb96fBF67eA47fB71fde142C3";

        let res = EthereumVerifier::verify(signature, msg, pk);
        assert!(res.is_ok())
    }

    #[test]
    fn wrong_message_declined() {
        let msg = "helloworld!";
        let signature = "7c7240d970b40d0b7a7a798584fee5dbc3e64a7fd276eb068c9139e84bda6b57383276bf73f32ef7055969d0c896884350fc5e899a17904a5f728c5055d8c70d1b";
        let pk = "0x099dC008292EF1FEb96fBF67eA47fB71fde142C3";

        let res = EthereumVerifier::verify(signature, msg, pk);
        assert!(res.is_err())
    }

    #[test]
    fn wrong_signature_declined() {
        let msg = "hello, world!";
        let signature = "777240d970b40d0b7a7a798584fee5dbc3e64a7fd276eb068c9139e84bda6b57383276bf73f32ef7055969d0c896884350fc5e899a17904a5f728c5055d8c70d1b";
        let pk = "0x099dC008292EF1FEb96fBF67eA47fB71fde142C3";

        let res = EthereumVerifier::verify(signature, msg, pk);
        assert!(res.is_err())
    }
}
