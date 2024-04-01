use anyhow::anyhow;
use web3::signing::{keccak256, recover};

use crate::signature_verifier::SignatureVerifier;

pub struct EthereumVerifier;

impl SignatureVerifier for EthereumVerifier {
    fn verify<M: AsRef<str>>(
        signature: M,
        message: M,
        signer_pubkey: M,
    ) -> Result<(), anyhow::Error> {
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
        let recovery_id = signature_bytes[64] as i32 - 27;

        let extracted_signer = recover(&message_hash, &signature_bytes, recovery_id)
            .map(|pubkey| format!("{:02x?}", pubkey))?;

        if signer_pubkey == extracted_signer {
            Ok(())
        } else {
            Err(anyhow!("Invalid signature!"))
        }
    }
}
