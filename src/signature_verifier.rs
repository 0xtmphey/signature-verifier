use anyhow::Error;

pub trait SignatureVerifier {
    fn verify<S: AsRef<str>>(signature: S, message: S, signer_pubkey: S) -> Result<(), Error>;
}
