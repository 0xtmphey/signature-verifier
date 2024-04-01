use anyhow::Error;

pub trait SignatureVerifier {
    fn verify<M: AsRef<str>>(signature: M, message: M, signer_pubkey: M) -> Result<(), Error>;
}
