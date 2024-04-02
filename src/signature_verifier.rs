use crate::error::VerifyError;

/// A trait for verifying digital signatures.
///
/// A common use-case would be to verify that provided public key owner indeed signed a message.
///
/// # Errors
///
/// A successful verification returns `Ok(())`, indicating
/// that the signature is valid for the given message and public key.
/// A failed verification returns `Err(VerifyError)`, where `VerifyError` can be:
///
/// ### InvalidEncoding(String)
/// Indicates that some of the provided data (signature/message/public key) is malformed
/// (wrong size, wrong encoding). The string argument is the cause of the error.
///
/// ### InvalidSignature
/// Indicates that the signature doesn't match the provided public key or simply invalid.
///
/// # Examples
///
/// ```ignore
/// # struct MyVerifier;
/// # impl SignatureVerifier for MyVerifier {
/// #     fn verify<S: AsRef<str>>(signature: S, message: S, signer_pubkey: S)
/// #         -> Result<(), VerifyError> { Ok(()) }
/// # }
/// #
/// let verifier = MyVerifier;
/// let signature = "example_signature";
/// let message = "Hello, world!";
/// let signer_pubkey = "example_pubkey";
///
/// match verifier.verify(signature, message, signer_pubkey) {
///     Ok(()) => println!("Signature verified successfully."),
///     Err(e) => println!("Verification failed: {:?}", e),
/// }
/// ```
pub trait SignatureVerifier {
    /// Verifies a digital signature against a specified message and signer's public key.
    ///
    /// `signature`: The digital signature to verify.
    /// `message`: The original message that was signed.
    /// `signer_pubkey`: The public key of the signer.
    ///
    /// Returns `Ok(())` if the signature is valid, or `Err(VerifyError)` if it's not.
    fn verify<S: AsRef<str>>(signature: S, message: S, signer_pubkey: S)
        -> Result<(), VerifyError>;
}
