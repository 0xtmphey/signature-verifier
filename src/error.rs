#[derive(Debug, Clone, PartialEq)]
pub enum VerifyError {
    InvalidEncoding(String),

    InvalidSignature,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::InvalidEncoding(cause) => write!(f, "{}", cause),
            VerifyError::InvalidSignature => write!(f, "Signature is invalid"),
        }
    }
}

impl std::error::Error for VerifyError {}

#[cfg(feature = "ethereum")]
impl From<hex::FromHexError> for VerifyError {
    fn from(value: hex::FromHexError) -> Self {
        Self::InvalidEncoding(value.to_string())
    }
}

#[cfg(feature = "ethereum")]
impl From<web3::signing::RecoveryError> for VerifyError {
    fn from(_value: web3::signing::RecoveryError) -> Self {
        Self::InvalidSignature
    }
}

#[cfg(feature = "solana")]
impl From<bs58::decode::Error> for VerifyError {
    fn from(value: bs58::decode::Error) -> Self {
        Self::InvalidEncoding(value.to_string())
    }
}

#[cfg(feature = "solana")]
impl From<solana_sdk::pubkey::ParsePubkeyError> for VerifyError {
    fn from(value: solana_sdk::pubkey::ParsePubkeyError) -> Self {
        Self::InvalidEncoding(value.to_string())
    }
}

#[cfg(feature = "solana")]
impl From<nacl::Error> for VerifyError {
    fn from(_value: nacl::Error) -> Self {
        Self::InvalidSignature
    }
}
