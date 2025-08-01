use bitcoin::{bech32::primitives::decode::CheckedHrpstringError, secp256k1};

/// Silent payment code parsing error
#[derive(Debug)]
pub enum ParseError {
    /// Bech32 decoding error
    Bech32(CheckedHrpstringError),
    /// Version does not comply with spec
    Version(VersionError),
    /// The human readable prefix is not supported for silent payments
    UnknownHrp(UnknownHrpError),
    /// Some public key couldn't be derived from the provided payload
    InvalidPubKey(secp256k1::Error),
}

impl core::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        use ParseError::*;

        match *self {
            Bech32(ref e) => Some(e),
            Version(ref e) => Some(e),
            UnknownHrp(ref e) => Some(e),
            InvalidPubKey(ref e) => Some(e),
        }
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use ParseError::*;

        match *self {
            Bech32(ref e) => e.fmt(f),
            Version(ref e) => e.fmt(f),
            UnknownHrp(ref e) => e.fmt(f),
            InvalidPubKey(ref e) => e.fmt(f),
        }
    }
}

impl From<UnknownHrpError> for ParseError {
    fn from(e: UnknownHrpError) -> Self {
        Self::UnknownHrp(e)
    }
}

impl From<VersionError> for ParseError {
    fn from(e: VersionError) -> Self {
        Self::Version(e)
    }
}

impl From<bitcoin::bech32::primitives::decode::CheckedHrpstringError> for ParseError {
    fn from(e: bitcoin::bech32::primitives::decode::CheckedHrpstringError) -> Self {
        Self::Bech32(e)
    }
}

impl From<bitcoin::secp256k1::Error> for ParseError {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Self::InvalidPubKey(e)
    }
}

/// Unknown HRP error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownHrpError(pub String);

impl core::fmt::Display for UnknownHrpError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "unknown hrp: {}", self.0)
    }
}

impl core::error::Error for UnknownHrpError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        None
    }
}

/// Silent payment error related to versions
#[derive(Debug)]
pub enum VersionError {
    /// Silent payment v31 code. It is not backward compatible
    BackwardIncompatibleVersion,
    /// The length of the payload doesn't match the version of the code
    WrongPayloadLength,
}

impl core::fmt::Display for VersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use VersionError::*;

        match *self {
            BackwardIncompatibleVersion => {
                write!(f, "version 31 codes are not backward compatible")
            }
            WrongPayloadLength => write!(f, "payload length does not match version spec"),
        }
    }
}

impl core::error::Error for VersionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        None
    }
}
