use std::{io, str::Utf8Error};

use super::channel::ChannelOpenFailureReson;
use openssl::error::ErrorStack;
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Openssl error")]
    OpensslError(#[from] ErrorStack),

    #[error("Standard io error")]
    IOError(#[from] io::Error),

    #[error("UndefinedBehavior: {0}")]
    UndefinedBehavior(String),

    #[error("Failed to Decode binary data as utf8")]
    Utf8Error(#[from] Utf8Error),

    #[error("The peer does not support ssh2")]
    Ssh2Unsupport,

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Algorithm negotiation failed")]
    NegotiationFailed,

    #[error("Banner exchange failed: {0}")]
    BannerExchange(String),

    #[error("Server connection lost")]
    Disconnected,

    #[error("Server Message mac verification failed")]
    MacVerificationFailed,

    #[error("Channel open failed")]
    ChannelOpenFail(ChannelOpenFailureReson, String),

    #[error("Channel failed")]
    ChannelFailure,

    // #[error("internal error: failed to find channel")]
    // ChannelNotFound,
    #[error("error code: {0:?} {1}")]
    ScpError(Option<u8>, String),

    #[error("Channel was closed")]
    ChannelClosed,

    #[error("Channel end of file")]
    ChannelEOF,

    #[error("Failed to verify hostkey")]
    HostKeyVerifyFailed,

    #[error("Failed to request subsystem from server")]
    SubsystemFailed,

    #[error("Resource is temporarily unavailable")]
    TemporarilyUnavailable,

    #[error("Uncompress or Compress Error")]
    CompressFailed,

    #[error("Failed to parse binary: {0}")]
    InvalidFormat(String),

    #[error("The packet with sequence number {0} was rejected by the server")]
    Unimplemented(u32),

    #[error("User reject: {0}")]
    RejectByUser(String),

    #[error("Invalid Argument: {0}")]
    InvalidArgument(String),

    #[error("SFtp: {0}")]
    NoSuchFile(String),

    #[error("SFtp: {0}")]
    PermissionDenied(String),

    #[error("SFtp: {0}")]
    SFtpFailure(String),

    #[error("SFtp: {0}")]
    BadMessage(String),

    #[error("SFtp: {0}")]
    NoConnection(String),

    #[error("SFtp: {0}")]
    ConnectionLost(String),

    #[error("SFtp: {0}")]
    OpUnsupported(String),

    #[error("Failed to Request: {0}")]
    RequestFailure(String),
}

// struct Unexpect {
//     expect: Vec<String>,
//     found: String
// }

impl Error {
    pub fn ub(tip: impl Into<String>) -> Self {
        Self::UndefinedBehavior(tip.into())
    }

    // pub fn ssh_packet_parse(tip: impl Into<String>) -> Self {
    //     Self::SshPacketParseError(tip.into())
    // }

    pub fn scp_error(code: Option<u8>, tip: impl Into<String>) -> Self {
        Self::ScpError(code, tip.into())
    }

    pub fn invalid_format(tip: impl Into<String>) -> Self {
        Self::InvalidFormat(tip.into())
    }
}

impl From<RecvError> for Error {
    fn from(_: RecvError) -> Self {
        Self::Disconnected
    }
}
