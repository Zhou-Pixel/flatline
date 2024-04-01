use std::{io, string::FromUtf8Error};

use openssl::error::ErrorStack;
use thiserror::Error;

use crate::session::ChannelOpenFailureReson;


pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("openssl error")]
    OpensslError(#[from] ErrorStack),

    #[error("std io error")]
    IOError(#[from] io::Error),

    // #[error("custom io timeout")]
    // Timeout,
    #[error("UndefinedBehavior: {0}")]
    UndefinedBehavior(String),

    // #[error("{0}")]
    // SshPacketParseError(String),
    #[error("Failed to Decode binary data as utf8")]
    Utf8Error(#[from] FromUtf8Error),

    #[error("The peer does not support ssh2")]
    Ssh2Unsupport,

    #[error("unexpect msg from server")]
    UnexpectMsg,

    #[error("Algorithm negotiation failed")]
    NegotiationFailed,

    #[error("banner exchange failed: {0}")]
    BannerExchange(String),

    #[error("disconnect")]
    Disconnect,

    #[error("Server Message mac verification failed")]
    MacVerificationFailed,

    #[error("Channel open failed")]
    ChannelOpenFail(ChannelOpenFailureReson, String),

    #[error("Channel failed")]
    ChannelFailure,

    // #[error("internal error: failed to find channel")]
    // ChannelNotFound,

    #[error("channel closed")]
    ChannelClosed,

    #[error("channel end of file")]
    ChannelEof,

    #[error("host key verify failed")]
    HostKeyVerifyFailed,

    #[error("failed to startup sftp")]
    SubsystemFailed,

    #[error("Resource is temporarily unavailable")]
    TemporarilyUnavailable,

    #[error("Uncompress or Compress Error")]
    CompressFailed,

    #[error("Failed to parse binary: {0}")]
    InvalidFormat(String),

    // #[error("error code: {0:?}, msg: {1}")]
    // SFtpError(Status, String),

    #[error("{0}")]
    NoSuchFile(String),

    #[error("{0}")]
    PermissionDenied(String),

    #[error("{0}")]
    SFtpFailure(String),

    #[error("{0}")]
    BadMessage(String),

    #[error("{0}")]
    NoConnection(String),

    #[error("{0}")]
    ConnectionLost(String),

    #[error("{0}")]
    OpUnsupported(String),
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

    pub fn invalid_format(tip: impl Into<String>) -> Self {
        Self::InvalidFormat(tip.into())
    }
}
