use thiserror::Error;

use std::io;

#[derive(Debug, Error)]
pub enum Error {
    #[error("bytes sent not equal to pkt size")]
    PartialSend,
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("dns_message_parser decode: {0}")]
    DnsDecode(#[from] dns_message_parser::DecodeError),
    #[error("dns_message_parser encode: {0}")]
    DnsEncode(#[from] dns_message_parser::EncodeError),
}

pub type Result<T> = std::result::Result<T, Error>;
