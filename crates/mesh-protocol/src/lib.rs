//! Bounded decoders for the existing MeshAgent authentication wire format.
//!
//! Decoding does NOT authenticate a peer. In particular, certificate and signature
//! bytes remain unverified. This crate must never grant enrollment or session rights.
//! See upstream `meshagent.js` (commands 1–5 and 30) and native MeshAgent
//! `agentcore.c` (host information, command 31) for the reference behavior.

use std::{error::Error, fmt};

mod pkcs7;
pub use pkcs7::pkcs7_rsa_signature;

pub const HASH_LENGTH: usize = 48;
pub const MAX_HANDSHAKE_FRAME: usize = 16 * 1024;
pub const MAX_COMPUTER_NAME: usize = 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeFrame<'a> {
    Challenge {
        web_certificate_hash: &'a [u8; HASH_LENGTH],
        nonce: &'a [u8; HASH_LENGTH],
    },
    CertificateProof {
        certificate_der: &'a [u8],
        signature: &'a [u8],
    },
    AgentInfo(AgentInfo<'a>),
    ServerIdentityAccepted,
    ExpectedServerIdentity(&'a [u8]),
    AgentCommitDate(&'a str),
    HostInfo(&'a str),
}

#[derive(Debug, PartialEq, Eq)]
pub struct AgentInfo<'a> {
    pub info_version: u32,
    pub architecture: u32,
    pub agent_version: u32,
    pub platform: u32,
    pub mesh_id: &'a [u8; HASH_LENGTH],
    pub capabilities: u32,
    pub computer_name: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    InvalidLength,
    FrameTooLarge,
    InvalidUtf8,
    UnsupportedCommand(u16),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated handshake frame"),
            Self::InvalidLength => f.write_str("invalid handshake frame length"),
            Self::FrameTooLarge => f.write_str("handshake frame exceeds the configured limit"),
            Self::InvalidUtf8 => f.write_str("invalid UTF-8 in handshake metadata"),
            Self::UnsupportedCommand(command) => {
                write!(f, "unsupported handshake command {command}")
            }
        }
    }
}

impl Error for DecodeError {}

/// Decode one complete binary WebSocket message. Integers use network byte order.
/// Unknown commands and extra/truncated bytes fail closed; this is intentionally
/// stricter than the reference parser's handling of malformed metadata.
pub fn decode_handshake(frame: &[u8]) -> Result<HandshakeFrame<'_>, DecodeError> {
    if frame.len() > MAX_HANDSHAKE_FRAME {
        return Err(DecodeError::FrameTooLarge);
    }
    let command = read_u16(frame, 0)?;
    match command {
        1 => {
            require_length(frame, 98)?;
            Ok(HandshakeFrame::Challenge {
                web_certificate_hash: array_at(frame, 2)?,
                nonce: array_at(frame, 50)?,
            })
        }
        2 => {
            let certificate_length = usize::from(read_u16(frame, 2)?);
            let signature_offset = 4 + certificate_length;
            if certificate_length == 0 || signature_offset >= frame.len() {
                return Err(DecodeError::InvalidLength);
            }
            Ok(HandshakeFrame::CertificateProof {
                certificate_der: &frame[4..signature_offset],
                signature: &frame[signature_offset..],
            })
        }
        3 => {
            if frame.len() < 70 {
                return Err(DecodeError::Truncated);
            }
            let computer_name = if frame.len() == 70 {
                ""
            } else {
                let name_length = usize::from(read_u16(frame, 70)?);
                if name_length > MAX_COMPUTER_NAME {
                    return Err(DecodeError::InvalidLength);
                }
                require_length(frame, 72 + name_length)?;
                std::str::from_utf8(&frame[72..]).map_err(|_| DecodeError::InvalidUtf8)?
            };
            Ok(HandshakeFrame::AgentInfo(AgentInfo {
                info_version: read_u32(frame, 2)?,
                architecture: read_u32(frame, 6)?,
                agent_version: read_u32(frame, 10)?,
                platform: read_u32(frame, 14)?,
                mesh_id: array_at(frame, 18)?,
                capabilities: read_u32(frame, 66)?,
                computer_name,
            }))
        }
        4 => {
            require_length(frame, 2)?;
            Ok(HandshakeFrame::ServerIdentityAccepted)
        }
        5 => match frame.len() {
            34 | 50 => Ok(HandshakeFrame::ExpectedServerIdentity(&frame[2..])),
            _ => Err(DecodeError::InvalidLength),
        },
        30 => {
            if frame.len() <= 2 || frame.len() > 130 {
                return Err(DecodeError::InvalidLength);
            }
            Ok(HandshakeFrame::AgentCommitDate(
                std::str::from_utf8(&frame[2..]).map_err(|_| DecodeError::InvalidUtf8)?,
            ))
        }
        31 => {
            if frame.len() <= 2 || frame.len() > 514 {
                return Err(DecodeError::InvalidLength);
            }
            Ok(HandshakeFrame::HostInfo(
                std::str::from_utf8(&frame[2..]).map_err(|_| DecodeError::InvalidUtf8)?,
            ))
        }
        _ => Err(DecodeError::UnsupportedCommand(command)),
    }
}

fn require_length(frame: &[u8], expected: usize) -> Result<(), DecodeError> {
    if frame.len() == expected {
        Ok(())
    } else {
        Err(DecodeError::InvalidLength)
    }
}

fn array_at<const N: usize>(frame: &[u8], offset: usize) -> Result<&[u8; N], DecodeError> {
    frame
        .get(offset..offset + N)
        .ok_or(DecodeError::Truncated)?
        .try_into()
        .map_err(|_| DecodeError::Truncated)
}

fn read_u16(frame: &[u8], offset: usize) -> Result<u16, DecodeError> {
    Ok(u16::from_be_bytes(*array_at(frame, offset)?))
}

fn read_u32(frame: &[u8], offset: usize) -> Result<u32, DecodeError> {
    Ok(u32::from_be_bytes(*array_at(frame, offset)?))
}
