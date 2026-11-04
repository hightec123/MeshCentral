//! Extract the legacy Windows agent's bare RSA signature from PKCS#7 SignedData.
//! This is framing only: callers MUST verify the returned bytes using the pinned
//! outer certificate and fresh handshake transcript. Embedded certificates,
//! content and issuer names never establish identity or trust.
use crate::{DecodeError, MAX_HANDSHAKE_FRAME};

const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2];
const DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1];
const SHA384: &[u8] = &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 2];
const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1];
const RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 12];

struct Der<'a>(&'a [u8]);
impl<'a> Der<'a> {
    fn value(&mut self, tag: u8) -> Result<&'a [u8], DecodeError> {
        if self.0.first() != Some(&tag) {
            return Err(DecodeError::InvalidLength);
        }
        let first = *self.0.get(1).ok_or(DecodeError::Truncated)?;
        let (header, length) = if first < 128 {
            (2, usize::from(first))
        } else {
            let count = usize::from(first & 127);
            if count == 0 || count > 2 {
                return Err(DecodeError::InvalidLength);
            }
            let bytes = self.0.get(2..2 + count).ok_or(DecodeError::Truncated)?;
            let length = bytes
                .iter()
                .fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
            if bytes[0] == 0 || length < 128 {
                return Err(DecodeError::InvalidLength);
            }
            (2 + count, length)
        };
        let value = self
            .0
            .get(header..header + length)
            .ok_or(DecodeError::Truncated)?;
        self.0 = &self.0[header + length..];
        Ok(value)
    }
    fn done(&self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::InvalidLength)
        }
    }
    fn algorithm(&mut self, allowed: &[&[u8]]) -> Result<(), DecodeError> {
        let mut algorithm = Der(self.value(0x30)?);
        if !allowed.contains(&algorithm.value(6)?) {
            return Err(DecodeError::InvalidLength);
        }
        if !algorithm.0.is_empty() && !algorithm.value(5)?.is_empty() {
            return Err(DecodeError::InvalidLength);
        }
        algorithm.done()
    }
}

/// Accept one bounded, definite-length DER SignedData signer without signed
/// attributes, matching MeshAgent wincrypto.cpp's CryptMsgOpenToEncode format.
/// The returned RSA bytes remain UNVERIFIED. Do not use embedded signer metadata
/// as authentication. Multiple signers, other algorithms and BER are rejected.
pub fn pkcs7_rsa_signature(bytes: &[u8]) -> Result<&[u8], DecodeError> {
    if bytes.len() > MAX_HANDSHAKE_FRAME {
        return Err(DecodeError::FrameTooLarge);
    }
    let mut envelope = Der(bytes);
    let mut content_info = Der(envelope.value(0x30)?);
    envelope.done()?;
    if content_info.value(6)? != SIGNED_DATA {
        return Err(DecodeError::InvalidLength);
    }
    let mut explicit = Der(content_info.value(0xa0)?);
    content_info.done()?;
    let mut signed = Der(explicit.value(0x30)?);
    explicit.done()?;
    if signed.value(2)? != [1] {
        return Err(DecodeError::InvalidLength);
    }
    let mut algorithms = Der(signed.value(0x31)?);
    algorithms.algorithm(&[SHA384, RSA_SHA384])?;
    algorithms.done()?;
    let mut content = Der(signed.value(0x30)?);
    if content.value(6)? != DATA {
        return Err(DecodeError::InvalidLength);
    }
    if !content.0.is_empty() {
        let mut attached = Der(content.value(0xa0)?);
        attached.value(4)?;
        attached.done()?;
    }
    content.done()?;
    if signed.0.first() == Some(&0xa0) {
        signed.value(0xa0)?;
    } // untrusted certificates
    if signed.0.first() == Some(&0xa1) {
        signed.value(0xa1)?;
    } // untrusted CRLs
    let mut signers = Der(signed.value(0x31)?);
    signed.done()?;
    let mut signer = Der(signers.value(0x30)?);
    signers.done()?;
    if signer.value(2)? != [1] {
        return Err(DecodeError::InvalidLength);
    }
    signer.value(0x30)?; // issuerAndSerialNumber is advisory; outer certificate is pinned
    signer.algorithm(&[SHA384, RSA_SHA384])?;
    signer.algorithm(&[RSA, RSA_SHA384])?; // signed attributes are deliberately unsupported
    let signature = signer.value(4)?;
    if !matches!(signature.len(), 256 | 384 | 512) {
        return Err(DecodeError::InvalidLength);
    }
    if signer.0.first() == Some(&0xa1) {
        signer.value(0xa1)?;
    }
    signer.done()?;
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn der(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let length = if bytes.len() < 128 {
            vec![bytes.len() as u8]
        } else {
            vec![0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]
        };
        [vec![tag], length, bytes.to_vec()].concat()
    }
    fn wrapped(signature: &[u8], algorithm: &[u8], second_signer: bool) -> Vec<u8> {
        let digest = der(0x30, &der(6, algorithm));
        let signer = der(
            0x30,
            &[
                der(2, &[1]),
                der(0x30, &[]),
                digest.clone(),
                der(0x30, &der(6, RSA)),
                der(4, signature),
            ]
            .concat(),
        );
        let signers = if second_signer {
            [signer.clone(), signer].concat()
        } else {
            signer
        };
        der(
            0x30,
            &[
                der(6, SIGNED_DATA),
                der(
                    0xa0,
                    &der(
                        0x30,
                        &[
                            der(2, &[1]),
                            der(0x31, &digest),
                            der(0x30, &der(6, DATA)),
                            der(0x31, &signers),
                        ]
                        .concat(),
                    ),
                ),
            ]
            .concat(),
        )
    }
    #[test]
    fn extracts_only_the_unverified_signature() {
        for size in [256, 384, 512] {
            let signature = vec![0xab; size];
            assert_eq!(
                pkcs7_rsa_signature(&wrapped(&signature, SHA384, false)).unwrap(),
                signature
            );
            assert_eq!(
                pkcs7_rsa_signature(&wrapped(&signature, RSA_SHA384, false)).unwrap(),
                signature
            );
        }
    }
    #[test]
    fn truncated_or_trailing_envelopes_never_parse() {
        let valid = wrapped(&[7; 256], SHA384, false);
        for length in 0..valid.len() {
            assert!(pkcs7_rsa_signature(&valid[..length]).is_err());
        }
        assert!(pkcs7_rsa_signature(&[valid, vec![0]].concat()).is_err());
    }
    #[test]
    fn multiple_signers_and_other_algorithms_fail_closed() {
        assert!(pkcs7_rsa_signature(&wrapped(&[7; 256], SHA384, true)).is_err());
        assert!(pkcs7_rsa_signature(&wrapped(&[7; 256], RSA, false)).is_err());
        assert!(pkcs7_rsa_signature(&wrapped(&[7; 255], SHA384, false)).is_err());
        assert!(pkcs7_rsa_signature(&[0x30, 0x80, 0, 0]).is_err());
        assert!(pkcs7_rsa_signature(&vec![0; MAX_HANDSHAKE_FRAME + 1]).is_err());
    }
}
