use sha2::Digest;

/// Hex sha512 of `bytes`.
pub fn sha512(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", sha2::Sha512::digest(bytes))
}
