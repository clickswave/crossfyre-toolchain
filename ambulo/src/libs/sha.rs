use sha2::Digest;

// generate sha512 from a json string
pub async fn sha512_from_string(string: String) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(string);
    let result = hasher.finalize();
    Ok(format!("{result:x}"))
}
