use crate::libs::sha::sha512_from_filepath;
#[derive(Debug)]
pub struct WordlistConfig {
    pub path: String,
    pub name: String,
    pub hash: String,
}

impl WordlistConfig {
    pub async fn new(p: &str) -> Result<WordlistConfig, Box<dyn std::error::Error>> {
        let path = match p.is_empty() {
            true => return Err("[ERROR] No wordlist is specified".into()),
            false => p.to_string(),
        };

        let name = std::path::Path::new(&path)
            .file_name()
            .ok_or("[ERROR] Invalid wordlist path")?
            .to_str()
            .ok_or("[ERROR] Invalid wordlist name")?
            .to_string();

        let hash = sha512_from_filepath(&path).await?;

        Ok(WordlistConfig { path, name, hash })
    }
}
