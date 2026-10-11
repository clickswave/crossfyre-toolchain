use sha2::Digest;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

// generate sha512 from a json string
pub async fn sha512_from_string(string: String) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = sha2::Sha512::new();
    hasher.update(string);
    let result = hasher.finalize();
    Ok(format!("{result:x}"))
}

// get sha512 hash of a file
pub async fn sha512_from_filepath(file_path: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(file_path).await?;
    let mut hasher = sha2::Sha512::new();
    let mut buffer = [0; 4096];
    while let Ok(n) = file.read(&mut buffer).await {
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let hash_result = hasher.finalize();
    Ok(format!("{hash_result:x}"))
}
