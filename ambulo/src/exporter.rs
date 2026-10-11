use crate::libs::ambulo_db::AmbuloDb;
use tokio::io::AsyncWriteExt;

pub struct Exporter {
    scan_id: i64,
    db: AmbuloDb,
    file_path: String,
}

impl Exporter {
    pub fn new(scan_id: i64, db: &AmbuloDb, file_path: &str) -> Self {
        Exporter {
            scan_id,
            db: db.clone(),
            file_path: file_path.to_string(),
        }
    }

    pub async fn csv(&self) -> Result<(), String> {
        let results = match self.db.get_scan_results(self.scan_id, 0, 0).await {
            Ok(res) => res,
            Err(e) => return Err(e.to_string()),
        };

        let mut wtr = match csv::Writer::from_path(&self.file_path) {
            Ok(writer) => writer,
            Err(e) => return Err(format!("Failed to create CSV writer: {e}")),
        };

        for result in results.found {
            if let Err(e) = wtr.serialize(result) {
                return Err(format!("Failed to write to CSV file: {e}"));
            }
        }

        if let Err(e) = wtr.flush() {
            return Err(format!("Failed to flush CSV file: {e}"));
        }

        Ok(())
    }

    pub async fn text(&self) -> Result<(), String> {
        let results = match self.db.get_scan_results(self.scan_id, 0, 0).await {
            Ok(res) => res,
            Err(e) => return Err(e.to_string()),
        };

        let mut file = match tokio::fs::File::create(&self.file_path).await {
            Ok(f) => f,
            Err(e) => return Err(format!("Failed to create text file: {e}")),
        };

        for result in results.found {
            // url, body_length, headers_length, req status,
            // line contains
            let mut entry = String::from("");
            entry.push_str("------------------------------\n");
            entry.push_str(&format!("URL: {}\n", result.url));
            entry.push_str(&format!("Body Size: {}\n", result.body_length));
            entry.push_str(&format!("Headers: {}\n", result.headers_length));
            entry.push_str(&format!("Status Code: {}\n", result.request_status));

            if let Err(e) = file.write_all(entry.as_bytes()).await {
                return Err(format!("Failed to write to text file: {e}"));
            }
        }

        if let Err(e) = file.flush().await {
            return Err(format!("Failed to flush text file: {e}"));
        }

        Ok(())
    }

    pub async fn export(&self, output_format: &str) -> Result<(), String> {
        match output_format {
            "csv" => self.csv().await,
            "text" => self.text().await,
            _ => Err("Invalid output format".to_string()),
        }
    }
}
