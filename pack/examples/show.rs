//! What a pack file holds, to check one by hand:
//!
//! ```text
//! cargo run -p cfx_pack --example show -- PACK
//! ```

use cfx_pack::{COMPILED, FOLDERS, Pack};

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: show PACK");
        std::process::exit(2);
    };
    let pack = std::fs::read(&path)
        .map_err(|e| e.to_string())
        .and_then(|bytes| Pack::from_bytes(&bytes).map_err(|e| e.to_string()))
        .unwrap_or_else(|e| {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        });
    println!(
        "{} {} of {}, made {}",
        pack.name(),
        pack.sequence(),
        pack.commit(),
        pack.made()
    );
    for folder in FOLDERS {
        println!("{folder}: {} files", pack.files_in(folder).count());
    }
    println!(
        "the copy compiled in is {} of {}: this pack {}",
        COMPILED.sequence,
        COMPILED.commit,
        if pack.replaces_compiled() {
            "replaces it"
        } else {
            "does not replace it"
        }
    );
}
