//! Which CVEs in a dataset file affect a product at a version, to check a dataset by hand:
//!
//! ```text
//! cargo run -p cfx_cve --example leads -- DATASET PART:VENDOR:PRODUCT[,...] VERSION [DISTRO]
//! ```

use cfx_cve::{Cpe, Dataset};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path, names, version, rest @ ..] = args.as_slice() else {
        eprintln!("usage: leads DATASET PART:VENDOR:PRODUCT[,...] VERSION [DISTRO]");
        std::process::exit(2);
    };
    let bytes = std::fs::read(path).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    let names: Vec<Cpe> = names
        .split(',')
        .map(|name| match name.splitn(3, ':').collect::<Vec<_>>()[..] {
            [part, vendor, product] => Cpe::new(part, vendor, product),
            _ => fail(&format!("{name} is not PART:VENDOR:PRODUCT")),
        })
        .collect();
    let wanted = names.iter().cloned().collect();
    let dataset = Dataset::from_bytes_for(&bytes, &wanted).unwrap_or_else(|e| fail(&e.to_string()));
    println!("dataset {} made {}", dataset.sequence(), dataset.made());
    // Each name asked about is a product of its own.
    let products: Vec<Vec<Cpe>> = names.iter().map(|n| vec![n.clone()]).collect();
    for lead in dataset.leads(&products, version, rest.first().map(String::as_str)) {
        let known = &lead.known;
        println!(
            "{} {} {} kev={} epss={} possible={} backport={}",
            lead.cve,
            known.severity.as_deref().unwrap_or("-"),
            known.score.map_or("-".to_string(), |s| s.to_string()),
            known.kev,
            known.epss.map_or("-".to_string(), |e| e.to_string()),
            lead.possible,
            lead.backport,
        );
    }
}

fn fail(why: &str) -> ! {
    eprintln!("{why}");
    std::process::exit(1)
}
