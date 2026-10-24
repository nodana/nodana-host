fn main() {
    let domain = std::env::var("NODANA_PUBLIC_DOMAIN").unwrap_or_else(|_| {
        for path in ["../public-domain.txt", "../../public-domain.txt"] {
            println!("cargo:rerun-if-changed={path}");
            if let Ok(value) = std::fs::read_to_string(path) {
                return value;
            }
        }
        panic!("public domain input required");
    });
    println!("cargo:rerun-if-env-changed=NODANA_PUBLIC_DOMAIN");
    let domain = domain.trim();
    assert!(
        domain.len() <= 253
            && domain.contains('.')
            && domain.split('.').all(|label| !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-'))
    );
    std::fs::write(
        std::path::Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("public-domain.txt"),
        domain,
    )
    .unwrap();
}
