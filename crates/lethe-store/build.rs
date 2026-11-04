use std::{
    env, fs,
    path::{Path, PathBuf},
};

/// OpenSSL's runtime library, newest major version first: Win64 OpenSSL 4 ships
/// `libcrypto-4-x64.dll`, version 3 `libcrypto-3-x64.dll`.
const LIBCRYPTO_DLLS: [&str; 2] = ["libcrypto-4-x64.dll", "libcrypto-3-x64.dll"];

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_LIB_DIR");

    let Some(source) = find_libcrypto() else {
        println!(
            "cargo:warning=no OpenSSL runtime ({}) was found; Windows binaries may fail to launch unless OpenSSL bin is on PATH",
            LIBCRYPTO_DLLS.join(" or ")
        );
        return;
    };

    let Some(profile_dir) = cargo_profile_dir() else {
        println!("cargo:warning=Could not resolve Cargo profile dir for OpenSSL runtime copy");
        return;
    };

    copy_to(&source, &profile_dir);
    copy_to(&source, &profile_dir.join("deps"));
}

/// Looks in the OpenSSL the build links against first, so the copied runtime matches it.
fn find_libcrypto() -> Option<PathBuf> {
    candidate_dirs()
        .into_iter()
        .flat_map(|dir| {
            LIBCRYPTO_DLLS.map(|dll| {
                [dir.join(dll), dir.join("bin").join(dll), dir.join("..").join("bin").join(dll)]
            })
        })
        .flatten()
        .find(|path| path.is_file())
}

fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    for key in ["OPENSSL_DIR", "OPENSSL_LIB_DIR"] {
        if let Some(value) = env::var_os(key) {
            dirs.push(PathBuf::from(value));
        }
    }

    if let Some(profile) = env::var_os("USERPROFILE") {
        dirs.push(
            PathBuf::from(profile)
                .join("scoop")
                .join("apps")
                .join("openssl")
                .join("current"),
        );
    }

    dirs.push(PathBuf::from(r"C:\Program Files\OpenSSL-Win64"));
    dirs
}

fn cargo_profile_dir() -> Option<PathBuf> {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR")?);
    out_dir.ancestors().nth(3).map(Path::to_path_buf)
}

fn copy_to(source: &Path, dest_dir: &Path) {
    if fs::create_dir_all(dest_dir).is_err() {
        println!(
            "cargo:warning=Could not create OpenSSL runtime destination {}",
            dest_dir.display()
        );
        return;
    }

    let dest = dest_dir.join(source.file_name().expect("DLL source has a file name"));
    if let Err(err) = fs::copy(source, &dest) {
        println!(
            "cargo:warning=Could not copy OpenSSL runtime DLL to {}: {err}",
            dest.display()
        );
    }
}
