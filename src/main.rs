#![feature(never_type)]
mod cli;
use std::process::exit;
use rocksdb::{DB, IteratorMode};
use structopt::*;
use cli::Opt::*;
use std::fmt::Debug;
use std::io::Write;
use mimalloc::MiMalloc;
use clipboard::{ClipboardContext, ClipboardProvider};

#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;
#[inline(always)]
fn failed_with<T  : Debug  + 'static, U>(message: &str) -> Box<dyn FnOnce(T) -> U>{
    let message = String::from(message);
    Box::new(move |_| {
        eprintln!("[ERROR] {}", message);
        exit(1)
    })
}

#[inline(always)]
fn get_var(key: &str) -> String {
    std::env::var(key)
        .unwrap_or_else(failed_with(format!("unable to get {}", key).as_str()))
}

fn main() {
    let mut opt = cli::Opt::from_args();
    let gen = botan::RandomNumberGenerator::new()
        .unwrap_or_else(failed_with("unable to initialize generator"));
    if let GenKey {path}  = opt {
        let password = rpassword::read_password_from_tty(Some("password for the private key: "))
            .unwrap_or_else(failed_with("unable to read the password"));
        let prikey = botan::Privkey::create("RSA", "16384", &gen)
            .unwrap_or_else(failed_with("unable to create private key"));
        let pubkey = prikey.pubkey()
            .unwrap_or_else(failed_with("unable to create public key"));
        std::fs::write(format!("{}/keeper_pub.pem", path.as_str()), pubkey.pem_encode().unwrap())
            .unwrap_or_else(failed_with("unable to write the public key"));
        std::fs::write(format!("{}/keeper_pri.pem", path.as_str()), prikey
            .pem_encode_encrypted(password.as_str(), &gen).unwrap())
            .unwrap_or_else(failed_with("unable to write the private key"));
    } else {
        let data_path = get_var("PASSKEEPER_DATA_PATH");
        let db = DB::open_default(data_path).unwrap_or_else(failed_with("unable to open data base"));
        let mut pass = if let GenPassword {name} = opt {
            let mut k : [u8; 16] = [0; 16];
            gen.fill(&mut k).unwrap_or_else(failed_with("unable to generate random bits"));
            let pass = botan::base64_encode(&k).unwrap();
            println!("{}", pass);
            opt = Add { name };
            Some(pass)
        } else if let AddFile {name, path} = opt {
            let file = std::fs::read_to_string(path)
                .unwrap_or_else(failed_with("unable to read file"));
            opt = Add { name };
            Some(file)
        }
        else { None };
        match opt {
            List => {
                let iter = db.iterator(IteratorMode::Start);
                for (key, _) in iter {
                    println!("{}", String::from_utf8_lossy(&*key));
                }
            },
            Add { name} => {
                if pass.is_none() {
                    pass.replace(rpassword::read_password_from_tty(Some("input the password: "))
                        .unwrap_or_else(failed_with("unable to read the password")));
                }
                let public_path = get_var("PASSKEEPER_PUBLIC_KEY_PATH");
                let public_key = std::fs::read_to_string(public_path)
                    .map(|x| botan::Pubkey::load_pem(
                        x.as_str()).unwrap_or_else(failed_with("unable to load public key")))
                    .unwrap_or_else(failed_with("failed to read public key"));
                if let Ok(Some(_)) = db.get(&name) {
                    failed_with::<(), ()>("name existed")(());
                }
                let encryptor = botan::Encryptor::new(&public_key, "OAEP(SHA-256)")
                    .unwrap_or_else(failed_with("unable to init the encryptor"));
                let encoded = encryptor.encrypt(pass.unwrap().as_bytes(), &gen)
                    .unwrap_or_else(failed_with("unable to encrypted the password"));
                db.put(name, encoded)
                    .and_then(|_|db.flush())
                    .unwrap_or_else(failed_with("unable to write the key"));
            },
            Remove {name} => {
                match db.get(&name) {
                    Err(_) | Ok(None) => failed_with::<(), ()>("name does not exist")(()),
                    Ok(Some(_)) => {
                        print!("re-type the name to confirm the deletion: ");
                        std::io::stdout().flush().unwrap();
                        let mut line = String::new();
                        std::io::stdin().read_line(&mut line)
                            .unwrap_or_else(failed_with("invalid input"));
                        if line.trim() == name {
                            db.delete(name)
                                .unwrap_or_else(failed_with("unable to delete the password from datebase"));
                        }
                    }
                }
            },
            Fetch {name, clipboard: clip} => {
                match db.get(&name) {
                    Err(_) | Ok(None) => failed_with::<(), ()>("name does not exist")(()),
                    Ok(Some(content)) => {
                        let password = rpassword::read_password_from_tty(Some("password for the private key: "))
                            .unwrap_or_else(failed_with("unable to read the password"));
                        let private_path = get_var("PASSKEEPER_PRIVATE_KEY_PATH");
                        let private_key = std::fs::read_to_string(private_path)
                            .map(|x| botan::Privkey::load_encrypted_pem(
                                x.as_str(), password.as_str())
                                .unwrap_or_else(failed_with("unable to load private key")))
                            .unwrap_or_else(failed_with("failed to read private key"));
                        let decrypter = botan::Decryptor::new(&private_key, "OAEP(SHA-256)")
                            .unwrap_or_else(failed_with("unable to initalize decrypter"));
                        let password = decrypter.decrypt(content.as_slice())
                            .unwrap_or_else(failed_with("unable to decrypt the password"));
                        if clip {
                            let mut cb: ClipboardContext = ClipboardProvider::new()
                                .unwrap_or_else(failed_with("unable to initalize clipboard"));
                            unsafe {
                                cb.set_contents(String::from_utf8_unchecked(password))
                                    .unwrap_or_else(failed_with("unable to set clipboard"));
                            }
                        } else {
                            println!("{}", String::from_utf8_lossy(password.as_slice()));
                        }
                    }
                }
            }
            _ => unimplemented!()
        }
    }
}
