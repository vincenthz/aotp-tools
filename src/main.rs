mod args;
mod migration;
mod qr;

use std::path::Path;
use url::Url;

fn qr_dump<P: AsRef<Path>>(loc: P, debug: bool, use_url: bool) -> anyhow::Result<()> {
    fn dump_otp(_: usize, otp: &aotp::OTP) {
        println!(
            "  * name: {:?} issuer: {} -- alg: {:?} -- digits: {:?} -- secret: {}",
            otp.account.as_ref().unwrap_or(&String::new()),
            otp.issuer,
            otp.algorithm,
            otp.digits,
            base32::encode(base32::Alphabet::RFC4648 { padding: false }, &otp.secret)
        )
    }

    let qr_dump_one = |i: usize, url: &Url| {
        let aotp = aotp::OTP::from_url(url).expect("working OTP");
        if debug {
            dump_otp(i, &aotp)
        } else if use_url {
            let url = aotp.to_url();
            println!("{}", url)
        } else {
        }
    };

    let qr_dump_migration = |i: usize, url: &Url| match migration::try_one(&url) {
        Err(otp_migration_err) => {
            println!("{} : otp error: {}", i, otp_migration_err)
        }
        Ok(found) => {
            if debug {
                println!("{} : ", i);
                for m in found {
                    println!(
                        "  version: {} batch-id: {} batch-index: {} batch-size: {}",
                        m.version, m.batch_id, m.batch_index, m.batch_size
                    );
                    for params in m.otp_parameters {
                        let otp = migration::params_to_otp(&params).expect("otp params valid");
                        dump_otp(i, &otp);
                    }
                }
            } else if use_url {
                let url = migration::to_url(&found);
                println!("{}", url)
            } else {
                for m in found {
                    println!(
                        "  version: {} batch-id: {} batch-index: {} batch-size: {}",
                        m.version, m.batch_id, m.batch_index, m.batch_size
                    );
                    for params in m.otp_parameters {
                        let otp = migration::params_to_otp(&params).expect("otp params valid");
                        println!("{}", otp.to_url())
                    }
                }
            }
        }
    };

    let results = qr::to_strings(loc).expect("qr image");

    println!("{} entity found", results.len());
    for (i, result) in results.iter().enumerate() {
        match result {
            Err(e) => {
                println!("{} : image decoding error {}", i, e)
            }
            Ok(decoded_string) => match Url::parse(decoded_string) {
                Err(parse_err) => {
                    println!("{} : OTP URL error: {}", i, parse_err)
                }
                Ok(url) => match url.scheme() {
                    "otpauth-migration" => qr_dump_migration(i, &url),
                    "otpauth" => qr_dump_one(i, &url),
                    scheme => {
                        anyhow::bail!("unknown OTP scheme {}", scheme)
                    }
                },
            },
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = args::args();
    match args.command {
        args::Commands::QrDump { path, debug, url } => qr_dump(&path, debug, url),
    }
}
