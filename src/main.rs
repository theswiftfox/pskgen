use std::env::args;

fn main() {
    let args = args().collect::<Vec<String>>();
    if args.len() < 2 {
        println!(
            "WPA Passphrase generator\nUsage: {} <ssid> [passphrase]\nPassphrase is read from stdin if left out.",
            args[0]
        );
        return;
    }

    let (ssid, passphrase) = if args.len() == 2 {
        let pw = rpassword::prompt_password("Enter passphrase: ").unwrap();
        (args[1].clone(), pw.trim().to_owned())
    } else {
        (args[1].clone(), args[2].clone())
    };

    if passphrase.len() < 8 || passphrase.len() > 63 {
        println!("Passphrase must be between 8 and 63 characters long.");
        return;
    }

    let mut psk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase.as_bytes(), ssid.as_bytes(), 4096, &mut psk);

    println!(
        "PSK: {}",
        psk.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );
}
