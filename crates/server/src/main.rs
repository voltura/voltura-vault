use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};
use voltura_server_auth::SecretToken;
use voltura_vault_server::{AppState, initialize, now, rotation, router_with_unix_desktop};

mod restore;

fn maintenance_lock(directory: &std::path::Path) -> std::io::Result<fs::File> {
    let path = directory.join("maintenance.lock");
    match fs::File::open(&path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o644);
            }
            match options.open(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => fs::File::open(&path),
                result => result,
            }
        }
        Err(error) => Err(error),
    }
}

fn minimum_key_epoch() -> Result<u32, Box<dyn std::error::Error>> {
    let epoch = match std::env::var("VOLTURA_MIN_KEY_EPOCH") {
        Ok(value) => value.parse()?,
        Err(std::env::VarError::NotPresent) => 1,
        Err(error) => return Err(error.into()),
    };
    if epoch == 0 {
        return Err("The minimum vault key epoch must be positive".into());
    }
    Ok(epoch)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_, command, data] if command == "rotation-point" => {
            println!("{}", serde_json::to_string(&rotation::inspect(PathBuf::from(data).as_path())?)?);
            return Ok(());
        }
        [_, command, data, replacement, point, options @ ..]
            if command == "activate-rotation" && (options.is_empty() || options == ["--quarantine-invalid"]) => {
            use std::{io::Read, path::Path};
            let directory = Path::new(data);
            let database_lock = maintenance_lock(directory)?;
            database_lock.try_lock().map_err(|_| "Stop the Vault API before activating a rotation")?;
            let floor = std::env::var_os("VOLTURA_KEY_EPOCH_FLOOR").ok_or("Configure the trusted vault epoch file before rotation")?;
            let mut encoded = Vec::new();
            fs::File::open(point)?.take(4097).read_to_end(&mut encoded)?;
            if encoded.len() > 4096 { return Err("Invalid rotation point".into()); }
            rotation::activate_with_quarantine(directory, Path::new(replacement), &serde_json::from_slice(&encoded)?,
                Path::new(&floor), !options.is_empty())?;
            println!("Replacement vault activated and prior sessions revoked.");
            return Ok(());
        }
        _ => {}
    }
    if args.len() != 3 || !matches!(args[1].as_str(), "init" | "run" | "prepare-restore") {
        return Err("Usage: voltura-vault-server init|run|prepare-restore|rotation-point DATA_DIRECTORY, or activate-rotation DATA_DIRECTORY REPLACEMENT_DATABASE ROTATION_POINT_FILE".into());
    }
    let directory = PathBuf::from(&args[2]);
    if args[1] == "prepare-restore" {
        return restore::prepare(&directory, minimum_key_epoch()?);
    }
    if args[1] == "init" {
        fs::create_dir(&directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        }
        let token =
            SecretToken::generate().map_err(|_| "Operating-system randomness unavailable")?;
        let mut db = rusqlite::Connection::open(directory.join("vault.sqlite3"))?;
        initialize(&mut db, &token, now())?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(directory.join("setup-token"))?;
        file.write_all(token.encode().as_bytes())?;
        file.sync_all()?;
        println!(
            "Vault server initialized. The setup token expires after 15 minutes. Keep it private."
        );
        return Ok(());
    }
    let unix_desktop = std::env::var("VOLTURA_ENABLE_UNIX_DESKTOP").as_deref() == Ok("1");
    let minimum_epoch = minimum_key_epoch()?;
    let database = directory.join("vault.sqlite3");
    let database_lock = maintenance_lock(&directory)?;
    database_lock.try_lock_shared().map_err(|_| "Vault key rotation is in progress")?;
    let floor = std::env::var_os("VOLTURA_KEY_EPOCH_FLOOR")
        .map(|path| rotation::read_epoch_floor(PathBuf::from(path).as_path())).transpose()?;
    let app = router_with_unix_desktop(AppState::open_with_epoch(&database, minimum_epoch, floor)?, unix_desktop);
    let port = std::env::var("VOLTURA_PORT").map_or(Ok(8787), |port| port.parse::<u16>())?;
    let address = std::env::var("VOLTURA_LISTEN")
        .as_deref()
        .unwrap_or("127.0.0.1")
        .parse::<std::net::Ipv4Addr>()?;
    let listener = tokio::net::TcpListener::bind((address, port)).await?;
    println!("Vault API listening on {}. Use the private HTTPS proxy.", listener.local_addr()?);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
