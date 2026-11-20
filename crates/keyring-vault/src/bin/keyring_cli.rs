//! Temporary CLI for Phase 2.
//!
//! This exists so the vault can be exercised before any GUI exists, and so
//! restore-from-backup can be verified without a running application. It is
//! not the product. It is deleted, or kept as a developer tool, once the
//! Tauri shell lands in Phase 3.
//!
//! WARNING: the password is read from stdin and IS echoed. That is fine for
//! a development tool on your own machine and unacceptable for anything
//! else. Phase 3 replaces this with the real unlock screen.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use keyring_vault::db;
use keyring_vault::util::time::format_unix;
use keyring_vault::{
    calibrate_kdf, KdfParams, LockReason, OpenMode, RecordFilter, RecordType, VaultSession,
};
use zeroize::Zeroizing;

const USAGE: &str = r#"keyring-cli - development tool for the Keyring vault

USAGE
  keyring-cli init      <dir> [--calibrate-ms N]
  keyring-cli info      <dir>
  keyring-cli types
  keyring-cli add       <dir> <type> <title> [field=value ...] [--folder P] [--tag T]
  keyring-cli list      <dir> [--type T] [--folder P] [--tag T] [--trash]
  keyring-cli get       <dir> <id-or-title> [--reveal]
  keyring-cli set       <dir> <id> <field=value> [field=value ...]
  keyring-cli rm        <dir> <id> [--permanent]
  keyring-cli attach    <dir> <id> <file>
  keyring-cli extract   <dir> <attachment-id> <destination>
  keyring-cli passwd    <dir>
  keyring-cli calibrate [target-ms]
  keyring-cli bench     <dir> <count>

NOTES
  A "dir" is the vault directory: it contains vault.kr, blobs/ and vault.lock.
  Prefix a field name with `secret:` to force encrypted storage.
  --reveal prints secrets to your terminal. Think before you use it.
"#;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        println!("{USAGE}");
        std::process::exit(2);
    }

    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args[0].as_str() {
        "init" => cmd_init(args),
        "info" => cmd_info(args),
        "types" => cmd_types(),
        "add" => cmd_add(args),
        "list" => cmd_list(args),
        "get" => cmd_get(args),
        "set" => cmd_set(args),
        "rm" => cmd_rm(args),
        "attach" => cmd_attach(args),
        "extract" => cmd_extract(args),
        "passwd" => cmd_passwd(args),
        "calibrate" => cmd_calibrate(args),
        "bench" => cmd_bench(args),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command '{other}'. Try `keyring-cli help`.").into()),
    }
}

// ------------------------------------------------------------- helpers

fn positional(args: &[String], index: usize) -> Option<&str> {
    args.iter()
        .filter(|a| !a.starts_with("--"))
        .nth(index)
        .map(|s| s.as_str())
}

fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let key = format!("--{name}");
    let pos = args.iter().position(|a| a == &key)?;
    args.get(pos + 1).map(|s| s.as_str())
}

fn has_flag(args: &[String], name: &str) -> bool {
    let key = format!("--{name}");
    args.iter().any(|a| a == &key)
}

fn vault_dir(args: &[String]) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(PathBuf::from(
        positional(args, 1).ok_or("missing <dir> argument")?,
    ))
}

fn prompt_password(label: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    print!("{label}: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let bytes = Zeroizing::new(line.trim_end_matches(['\r', '\n']).as_bytes().to_vec());
    Ok(bytes)
}

fn unlock(args: &[String]) -> Result<VaultSession, Box<dyn std::error::Error>> {
    let dir = vault_dir(args)?;
    let password = prompt_password("Master password")?;
    let started = Instant::now();
    let session = match VaultSession::open(&dir, &password[..], OpenMode::ReadWrite) {
        Ok(s) => s,
        Err(keyring_vault::VaultError::AlreadyOpen { pid }) => {
            eprintln!("This vault is open in process {pid}. Opening read-only.");
            VaultSession::open(&dir, &password[..], OpenMode::ReadOnly)?
        }
        Err(e) => return Err(e.into()),
    };
    eprintln!("unlocked in {} ms", started.elapsed().as_millis());
    Ok(session)
}

/// Split `field=value` pairs out of the argument list.
fn key_values(args: &[String], skip: usize) -> Vec<(String, String)> {
    args.iter()
        .skip(skip)
        .filter(|a| !a.starts_with("--"))
        .filter_map(|a| a.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect()
}

fn resolve_record(
    session: &VaultSession,
    needle: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let conn = session.conn()?;
    if db::records::get(conn, needle)?.is_some() {
        return Ok(needle.to_string());
    }
    let matches = db::records::find_by_title(conn, needle)?;
    match matches.len() {
        0 => Err(format!("no record matching '{needle}'").into()),
        1 => Ok(matches[0].id.clone()),
        n => {
            eprintln!("{n} records share that title:");
            for m in &matches {
                eprintln!("  {}  {}", m.id, m.title);
            }
            Err("be more specific, or use the id".into())
        }
    }
}

// ------------------------------------------------------------ commands

fn cmd_init(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let dir = vault_dir(args)?;
    let target_ms: u64 = flag_value(args, "calibrate-ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);

    println!("Calibrating Argon2id for a ~{target_ms} ms unlock...");
    let params = calibrate_kdf(Duration::from_millis(target_ms))?;
    println!(
        "  memory {} MiB, {} iterations, {} lanes",
        params.memory_kib / 1024,
        params.iterations,
        params.parallelism
    );

    println!();
    println!("There is NO password recovery. If you forget this password, the");
    println!("vault is gone. No reset, no backdoor, no recovery email.");
    println!();

    let password = prompt_password("New master password")?;
    let confirm = prompt_password("Confirm")?;
    if password.as_slice() != confirm.as_slice() {
        return Err("passwords do not match".into());
    }
    if keyring_vault::password_strength(std::str::from_utf8(&password[..]).unwrap_or("")) == 0 {
        return Err(format!(
            "master password must be at least {} characters",
            keyring_vault::MIN_PASSWORD_LEN
        )
        .into());
    }

    let started = Instant::now();
    let mut session = VaultSession::create(&dir, &password[..], &params, target_ms as u32)?;
    session.save()?;
    println!(
        "Created {} in {} ms.",
        session.paths().container().display(),
        started.elapsed().as_millis()
    );
    println!("Back this directory up. All of it, including blobs/.");
    Ok(())
}

fn cmd_info(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let session = unlock(args)?;
    let h = session.header();
    let conn = session.conn()?;
    println!("vault id        {}", h.vault_id);
    println!("format version  {}", h.format_version);
    println!("created         {}", format_unix(h.created_at));
    println!("modified        {}", format_unix(h.modified_at));
    println!(
        "kdf             {} m={} MiB t={} p={}",
        h.kdf.algorithm,
        h.kdf.memory_kib / 1024,
        h.kdf.iterations,
        h.kdf.parallelism
    );
    println!("mode            {:?}", session.mode());
    println!("records         {}", db::records::count(conn)?);
    let attachments: i64 = conn.query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))?;
    println!("attachments     {attachments}");
    for (folder, n) in db::tags::folders(conn)? {
        let name = if folder.is_empty() { "(no folder)" } else { &folder };
        println!("  {name:30} {n}");
    }
    Ok(())
}

fn cmd_types() -> Result<(), Box<dyn std::error::Error>> {
    for t in RecordType::ALL {
        println!("{}  ({})", t.as_str(), t.label());
        for f in t.template() {
            println!(
                "    {:16} {:10} {}",
                f.name,
                f.kind.as_str(),
                if f.secret { "encrypted" } else { "searchable" }
            );
        }
        println!();
    }
    Ok(())
}

fn cmd_add(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let type_str = positional(args, 2).ok_or("missing <type>")?.to_string();
    let title = positional(args, 3).ok_or("missing <title>")?.to_string();
    let record_type = RecordType::parse(&type_str)
        .ok_or_else(|| format!("unknown type '{type_str}'. Run `keyring-cli types`."))?;
    let folder = flag_value(args, "folder").unwrap_or("").to_string();
    let tag = flag_value(args, "tag").map(|s| s.to_string());

    // field=value pairs start after `add <dir> <type> <title>`
    let values: Vec<(String, String)> = key_values(args, 1)
        .into_iter()
        .filter(|(k, _)| k != "--folder" && k != "--tag")
        .collect();

    let mut session = unlock(args)?;
    let id = session.create_record(record_type, &title, &folder, &values)?;
    if let Some(tag) = tag {
        db::tags::add(session.conn()?, &id, &tag)?;
    }
    session.save()?;
    println!("{id}");
    Ok(())
}

fn cmd_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let session = unlock(args)?;
    let filter = RecordFilter {
        record_type: flag_value(args, "type").and_then(RecordType::parse),
        folder: flag_value(args, "folder").map(|s| s.to_string()),
        tag: flag_value(args, "tag").map(|s| s.to_string()),
        only_deleted: has_flag(args, "trash"),
        ..Default::default()
    };

    let records = db::records::list(session.conn()?, &filter)?;
    println!("{:<38} {:<22} {:<28} {}", "ID", "TYPE", "TITLE", "FOLDER");
    for r in &records {
        println!(
            "{:<38} {:<22} {:<28} {}",
            r.id,
            r.record_type.as_str(),
            truncate(&r.title, 28),
            r.folder
        );
    }
    eprintln!("\n{} record(s)", records.len());
    Ok(())
}

fn cmd_get(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let needle = positional(args, 2).ok_or("missing <id-or-title>")?.to_string();
    let reveal = has_flag(args, "reveal");
    let mut session = unlock(args)?;
    let id = resolve_record(&session, &needle)?;

    let record = db::records::require(session.conn()?, &id)?;
    println!("{}  [{}]", record.title, record.record_type.as_str());
    println!("id       {}", record.id);
    println!("folder   {}", record.folder);
    println!("created  {}", format_unix(record.created_at));
    println!("modified {}", format_unix(record.modified_at));
    let tags = db::tags::for_record(session.conn()?, &id)?;
    if !tags.is_empty() {
        println!("tags     {}", tags.join(", "));
    }
    println!();

    for field in db::fields::list_for_record(session.conn()?, &id)? {
        if field.has_secret {
            if reveal {
                let value = session.open_secret(&id, &field.name)?;
                println!(
                    "  {:16} {}",
                    field.name,
                    String::from_utf8_lossy(&value[..])
                );
            } else {
                println!("  {:16} ******** (use --reveal)", field.name);
            }
        } else {
            println!(
                "  {:16} {}",
                field.name,
                field.plain_value.as_deref().unwrap_or("")
            );
        }
    }

    let attachments = db::attachments::list_for_record(session.conn()?, &id)?;
    if !attachments.is_empty() {
        println!("\nattachments:");
        for a in attachments {
            println!("  {}  {}  {} bytes", a.id, a.filename, a.size_bytes);
        }
    }

    db::records::touch_used(session.conn()?, &id)?;
    session.touch();
    session.save_if_dirty()?;
    Ok(())
}

fn cmd_set(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let needle = positional(args, 2).ok_or("missing <id>")?.to_string();
    let pairs = key_values(args, 3);
    if pairs.is_empty() {
        return Err("nothing to set: pass at least one field=value".into());
    }
    let mut session = unlock(args)?;
    let id = resolve_record(&session, &needle)?;
    for (k, v) in &pairs {
        session.set_field(&id, k, v)?;
        println!("set {k}");
    }
    session.save()?;
    Ok(())
}

fn cmd_rm(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let needle = positional(args, 2).ok_or("missing <id>")?.to_string();
    let permanent = has_flag(args, "permanent");
    let mut session = unlock(args)?;
    let id = resolve_record(&session, &needle)?;

    if permanent {
        for a in db::attachments::list_for_record(session.conn()?, &id)? {
            db::attachments::remove(session.conn()?, session.paths(), &a.id)?;
        }
        db::records::purge(session.conn()?, &id)?;
        println!("permanently deleted {id}");
    } else {
        db::records::soft_delete(session.conn()?, &id)?;
        println!("moved {id} to trash");
    }
    session.touch();
    session.save()?;
    Ok(())
}

fn cmd_attach(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let needle = positional(args, 2).ok_or("missing <id>")?.to_string();
    let file = positional(args, 3).ok_or("missing <file>")?.to_string();
    let mut session = unlock(args)?;
    let id = resolve_record(&session, &needle)?;
    let attachment_id = session.add_attachment(&id, Path::new(&file))?;
    session.save()?;
    println!("{attachment_id}");
    Ok(())
}

fn cmd_extract(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let attachment_id = positional(args, 2).ok_or("missing <attachment-id>")?.to_string();
    let dest = positional(args, 3).ok_or("missing <destination>")?.to_string();
    let session = unlock(args)?;
    let data = session.open_attachment(&attachment_id)?;
    std::fs::write(&dest, &data[..])?;
    println!("wrote {} bytes to {dest}", data.len());
    println!("Delete it when you are done. Phase 5 does this automatically.");
    Ok(())
}

fn cmd_passwd(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = unlock(args)?;
    let current = prompt_password("Current master password")?;
    let new = prompt_password("New master password")?;
    let confirm = prompt_password("Confirm")?;
    if new.as_slice() != confirm.as_slice() {
        return Err("passwords do not match".into());
    }
    let started = Instant::now();
    session.change_master_password(&current[..], &new[..], None)?;
    println!("Password changed in {} ms.", started.elapsed().as_millis());
    println!("Every existing backup still needs the OLD password. Make a new one.");
    Ok(())
}

fn cmd_calibrate(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let target_ms: u64 = positional(args, 1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    let params: KdfParams = calibrate_kdf(Duration::from_millis(target_ms))?;
    let measured = keyring_crypto::kdf::measure(&params)?;
    println!(
        "memory {} MiB, {} iterations, {} lanes -> {} ms measured (target {target_ms} ms)",
        params.memory_kib / 1024,
        params.iterations,
        params.parallelism,
        measured.as_millis()
    );
    Ok(())
}

fn cmd_bench(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let count: usize = positional(args, 2)
        .and_then(|v| v.parse().ok())
        .ok_or("missing <count>")?;
    let mut session = unlock(args)?;

    let start = Instant::now();
    for i in 0..count {
        session.create_record(
            RecordType::SshServer,
            &format!("bench-host-{i:05}"),
            "bench",
            &[
                ("host".into(), format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256)),
                ("username".into(), "root".into()),
                ("password".into(), format!("generated-password-{i}")),
            ],
        )?;
    }
    let insert = start.elapsed();

    let save_start = Instant::now();
    session.save()?;
    let save = save_start.elapsed();

    println!("inserted {count} records in {insert:?}");
    println!("saved the container in {save:?}");
    println!("total records now {}", db::records::count(session.conn()?)?);

    let lock_start = Instant::now();
    session.lock(LockReason::Manual);
    println!("locked (keys wiped) in {:?}", lock_start.elapsed());
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
    }
}
