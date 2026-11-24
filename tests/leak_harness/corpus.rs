//! Deterministic synthetic tree. The same seed bytes always produce the same files.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::model::{FileSpec, Seed};

pub fn generate(seed: &Seed, root: &Path) -> Result<()> {
    if root.exists() {
        fs::remove_dir_all(root).with_context(|| format!("reset {}", root.display()))?;
    }
    fs::create_dir_all(root)?;
    for spec in &seed.files {
        let path = root.join(spec.path());
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = render(spec)?;
        fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;
    }
    for item in &seed.items {
        for location in &item.locations {
            if let Some(name) = location.strip_prefix("session:") {
                match name {
                    "json-key" | "json-number" => {}
                    other => bail!("unknown session probe {other}"),
                }
                continue;
            }
            let bytes = fs::read(root.join(location))
                .with_context(|| format!("read {location} for {}", item.id))?;
            let needle = item.value.as_bytes();
            if !bytes.windows(needle.len()).any(|window| window == needle) {
                bail!("{} value is not in {location}", item.id);
            }
        }
    }
    Ok(())
}

pub fn snapshot(root: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    out.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, fs::read(&path)?));
        }
    }
    Ok(())
}

pub fn transcript(root: &Path) -> Result<String> {
    let files = snapshot(root)?;
    let mut out = String::new();
    for (path, bytes) in files {
        out.push_str("===== ");
        out.push_str(&path);
        out.push_str(" =====\n");
        out.push_str(&String::from_utf8_lossy(&bytes));
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
    Ok(out)
}

fn render(spec: &FileSpec) -> Result<Vec<u8>> {
    match spec {
        FileSpec::Text { body, .. } => Ok(body.as_bytes().to_vec()),
        FileSpec::Png { chunks, .. } => Ok(png(chunks)),
        FileSpec::Pdf { author, title, .. } => Ok(pdf(author, title)),
        FileSpec::Zip {
            comment,
            entry_name,
            entry_text,
            ..
        } => Ok(zip(entry_name, entry_text.as_bytes(), comment)),
    }
}

fn png(chunks: &[(String, String)]) -> Vec<u8> {
    let mut ihdr = Vec::new();
    ihdr.extend(1u32.to_be_bytes());
    ihdr.extend(1u32.to_be_bytes());
    ihdr.extend([8, 2, 0, 0, 0]);
    let scanline = [0, 0, 0, 0];
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    out.extend(chunk(b"IHDR", &ihdr));
    for (keyword, text) in chunks {
        let mut data = keyword.as_bytes().to_vec();
        data.push(0);
        data.extend(text.as_bytes());
        out.extend(chunk(b"tEXt", &data));
    }
    out.extend(chunk(b"IDAT", &zlib_store(&scanline)));
    out.extend(chunk(b"IEND", &[]));
    out
}

fn chunk(tag: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + data.len());
    body.extend(tag);
    body.extend(data);
    let crc = crc32(&body);
    let mut out = Vec::new();
    out.extend((data.len() as u32).to_be_bytes());
    out.extend(body);
    out.extend(crc.to_be_bytes());
    out
}

fn zlib_store(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01, 0x01];
    let len = u16::try_from(data.len()).expect("stored block");
    out.extend(len.to_le_bytes());
    out.extend((!len).to_le_bytes());
    out.extend(data);
    out.extend(adler32(data).to_be_bytes());
    out
}

fn adler32(data: &[u8]) -> u32 {
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn pdf(author: &str, title: &str) -> Vec<u8> {
    let content = "BT /F1 12 Tf 72 72 Td (FAKE Tundrahorn note) Tj ET";
    let objects = [
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n".to_string(),
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n".to_string(),
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>\nendobj\n".to_string(),
        format!(
            "4 0 obj\n<< /Length {} >>\nstream\n{content}\nendstream\nendobj\n",
            content.len()
        ),
        format!("5 0 obj\n<< /Title ({title}) /Author ({author}) >>\nendobj\n"),
    ];
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for object in &objects {
        offsets.push(out.len());
        out.extend(object.as_bytes());
    }
    let xref_at = out.len();
    let mut xref = format!("xref\n0 {}\n", objects.len() + 1);
    xref.push_str("0000000000 65535 f \n");
    for offset in offsets {
        xref.push_str(&format!("{offset:010} 00000 n \n"));
    }
    let trailer = format!(
        "trailer\n<< /Size {} /Root 1 0 R /Info 5 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
        objects.len() + 1
    );
    out.extend(xref.as_bytes());
    out.extend(trailer.as_bytes());
    out
}

fn zip(name: &str, data: &[u8], comment: &str) -> Vec<u8> {
    let crc = crc32(data);
    let name_b = name.as_bytes();
    let comment_b = comment.as_bytes();
    let mut local = Vec::new();
    push_u32(&mut local, 0x0403_4b50);
    push_u16(&mut local, 20);
    push_u16(&mut local, 0);
    push_u16(&mut local, 0);
    push_u16(&mut local, 0);
    push_u16(&mut local, 0);
    push_u32(&mut local, crc);
    push_u32(&mut local, data.len() as u32);
    push_u32(&mut local, data.len() as u32);
    push_u16(&mut local, name_b.len() as u16);
    push_u16(&mut local, 0);
    local.extend(name_b);
    local.extend(data);

    let mut central = Vec::new();
    push_u32(&mut central, 0x0201_4b50);
    push_u16(&mut central, 20);
    push_u16(&mut central, 20);
    push_u16(&mut central, 0);
    push_u16(&mut central, 0);
    push_u16(&mut central, 0);
    push_u16(&mut central, 0);
    push_u32(&mut central, crc);
    push_u32(&mut central, data.len() as u32);
    push_u32(&mut central, data.len() as u32);
    push_u16(&mut central, name_b.len() as u16);
    push_u16(&mut central, 0);
    push_u16(&mut central, 0);
    push_u16(&mut central, 0);
    push_u16(&mut central, 0);
    push_u32(&mut central, 0);
    push_u32(&mut central, 0);
    central.extend(name_b);

    let mut eocd = Vec::new();
    push_u32(&mut eocd, 0x0605_4b50);
    push_u16(&mut eocd, 0);
    push_u16(&mut eocd, 0);
    push_u16(&mut eocd, 1);
    push_u16(&mut eocd, 1);
    push_u32(&mut eocd, central.len() as u32);
    push_u32(&mut eocd, local.len() as u32);
    push_u16(&mut eocd, comment_b.len() as u16);
    eocd.extend(comment_b);

    local.extend(central);
    local.extend(eocd);
    local
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend(value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend(value.to_le_bytes());
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = if crc & 1 == 1 { 0xEDB8_8320 } else { 0 };
            crc = (crc >> 1) ^ mask;
        }
    }
    !crc
}
