//! Seed document for the synthetic corpus.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Masked,
    Visible,
    Keep,
}

impl Expect {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "masked" => Ok(Self::Masked),
            "visible" => Ok(Self::Visible),
            "keep" => Ok(Self::Keep),
            other => bail!("unknown expect {other}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Item {
    pub id: String,
    pub category: String,
    pub expect: Expect,
    pub family: String,
    pub value: String,
    pub rule: Option<String>,
    pub carrier: String,
    pub locations: Vec<String>,
    pub severity: Option<String>,
    pub repro: Option<String>,
    pub fix: Option<String>,
}

#[derive(Debug, Clone)]
pub enum FileSpec {
    Text {
        path: String,
        body: String,
    },
    Png {
        path: String,
        chunks: Vec<(String, String)>,
    },
    Pdf {
        path: String,
        author: String,
        title: String,
    },
    Zip {
        path: String,
        comment: String,
        entry_name: String,
        entry_text: String,
    },
}

impl FileSpec {
    pub fn path(&self) -> &str {
        match self {
            Self::Text { path, .. }
            | Self::Png { path, .. }
            | Self::Pdf { path, .. }
            | Self::Zip { path, .. } => path,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Seed {
    pub about: String,
    pub restore_text: String,
    pub restore_tool: String,
    pub items: Vec<Item>,
    pub files: Vec<FileSpec>,
}

impl Seed {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let value: Value = serde_json::from_str(&text).context("parse seed")?;
        let about = req_str(&value, "about")?.to_string();
        let restore = value.get("restore").context("restore")?;
        let restore_text = req_str(restore, "text")?.to_string();
        let restore_tool = req_str(restore, "tool")?.to_string();
        let items = value
            .get("items")
            .and_then(Value::as_array)
            .context("items")?
            .iter()
            .map(parse_item)
            .collect::<Result<Vec<_>>>()?;
        let files = value
            .get("files")
            .and_then(Value::as_array)
            .context("files")?
            .iter()
            .map(parse_file)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            about,
            restore_text,
            restore_tool,
            items,
            files,
        })
    }

    pub fn item(&self, id: &str) -> Result<&Item> {
        self.items
            .iter()
            .find(|item| item.id == id)
            .with_context(|| format!("missing item {id}"))
    }
}

fn parse_item(value: &Value) -> Result<Item> {
    let id = req_str(value, "id")?.to_string();
    let locations = string_list(value, "locations")?;
    Ok(Item {
        id,
        category: req_str(value, "category")?.to_string(),
        expect: Expect::parse(req_str(value, "expect")?)?,
        family: req_str(value, "family")?.to_string(),
        value: req_str(value, "value")?.to_string(),
        rule: opt_str(value, "rule")?,
        carrier: req_str(value, "carrier")?.to_string(),
        locations,
        severity: opt_str(value, "severity")?,
        repro: opt_str(value, "repro")?,
        fix: opt_str(value, "fix")?,
    })
}

fn parse_file(value: &Value) -> Result<FileSpec> {
    let path = req_str(value, "path")?.to_string();
    match req_str(value, "kind")? {
        "text" => Ok(FileSpec::Text {
            path,
            body: req_str(value, "body")?.to_string(),
        }),
        "png" => {
            let chunks = value
                .get("chunks")
                .and_then(Value::as_array)
                .context("png chunks")?
                .iter()
                .map(|chunk| {
                    Ok((
                        req_str(chunk, "keyword")?.to_string(),
                        req_str(chunk, "text")?.to_string(),
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(FileSpec::Png { path, chunks })
        }
        "pdf" => Ok(FileSpec::Pdf {
            path,
            author: req_str(value, "author")?.to_string(),
            title: req_str(value, "title")?.to_string(),
        }),
        "zip" => Ok(FileSpec::Zip {
            path,
            comment: req_str(value, "comment")?.to_string(),
            entry_name: req_str(value, "entry_name")?.to_string(),
            entry_text: req_str(value, "entry_text")?.to_string(),
        }),
        other => bail!("unknown file kind {other}"),
    }
}

fn req_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string {key}"))
}

fn opt_str(value: &Value, key: &str) -> Result<Option<String>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => bail!("{key} is not a string"),
    }
}

fn string_list(value: &Value, key: &str) -> Result<Vec<String>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .with_context(|| format!("missing array {key}"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_string)
                .with_context(|| format!("{key} entry is not a string"))
        })
        .collect()
}
