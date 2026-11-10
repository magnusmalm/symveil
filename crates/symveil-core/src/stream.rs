//! Streaming restore.
//!
//! A placeholder is the fixed ASCII token `@@sv:` + 8 hex digits + `@@` (15 bytes).
//! Chunk boundaries can land inside that token, or inside a UTF-8 scalar that sits
//! next to it. `ByteRestorer` holds back an incomplete UTF-8 tail and any suffix
//! that is still a legal prefix of a placeholder, then emits the restored prefix.
//!
//! Tool-call and text streams also split one placeholder across two JSON strings
//! (separate SSE deltas). The bytes between those strings are framing, not the rest
//! of the token, so a flat byte scan leaves the fragments unrestored. `SseRestorer`
//! keeps a carry per logical stream — one tool call, or one text block — and flushes
//! a trailing partial token when that block ends.

use std::collections::HashMap;

use serde_json::Value;

use crate::vault::TOKEN_LEN;

pub struct StreamRestorer {
    carry: String,
    map: HashMap<String, String>,
    json_escape: bool,
    restored: usize,
}

impl StreamRestorer {
    pub fn new(map: HashMap<String, String>, json_escape: bool) -> Self {
        Self {
            carry: String::new(),
            map,
            json_escape,
            restored: 0,
        }
    }

    pub fn push(&mut self, chunk: &str) -> String {
        if chunk.is_empty() {
            return String::new();
        }
        if self.carry.is_empty() && !chunk.contains('@') {
            return chunk.to_string();
        }
        let mut data = String::with_capacity(self.carry.len() + chunk.len());
        data.push_str(&self.carry);
        data.push_str(chunk);
        let (emit, hold, restored) = restore_with_hold(&data, &self.map, self.json_escape);
        self.restored += restored;
        self.carry = hold;
        emit
    }

    pub fn finish(&mut self) -> String {
        std::mem::take(&mut self.carry)
    }

    pub fn restored(&self) -> usize {
        self.restored
    }
}

pub struct ByteRestorer {
    pending: Vec<u8>,
    inner: StreamRestorer,
}

impl ByteRestorer {
    pub fn new(map: HashMap<String, String>, json_escape: bool) -> Self {
        Self {
            pending: Vec::new(),
            inner: StreamRestorer::new(map, json_escape),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> String {
        if chunk.is_empty() {
            return String::new();
        }
        if self.pending.is_empty() && !chunk.contains(&b'@') {
            if let Ok(text) = std::str::from_utf8(chunk) {
                return self.inner.push(text);
            }
        }
        self.pending.extend_from_slice(chunk);
        let decoded = drain_valid_utf8(&mut self.pending);
        self.inner.push(&decoded)
    }

    pub fn finish(&mut self) -> String {
        let pending = std::mem::take(&mut self.pending);
        let mut out = String::new();
        if !pending.is_empty() {
            let lossy = String::from_utf8_lossy(&pending);
            out.push_str(&self.inner.push(&lossy));
        }
        out.push_str(&self.inner.finish());
        out
    }

    pub fn restored(&self) -> usize {
        self.inner.restored()
    }
}

pub fn restore_all(
    bytes: &[u8],
    map: &HashMap<String, String>,
    json_escape: bool,
) -> (Vec<u8>, usize) {
    let mut restorer = ByteRestorer::new(map.clone(), json_escape);
    let mut out = restorer.push(bytes);
    out.push_str(&restorer.finish());
    let restored = restorer.restored();
    (out.into_bytes(), restored)
}

pub fn placeholder_ranges(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i + TOKEN_LEN <= bytes.len() {
        if token_key_at(text, i).is_some() {
            ranges.push((i, i + TOKEN_LEN));
            i += TOKEN_LEN;
            continue;
        }
        i += 1;
    }
    ranges
}

pub fn json_escape(value: &str) -> String {
    match serde_json::to_string(value) {
        Ok(quoted) if quoted.len() >= 2 => quoted[1..quoted.len() - 1].to_string(),
        _ => value.to_string(),
    }
}

fn restore_with_hold(
    input: &str,
    map: &HashMap<String, String>,
    json_escape_replacements: bool,
) -> (String, String, usize) {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut restored = 0;
    while i < bytes.len() {
        if bytes[i] != b'@' {
            match input[i..].find('@') {
                Some(rel) => {
                    out.push_str(&input[i..i + rel]);
                    i += rel;
                }
                None => {
                    out.push_str(&input[i..]);
                    break;
                }
            }
            continue;
        }
        if let Some(key) = token_key_at(input, i) {
            let raw = &input[i..i + TOKEN_LEN];
            if let Some(original) = map.get(&key) {
                if json_escape_replacements {
                    out.push_str(&json_escape(original));
                } else {
                    out.push_str(original);
                }
                restored += 1;
            } else {
                out.push_str(raw);
            }
            i += TOKEN_LEN;
            continue;
        }
        if is_incomplete_prefix(&input[i..]) {
            return (out, input[i..].to_string(), restored);
        }
        out.push('@');
        i += 1;
    }
    (out, String::new(), restored)
}

fn token_key_at(input: &str, i: usize) -> Option<String> {
    let bytes = input.as_bytes();
    if i + TOKEN_LEN > bytes.len() {
        return None;
    }
    if &bytes[i..i + 5] != b"@@sv:" || &bytes[i + 13..i + 15] != b"@@" {
        return None;
    }
    if !bytes[i + 5..i + 13].iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut hex = [0u8; 8];
    hex.copy_from_slice(&bytes[i + 5..i + 13]);
    for byte in &mut hex {
        *byte = byte.to_ascii_lowercase();
    }
    let hex = std::str::from_utf8(&hex).ok()?;
    Some(format!("@@sv:{hex}@@"))
}

fn is_incomplete_prefix(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() >= TOKEN_LEN {
        return false;
    }
    let head = b"@@sv:";
    if bytes.len() <= head.len() {
        return head.starts_with(bytes);
    }
    if &bytes[..5] != b"@@sv:" {
        return false;
    }
    let rest = &bytes[5..];
    if rest.len() <= 8 {
        return rest.iter().all(|byte| byte.is_ascii_hexdigit());
    }
    rest.len() == 9 && rest[..8].iter().all(|byte| byte.is_ascii_hexdigit()) && rest[8] == b'@'
}

fn drain_valid_utf8(pending: &mut Vec<u8>) -> String {
    let mut decoded = String::new();
    loop {
        if pending.is_empty() {
            break;
        }
        match std::str::from_utf8(pending) {
            Ok(text) => {
                decoded.push_str(text);
                pending.clear();
                break;
            }
            Err(err) => {
                let valid = err.valid_up_to();
                if valid > 0 {
                    if let Ok(text) = std::str::from_utf8(&pending[..valid]) {
                        decoded.push_str(text);
                    }
                    pending.drain(..valid);
                }
                match err.error_len() {
                    None => break,
                    Some(0) => break,
                    Some(len) => {
                        decoded.push('\u{FFFD}');
                        let drop_n = len.min(pending.len());
                        if drop_n == 0 {
                            break;
                        }
                        pending.drain(..drop_n);
                    }
                }
            }
        }
    }
    decoded
}

/// Restores placeholders in a server-sent event stream.
///
/// HTTP chunks and SSE events are buffered until a full event is available.
/// Argument and text deltas are restored per logical stream, so a placeholder
/// split across two deltas of the same tool call (or the same text block) comes
/// back as the original value. A non-SSE body falls back to [`ByteRestorer`].
pub struct SseRestorer {
    map: HashMap<String, String>,
    json_escape: bool,
    buffer: Vec<u8>,
    mode: Mode,
    lanes: HashMap<StreamId, Lane>,
    extra_restored: usize,
    raw: Option<ByteRestorer>,
}

struct Lane {
    restorer: StreamRestorer,
    sse_event: Option<String>,
    item_id: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Detect,
    Sse,
    Raw,
}

enum Probe {
    NeedMore,
    Sse,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum StreamId {
    ChatContent {
        choice: u64,
    },
    ChatRefusal {
        choice: u64,
    },
    ChatReasoning {
        choice: u64,
    },
    ChatToolArgs {
        choice: u64,
        tool: u64,
    },
    ChatToolName {
        choice: u64,
        tool: u64,
    },
    Response {
        kind: String,
        output: u64,
        content: u64,
    },
    Anthropic {
        index: u64,
        field: AnthropicField,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum AnthropicField {
    Text,
    PartialJson,
    Thinking,
}

struct ParsedEvent {
    event_name: Option<String>,
    others: Vec<String>,
    data: String,
}

impl SseRestorer {
    pub fn new(map: HashMap<String, String>, json_escape: bool) -> Self {
        Self {
            map,
            json_escape,
            buffer: Vec::new(),
            mode: Mode::Detect,
            lanes: HashMap::new(),
            extra_restored: 0,
            raw: None,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> String {
        if matches!(self.mode, Mode::Raw) {
            return self.raw_mut().push(chunk);
        }
        if chunk.is_empty() {
            return String::new();
        }
        self.buffer.extend_from_slice(chunk);
        if matches!(self.mode, Mode::Detect) {
            match probe(&self.buffer) {
                Probe::NeedMore => return String::new(),
                Probe::Raw => {
                    self.mode = Mode::Raw;
                    let buffered = std::mem::take(&mut self.buffer);
                    return self.raw_mut().push(&buffered);
                }
                Probe::Sse => self.mode = Mode::Sse,
            }
        }
        self.drain_events()
    }

    pub fn finish(&mut self) -> String {
        match self.mode {
            Mode::Raw => self.raw_mut().finish(),
            Mode::Detect => {
                let buffered = std::mem::take(&mut self.buffer);
                self.mode = Mode::Raw;
                let mut out = self.raw_mut().push(&buffered);
                out.push_str(&self.raw_mut().finish());
                out
            }
            Mode::Sse => {
                let mut out = String::new();
                let rest = std::mem::take(&mut self.buffer);
                if !rest.is_empty() {
                    let text = String::from_utf8_lossy(&rest);
                    out.push_str(&self.rewrite_event(&text));
                }
                out.push_str(&self.flush_all());
                out
            }
        }
    }

    pub fn restored(&self) -> usize {
        let lanes = self
            .lanes
            .values()
            .map(|lane| lane.restorer.restored())
            .sum::<usize>();
        let raw = self.raw.as_ref().map(ByteRestorer::restored).unwrap_or(0);
        self.extra_restored + lanes + raw
    }

    fn raw_mut(&mut self) -> &mut ByteRestorer {
        if self.raw.is_none() {
            self.raw = Some(ByteRestorer::new(self.map.clone(), self.json_escape));
        }
        self.raw.as_mut().expect("raw restorer")
    }

    fn drain_events(&mut self) -> String {
        let mut out = String::new();
        while let Some((end, sep)) = find_event_sep(&self.buffer) {
            let event: Vec<u8> = self.buffer.drain(..end).collect();
            self.buffer.drain(..sep);
            let text = String::from_utf8_lossy(&event);
            out.push_str(&self.rewrite_event(&text));
        }
        out
    }

    fn rewrite_event(&mut self, event: &str) -> String {
        let parsed = parse_event(event);
        if parsed.data.trim() == "[DONE]" {
            let flushed = self.flush_all();
            return flushed + &render_event(&parsed, "[DONE]");
        }
        if parsed.data.is_empty() {
            return render_raw_event(event);
        }
        let Ok(mut value) = serde_json::from_str::<Value>(&parsed.data) else {
            let (text, count) = restore_in_string(&parsed.data, &self.map, self.json_escape);
            self.extra_restored += count;
            return render_event(&parsed, &text);
        };
        let prefixes = self.restore_value(&mut value, parsed.event_name.as_deref());
        match serde_json::to_string(&value) {
            Ok(data) => prefixes + &render_event(&parsed, &data),
            Err(_) => prefixes + &render_event(&parsed, &parsed.data),
        }
    }

    fn restore_value(&mut self, value: &mut Value, sse_event: Option<&str>) -> String {
        let prefixes = if value.get("choices").is_some() {
            self.restore_chat(value, sse_event)
        } else if let Some(kind) = value
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_string)
        {
            self.restore_typed(value, &kind, sse_event)
        } else {
            String::new()
        };
        self.extra_restored += restore_tree(value, &self.map);
        prefixes
    }

    fn restore_typed(&mut self, value: &mut Value, kind: &str, sse_event: Option<&str>) -> String {
        if kind == "content_block_delta" {
            self.restore_anthropic_delta(value, sse_event);
            return String::new();
        }
        if kind == "content_block_stop" {
            let index = json_u64(value, "index").unwrap_or(0);
            return self.flush_anthropic(index);
        }
        if kind == "message_stop" {
            return self.flush_where(|id| matches!(id, StreamId::Anthropic { .. }));
        }
        if is_response_delta(kind) {
            self.restore_response_delta(value, kind, sse_event);
            return String::new();
        }
        if kind == "response.output_item.done" {
            let output = json_u64(value, "output_index").unwrap_or(0);
            return self.flush_response_output(output);
        }
        if kind == "response.content_part.done" {
            let output = json_u64(value, "output_index").unwrap_or(0);
            let content = json_u64(value, "content_index");
            return self.flush_response_output_content(output, content);
        }
        if let Some(stem) = kind.strip_suffix(".done") {
            let delta_kind = format!("{stem}.delta");
            let output = json_u64(value, "output_index").unwrap_or(0);
            let content = json_u64(value, "content_index");
            return self.flush_response_kind(&delta_kind, output, content);
        }
        if matches!(
            kind,
            "response.completed" | "response.failed" | "response.incomplete"
        ) {
            return self.flush_where(|id| matches!(id, StreamId::Response { .. }));
        }
        String::new()
    }

    fn restore_chat(&mut self, value: &mut Value, sse_event: Option<&str>) -> String {
        let mut finishing = Vec::new();
        if let Some(choices) = value.get_mut("choices").and_then(Value::as_array_mut) {
            for choice in choices {
                let index = json_u64(choice, "index").unwrap_or(0);
                let closes = choice
                    .get("finish_reason")
                    .is_some_and(|reason| !reason.is_null());
                if let Some(delta) = choice.get_mut("delta") {
                    self.restore_chat_delta(delta, index, closes, sse_event);
                }
                if closes {
                    finishing.push(index);
                }
            }
        }
        let mut out = String::new();
        for index in finishing {
            out.push_str(&self.flush_chat(index));
        }
        out
    }

    fn restore_chat_delta(
        &mut self,
        delta: &mut Value,
        choice: u64,
        closing: bool,
        sse_event: Option<&str>,
    ) {
        for (field, id) in [
            ("content", StreamId::ChatContent { choice }),
            ("refusal", StreamId::ChatRefusal { choice }),
            ("reasoning_content", StreamId::ChatReasoning { choice }),
        ] {
            if let Some(fragment) = take_string(delta, field) {
                let emit = self.push_lane(id, &fragment, sse_event, None, closing);
                set_string(delta, field, emit);
            }
        }
        let Some(calls) = delta.get_mut("tool_calls").and_then(Value::as_array_mut) else {
            return;
        };
        for (position, call) in calls.iter_mut().enumerate() {
            let tool = json_u64(call, "index").unwrap_or(position as u64);
            let Some(function) = call.get_mut("function") else {
                continue;
            };
            if let Some(fragment) = take_string(function, "arguments") {
                let emit = self.push_lane(
                    StreamId::ChatToolArgs { choice, tool },
                    &fragment,
                    sse_event,
                    None,
                    closing,
                );
                set_string(function, "arguments", emit);
            }
            if let Some(fragment) = take_string(function, "name") {
                let emit = self.push_lane(
                    StreamId::ChatToolName { choice, tool },
                    &fragment,
                    sse_event,
                    None,
                    closing,
                );
                set_string(function, "name", emit);
            }
        }
    }

    fn restore_anthropic_delta(&mut self, value: &mut Value, sse_event: Option<&str>) {
        let index = json_u64(value, "index").unwrap_or(0);
        let Some(delta) = value.get_mut("delta") else {
            return;
        };
        let kind = delta
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let (field_name, field) = match kind.as_str() {
            "text_delta" => ("text", AnthropicField::Text),
            "input_json_delta" => ("partial_json", AnthropicField::PartialJson),
            "thinking_delta" => ("thinking", AnthropicField::Thinking),
            _ => return,
        };
        if let Some(fragment) = take_string(delta, field_name) {
            let emit = self.push_lane(
                StreamId::Anthropic { index, field },
                &fragment,
                sse_event,
                None,
                false,
            );
            set_string(delta, field_name, emit);
        }
    }

    fn restore_response_delta(&mut self, value: &mut Value, kind: &str, sse_event: Option<&str>) {
        let output = json_u64(value, "output_index").unwrap_or(0);
        let content = json_u64(value, "content_index").unwrap_or(0);
        let item_id = value
            .get("item_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(fragment) = take_string(value, "delta") {
            let emit = self.push_lane(
                StreamId::Response {
                    kind: kind.to_string(),
                    output,
                    content,
                },
                &fragment,
                sse_event,
                item_id,
                false,
            );
            set_string(value, "delta", emit);
        }
    }

    fn push_lane(
        &mut self,
        id: StreamId,
        fragment: &str,
        sse_event: Option<&str>,
        item_id: Option<String>,
        closing: bool,
    ) -> String {
        if !self.lanes.contains_key(&id) {
            let escape = lane_escapes(&id);
            self.lanes.insert(
                id.clone(),
                Lane {
                    restorer: StreamRestorer::new(self.map.clone(), escape),
                    sse_event: None,
                    item_id: None,
                },
            );
        }
        let Some(lane) = self.lanes.get_mut(&id) else {
            return fragment.to_string();
        };
        if let Some(name) = sse_event {
            lane.sse_event = Some(name.to_string());
        }
        if item_id.is_some() {
            lane.item_id = item_id;
        }
        let mut emit = lane.restorer.push(fragment);
        if closing {
            emit.push_str(&lane.restorer.finish());
        }
        emit
    }

    fn flush_chat(&mut self, choice: u64) -> String {
        self.flush_where(|id| match id {
            StreamId::ChatContent { choice: found }
            | StreamId::ChatRefusal { choice: found }
            | StreamId::ChatReasoning { choice: found }
            | StreamId::ChatToolArgs { choice: found, .. }
            | StreamId::ChatToolName { choice: found, .. } => *found == choice,
            StreamId::Response { .. } | StreamId::Anthropic { .. } => false,
        })
    }

    fn flush_anthropic(&mut self, index: u64) -> String {
        self.flush_where(
            |id| matches!(id, StreamId::Anthropic { index: found, .. } if *found == index),
        )
    }

    fn flush_response_output(&mut self, output: u64) -> String {
        self.flush_where(
            |id| matches!(id, StreamId::Response { output: found, .. } if *found == output),
        )
    }

    fn flush_response_output_content(&mut self, output: u64, content: Option<u64>) -> String {
        self.flush_where(|id| match id {
            StreamId::Response {
                output: found_output,
                content: found_content,
                ..
            } => *found_output == output && content.is_none_or(|want| *found_content == want),
            _ => false,
        })
    }

    fn flush_response_kind(&mut self, kind: &str, output: u64, content: Option<u64>) -> String {
        self.flush_where(|id| match id {
            StreamId::Response {
                kind: found_kind,
                output: found_output,
                content: found_content,
            } => {
                found_kind == kind
                    && *found_output == output
                    && content.is_none_or(|want| *found_content == want)
            }
            _ => false,
        })
    }

    fn flush_all(&mut self) -> String {
        self.flush_where(|_| true)
    }

    fn flush_where(&mut self, mut pred: impl FnMut(&StreamId) -> bool) -> String {
        let mut keys: Vec<StreamId> = self.lanes.keys().filter(|id| pred(id)).cloned().collect();
        keys.sort();
        let mut out = String::new();
        for key in keys {
            let Some(lane) = self.lanes.get_mut(&key) else {
                continue;
            };
            let tail = lane.restorer.finish();
            if tail.is_empty() {
                continue;
            }
            out.push_str(&continuation_frame(
                &key,
                &tail,
                lane.sse_event.as_deref(),
                lane.item_id.as_deref(),
            ));
        }
        out
    }
}

fn lane_escapes(id: &StreamId) -> bool {
    match id {
        StreamId::ChatToolArgs { .. } => true,
        StreamId::ChatContent { .. }
        | StreamId::ChatRefusal { .. }
        | StreamId::ChatReasoning { .. }
        | StreamId::ChatToolName { .. } => false,
        StreamId::Anthropic { field, .. } => matches!(field, AnthropicField::PartialJson),
        StreamId::Response { kind, .. } => kind.contains("arguments"),
    }
}

fn is_response_delta(kind: &str) -> bool {
    kind.starts_with("response.") && kind.ends_with(".delta")
}

fn continuation_frame(
    id: &StreamId,
    tail: &str,
    sse_event: Option<&str>,
    item_id: Option<&str>,
) -> String {
    let (event_name, value) = match id {
        StreamId::ChatContent { choice } => (
            sse_event.map(str::to_string),
            serde_json::json!({
                "choices": [{"index": choice, "delta": {"content": tail}}]
            }),
        ),
        StreamId::ChatRefusal { choice } => (
            sse_event.map(str::to_string),
            serde_json::json!({
                "choices": [{"index": choice, "delta": {"refusal": tail}}]
            }),
        ),
        StreamId::ChatReasoning { choice } => (
            sse_event.map(str::to_string),
            serde_json::json!({
                "choices": [{"index": choice, "delta": {"reasoning_content": tail}}]
            }),
        ),
        StreamId::ChatToolArgs { choice, tool } => (
            sse_event.map(str::to_string),
            serde_json::json!({
                "choices": [{
                    "index": choice,
                    "delta": {"tool_calls": [{"index": tool, "function": {"arguments": tail}}]}
                }]
            }),
        ),
        StreamId::ChatToolName { choice, tool } => (
            sse_event.map(str::to_string),
            serde_json::json!({
                "choices": [{
                    "index": choice,
                    "delta": {"tool_calls": [{"index": tool, "function": {"name": tail}}]}
                }]
            }),
        ),
        StreamId::Response {
            kind,
            output,
            content,
        } => {
            let mut fields = serde_json::Map::new();
            fields.insert("type".to_string(), Value::String(kind.clone()));
            fields.insert("output_index".to_string(), serde_json::json!(output));
            if !kind.contains("arguments") {
                fields.insert("content_index".to_string(), serde_json::json!(content));
            }
            if let Some(item_id) = item_id {
                fields.insert("item_id".to_string(), Value::String(item_id.to_string()));
            }
            fields.insert("delta".to_string(), Value::String(tail.to_string()));
            (sse_event.map(str::to_string), Value::Object(fields))
        }
        StreamId::Anthropic { index, field } => {
            let delta = match field {
                AnthropicField::Text => serde_json::json!({"type": "text_delta", "text": tail}),
                AnthropicField::PartialJson => {
                    serde_json::json!({"type": "input_json_delta", "partial_json": tail})
                }
                AnthropicField::Thinking => {
                    serde_json::json!({"type": "thinking_delta", "thinking": tail})
                }
            };
            (
                Some(sse_event.unwrap_or("content_block_delta").to_string()),
                serde_json::json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": delta
                }),
            )
        }
    };
    let data = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    let parsed = ParsedEvent {
        event_name,
        others: Vec::new(),
        data,
    };
    render_event(&parsed, &parsed.data)
}

fn restore_tree(value: &mut Value, map: &HashMap<String, String>) -> usize {
    match value {
        Value::String(_) => 0,
        Value::Array(items) => items.iter_mut().map(|item| restore_tree(item, map)).sum(),
        Value::Object(fields) => {
            let mut count = 0;
            for (key, child) in fields.iter_mut() {
                if let Value::String(text) = child {
                    let escape = key == "arguments" || key == "partial_json";
                    let (restored, found) = restore_in_string(text, map, escape);
                    count += found;
                    if restored != *text {
                        *text = restored;
                    }
                } else {
                    count += restore_tree(child, map);
                }
            }
            count
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
    }
}

fn restore_in_string(
    text: &str,
    map: &HashMap<String, String>,
    json_escape_replacements: bool,
) -> (String, usize) {
    let (mut emit, hold, count) = restore_with_hold(text, map, json_escape_replacements);
    emit.push_str(&hold);
    (emit, count)
}

fn take_string(value: &mut Value, field: &str) -> Option<String> {
    let slot = value.get_mut(field)?;
    match slot {
        Value::String(text) => Some(std::mem::take(text)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
            None
        }
    }
}

fn set_string(value: &mut Value, field: &str, text: String) {
    if let Some(slot) = value.get_mut(field) {
        *slot = Value::String(text);
    }
}

fn json_u64(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

fn probe(buf: &[u8]) -> Probe {
    let trimmed = trim_ascii_start(buf);
    if trimmed.is_empty() {
        return Probe::NeedMore;
    }
    if trimmed.starts_with(b"data:") || trimmed.starts_with(b"event:") || trimmed.starts_with(b":")
    {
        return Probe::Sse;
    }
    if b"data:".starts_with(trimmed) || b"event:".starts_with(trimmed) {
        return Probe::NeedMore;
    }
    Probe::Raw
}

fn trim_ascii_start(buf: &[u8]) -> &[u8] {
    let mut index = 0;
    while index < buf.len() && matches!(buf[index], b' ' | b'\t' | b'\r' | b'\n') {
        index += 1;
    }
    &buf[index..]
}

fn find_event_sep(buf: &[u8]) -> Option<(usize, usize)> {
    let mut index = 0;
    while index < buf.len() {
        if buf[index] == b'\n' && index + 1 < buf.len() && buf[index + 1] == b'\n' {
            return Some((index, 2));
        }
        if buf[index] == b'\r'
            && index + 3 < buf.len()
            && buf[index + 1] == b'\n'
            && buf[index + 2] == b'\r'
            && buf[index + 3] == b'\n'
        {
            return Some((index, 4));
        }
        index += 1;
    }
    None
}

fn parse_event(event: &str) -> ParsedEvent {
    let mut event_name = None;
    let mut others = Vec::new();
    let mut data_lines = Vec::new();
    for line in event.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            let rest = rest.strip_prefix(' ').unwrap_or(rest);
            data_lines.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("event:") {
            event_name = Some(rest.trim_start().to_string());
        } else {
            others.push(line.to_string());
        }
    }
    ParsedEvent {
        event_name,
        others,
        data: data_lines.join("\n"),
    }
}

fn render_event(parsed: &ParsedEvent, data: &str) -> String {
    let mut out = String::new();
    if let Some(name) = &parsed.event_name {
        out.push_str("event: ");
        out.push_str(name);
        out.push('\n');
    }
    for line in &parsed.others {
        out.push_str(line);
        out.push('\n');
    }
    if data.is_empty() {
        out.push('\n');
        return out;
    }
    for line in data.split('\n') {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    out
}

fn render_raw_event(event: &str) -> String {
    let mut out = event.trim_end_matches(['\r', '\n']).to_string();
    if out.is_empty() {
        return String::new();
    }
    out.push_str("\n\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::vault::Vault;

    fn sample() -> (HashMap<String, String>, String, String) {
        let mut vault = Vault::ephemeral();
        let function = vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        let secret = vault
            .assign(
                "AKIAIOSFODNN7EXAMPLE",
                Category::Secret,
                Some("aws-access-key-id".into()),
            )
            .unwrap();
        let text = format!("alpha {function} see @@ notes {secret} omega é @");
        let expected =
            "alpha aurora_rcc_enable_pll see @@ notes AKIAIOSFODNN7EXAMPLE omega é @".to_string();
        (vault.restore_map(), text, expected)
    }

    #[test]
    fn every_byte_split_round_trips() {
        let (map, text, expected) = sample();
        let bytes = text.as_bytes();
        for split in 0..=bytes.len() {
            let mut restorer = ByteRestorer::new(map.clone(), false);
            let mut out = restorer.push(&bytes[..split]);
            out.push_str(&restorer.push(&bytes[split..]));
            out.push_str(&restorer.finish());
            assert_eq!(out, expected, "split at {split}");
        }
    }

    #[test]
    fn every_window_round_trips() {
        let (map, text, expected) = sample();
        let bytes = text.as_bytes();
        for window in 1..12 {
            let mut restorer = ByteRestorer::new(map.clone(), false);
            let mut out = String::new();
            let mut index = 0;
            while index < bytes.len() {
                let end = (index + window).min(bytes.len());
                out.push_str(&restorer.push(&bytes[index..end]));
                index = end;
            }
            out.push_str(&restorer.finish());
            assert_eq!(out, expected, "window {window}");
        }
    }

    #[test]
    fn adjacent_placeholders_restore() {
        let (map, _, _) = sample();
        let mut vault = Vault::ephemeral();
        let a = vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        let b = vault
            .assign("AURORA_RCC_CTRL_REG", Category::Register, None)
            .unwrap();
        let mut map = map;
        map.insert(a.clone(), "aurora_rcc_enable_pll".to_string());
        map.insert(b.clone(), "AURORA_RCC_CTRL_REG".to_string());
        let text = format!("{a}{b}");
        let mut restorer = ByteRestorer::new(map, false);
        let mut out = String::new();
        for byte in text.as_bytes() {
            out.push_str(&restorer.push(&[*byte]));
        }
        out.push_str(&restorer.finish());
        assert_eq!(out, "aurora_rcc_enable_pllAURORA_RCC_CTRL_REG");
    }

    #[test]
    fn json_escape_survives_a_split_inside_the_token() {
        let mut vault = Vault::ephemeral();
        let token = vault
            .assign("p@ss\"word12", Category::Secret, Some("literal".into()))
            .unwrap();
        let map = vault.restore_map();
        let bytes = token.as_bytes();
        let mut restorer = ByteRestorer::new(map, true);
        let mut out = restorer.push(&bytes[..6]);
        out.push_str(&restorer.push(&bytes[6..]));
        out.push_str(&restorer.finish());
        assert_eq!(out, r#"p@ss\"word12"#);
        assert_eq!(restorer.restored(), 1);
    }

    #[test]
    fn unknown_token_is_left_in_place() {
        let map = HashMap::new();
        let mut restorer = StreamRestorer::new(map, false);
        let out = restorer.push("@@sv:0123abcd@@");
        assert_eq!(out, "@@sv:0123abcd@@");
        assert_eq!(restorer.restored(), 0);
    }

    #[test]
    fn uppercase_hex_matches_the_lowercase_key() {
        let mut vault = Vault::ephemeral();
        let token = vault
            .assign("aurora_rcc_enable_pll", Category::Function, None)
            .unwrap();
        let upper = token.replace(&token[5..13], &token[5..13].to_ascii_uppercase());
        let mut restorer = StreamRestorer::new(vault.restore_map(), false);
        assert_eq!(restorer.push(&upper), "aurora_rcc_enable_pll");
    }

    #[test]
    fn json_escape_quotes_and_newlines() {
        assert_eq!(json_escape("a\"b\\c"), r#"a\"b\\c"#);
        assert_eq!(json_escape("line\n"), r#"line\n"#);
    }

    #[test]
    fn sse_splits_restore_across_argument_and_text_deltas() {
        let secret_a = "AKIAIOSFODNN7EXAMPLE";
        let secret_b = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let mut vault = Vault::ephemeral();
        let ph_a = vault
            .assign(secret_a, Category::Secret, Some("aws-access-key-id".into()))
            .unwrap();
        let ph_b = vault
            .assign(secret_b, Category::Secret, Some("github-pat".into()))
            .unwrap();
        let map = vault.restore_map();
        let logical_a = format!(r#"{{"cmd":"echo {ph_a}"}}"#);
        let logical_b = format!(r#"{{"cmd":"echo {ph_b}"}}"#);
        let expected_a = format!(r#"{{"cmd":"echo {secret_a}"}}"#);
        let expected_b = format!(r#"{{"cmd":"echo {secret_b}"}}"#);
        assert_eq!(logical_a.len(), logical_b.len());

        for at in 0..=logical_a.len() {
            let (left_a, right_a) = logical_a.split_at(at);
            let other = logical_b.len() - at;
            let (left_b, right_b) = logical_b.split_at(other);
            for window in [1usize, usize::MAX] {
                for shape in ["chat", "anthropic", "responses"] {
                    let single = match shape {
                        "chat" => chat_tool_sse(&[(left_a, right_a)]),
                        "anthropic" => anthropic_tool_sse(&[(left_a, right_a)]),
                        "responses" => responses_tool_sse(&[(left_a, right_a)]),
                        _ => unreachable!(),
                    };
                    let (body, restored) = feed(&map, &single, window);
                    assert!(
                        !body.contains("@@sv:"),
                        "{shape} single at {at} window {window}: {body}"
                    );
                    assert_eq!(
                        joined_args(&body, shape, 0),
                        expected_a,
                        "{shape} single at {at} window {window}"
                    );
                    assert_valid_frames(&body);
                    if shape == "chat" || shape == "anthropic" {
                        assert_eq!(restored, 1, "{shape} double-counted at {at}");
                    } else {
                        assert_eq!(joined_done_args(&body, 0), expected_a);
                        assert!(restored >= 1);
                    }

                    let interleaved = match shape {
                        "chat" => chat_tool_sse(&[(left_a, right_a), (left_b, right_b)]),
                        "anthropic" => anthropic_tool_sse(&[(left_a, right_a), (left_b, right_b)]),
                        "responses" => responses_tool_sse(&[(left_a, right_a), (left_b, right_b)]),
                        _ => unreachable!(),
                    };
                    let (body, _) = feed(&map, &interleaved, window);
                    assert!(
                        !body.contains("@@sv:"),
                        "{shape} interleave at {at} window {window}: {body}"
                    );
                    assert_eq!(joined_args(&body, shape, 0), expected_a);
                    assert_eq!(joined_args(&body, shape, 1), expected_b);
                    assert_valid_frames(&body);
                }
            }
        }
    }

    #[test]
    fn sse_text_deltas_restore_at_every_char_split() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let mut vault = Vault::ephemeral();
        let ph = vault
            .assign(secret, Category::Secret, Some("aws-access-key-id".into()))
            .unwrap();
        let map = vault.restore_map();
        let logical = format!("café key {ph} end");
        let expected = format!("café key {secret} end");
        let mut offsets: Vec<usize> = logical.char_indices().map(|(idx, _)| idx).collect();
        offsets.push(logical.len());
        for at in offsets {
            let (left, right) = logical.split_at(at);
            for shape in ["chat", "anthropic", "responses"] {
                let sse = match shape {
                    "chat" => chat_text_sse(left, right),
                    "anthropic" => anthropic_text_sse(left, right),
                    "responses" => responses_text_sse(left, right),
                    _ => unreachable!(),
                };
                let (body, _) = feed(&map, &sse, 1);
                assert!(!body.contains("@@sv:"), "{shape} text at {at}: {body}");
                assert_eq!(joined_text(&body, shape), expected, "{shape} text at {at}");
                assert_valid_frames(&body);
            }
        }
    }

    #[test]
    fn sse_argument_restore_escapes_quotes_and_keeps_text_raw() {
        let secret = "say \"hi\"\\there";
        let mut vault = Vault::ephemeral();
        let ph = vault
            .assign(secret, Category::Secret, Some("literal".into()))
            .unwrap();
        let map = vault.restore_map();
        let logical = format!(r#"{{"path":"{ph}"}}"#);
        for at in 0..=logical.len() {
            let (left, right) = logical.split_at(at);
            let (body, _) = feed(&map, &chat_tool_sse(&[(left, right)]), 1);
            assert_valid_frames(&body);
            let joined = joined_args(&body, "chat", 0);
            let parsed: Value = serde_json::from_str(&joined).unwrap_or_else(|err| {
                panic!("arguments are not json at {at}: {err} body {joined}")
            });
            assert_eq!(parsed["path"], secret, "at {at}");
        }
        let text = format!("note {ph} tail");
        let (left, right) = text.split_at(text.find(ph.as_str()).unwrap() + 2);
        let (body, _) = feed(&map, &chat_text_sse(left, right), 3);
        assert_eq!(joined_text(&body, "chat"), format!("note {secret} tail"));
    }

    #[test]
    fn dangling_partial_token_is_flushed_before_done() {
        let map = HashMap::new();
        let sse = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello @\"}}]}\n\ndata: [DONE]\n\n";
        let (body, _) = feed(&map, sse, 2);
        assert_eq!(joined_text(&body, "chat"), "hello @");
        assert!(body.contains("[DONE]"));
        assert_valid_frames(&body);
    }

    #[test]
    fn non_sse_stream_falls_back_to_byte_restore() {
        let mut vault = Vault::ephemeral();
        let ph = vault
            .assign("AKIAIOSFODNN7EXAMPLE", Category::Secret, None)
            .unwrap();
        let map = vault.restore_map();
        let text = format!("{{\"content\":\"{ph}\"}}");
        let (body, restored) = feed(&map, &text, 1);
        assert_eq!(body, "{\"content\":\"AKIAIOSFODNN7EXAMPLE\"}");
        assert_eq!(restored, 1);
    }

    #[test]
    fn thinking_delta_split_restores() {
        let mut vault = Vault::ephemeral();
        let ph = vault
            .assign("AKIAIOSFODNN7EXAMPLE", Category::Secret, None)
            .unwrap();
        let map = vault.restore_map();
        let logical = format!("think {ph}.");
        let (left, right) = logical.split_at(8);
        let sse = format!(
            "event: content_block_delta\ndata: {}\n\nevent: content_block_delta\ndata: {}\n\nevent: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":0}}\n\n",
            serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":left}}),
            serde_json::json!({"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":right}}),
        );
        let (body, _) = feed(&map, &sse, 1);
        assert_eq!(
            joined_text(&body, "thinking"),
            "think AKIAIOSFODNN7EXAMPLE."
        );
        assert!(!body.contains("@@sv:"));
    }

    fn feed(map: &HashMap<String, String>, sse: &str, window: usize) -> (String, usize) {
        let mut restorer = SseRestorer::new(map.clone(), true);
        let bytes = sse.as_bytes();
        let mut out = String::new();
        let step = window.max(1);
        let mut index = 0;
        while index < bytes.len() {
            let end = (index + step).min(bytes.len());
            out.push_str(&restorer.push(&bytes[index..end]));
            index = end;
        }
        out.push_str(&restorer.finish());
        (out, restorer.restored())
    }

    fn assert_valid_frames(body: &str) {
        assert!(body.ends_with("\n\n") || body.is_empty(), "{body}");
        for block in body.split("\n\n") {
            if block.is_empty() {
                continue;
            }
            let parsed = parse_event(block);
            if parsed.data.trim() == "[DONE]" {
                continue;
            }
            serde_json::from_str::<Value>(&parsed.data)
                .unwrap_or_else(|err| panic!("invalid frame {err}: {block}"));
        }
    }

    fn frames(body: &str) -> Vec<Value> {
        body.split("\n\n")
            .filter(|block| !block.is_empty())
            .filter_map(|block| {
                let parsed = parse_event(block);
                if parsed.data.trim() == "[DONE]" {
                    None
                } else {
                    Some(serde_json::from_str(&parsed.data).unwrap())
                }
            })
            .collect()
    }

    fn chat_tool_sse(tools: &[(&str, &str)]) -> String {
        let mut out = String::new();
        for (index, (left, _)) in tools.iter().enumerate() {
            let payload = serde_json::json!({
                "choices": [{
                    "index": 0,
                    "delta": {
                        "tool_calls": [{
                            "index": index,
                            "id": format!("call_{index}"),
                            "type": "function",
                            "function": {"name": "run_terminal_command", "arguments": left}
                        }]
                    }
                }]
            });
            out.push_str("data: ");
            out.push_str(&payload.to_string());
            out.push_str("\n\n");
        }
        for (index, (_, right)) in tools.iter().enumerate() {
            let payload = serde_json::json!({
                "choices": [{
                    "index": 0,
                    "delta": {
                        "tool_calls": [{
                            "index": index,
                            "function": {"arguments": right}
                        }]
                    }
                }]
            });
            out.push_str("data: ");
            out.push_str(&payload.to_string());
            out.push_str("\n\n");
        }
        out.push_str(
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        );
        out.push_str("data: [DONE]\n\n");
        out
    }

    fn anthropic_tool_sse(tools: &[(&str, &str)]) -> String {
        let mut out = String::from(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_test\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}}\n\n",
        );
        out.push_str("event: ping\ndata: {\"type\":\"ping\"}\n\n");
        for (index, _) in tools.iter().enumerate() {
            let payload = serde_json::json!({
                "type": "content_block_start",
                "index": index,
                "content_block": {
                    "type": "tool_use",
                    "id": format!("toolu_{index}"),
                    "name": "run_terminal_command",
                    "input": {}
                }
            });
            out.push_str("event: content_block_start\ndata: ");
            out.push_str(&payload.to_string());
            out.push_str("\n\n");
        }
        for (index, (left, _)) in tools.iter().enumerate() {
            push_anthropic_delta(&mut out, index, "input_json_delta", "partial_json", left);
        }
        for (index, (_, right)) in tools.iter().enumerate() {
            push_anthropic_delta(&mut out, index, "input_json_delta", "partial_json", right);
        }
        for index in 0..tools.len() {
            out.push_str(&format!(
                "event: content_block_stop\ndata: {{\"type\":\"content_block_stop\",\"index\":{index}}}\n\n"
            ));
        }
        out.push_str(
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n",
        );
        out.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
        out
    }

    fn push_anthropic_delta(out: &mut String, index: usize, kind: &str, field: &str, text: &str) {
        let mut delta = serde_json::Map::new();
        delta.insert("type".to_string(), Value::String(kind.to_string()));
        delta.insert(field.to_string(), Value::String(text.to_string()));
        let payload = serde_json::json!({
            "type": "content_block_delta",
            "index": index,
            "delta": Value::Object(delta)
        });
        out.push_str("event: content_block_delta\ndata: ");
        out.push_str(&payload.to_string());
        out.push_str("\n\n");
    }

    fn responses_tool_sse(tools: &[(&str, &str)]) -> String {
        let mut out = String::new();
        for (index, _) in tools.iter().enumerate() {
            let payload = serde_json::json!({
                "type": "response.output_item.added",
                "output_index": index,
                "item": {
                    "type": "function_call",
                    "id": format!("fc_{index}"),
                    "call_id": format!("call_{index}"),
                    "name": "run_terminal_command",
                    "arguments": ""
                }
            });
            out.push_str("event: response.output_item.added\ndata: ");
            out.push_str(&payload.to_string());
            out.push_str("\n\n");
        }
        for (index, (left, _)) in tools.iter().enumerate() {
            push_response_delta(
                &mut out,
                index,
                "response.function_call_arguments.delta",
                left,
            );
        }
        for (index, (_, right)) in tools.iter().enumerate() {
            push_response_delta(
                &mut out,
                index,
                "response.function_call_arguments.delta",
                right,
            );
        }
        let mut outputs = Vec::new();
        for (index, (left, right)) in tools.iter().enumerate() {
            let full = format!("{left}{right}");
            let done = serde_json::json!({
                "type": "response.function_call_arguments.done",
                "item_id": format!("fc_{index}"),
                "output_index": index,
                "arguments": full
            });
            out.push_str("event: response.function_call_arguments.done\ndata: ");
            out.push_str(&done.to_string());
            out.push_str("\n\n");
            let item = serde_json::json!({
                "type": "function_call",
                "id": format!("fc_{index}"),
                "call_id": format!("call_{index}"),
                "name": "run_terminal_command",
                "arguments": full
            });
            let item_done = serde_json::json!({
                "type": "response.output_item.done",
                "output_index": index,
                "item": item
            });
            out.push_str("event: response.output_item.done\ndata: ");
            out.push_str(&item_done.to_string());
            out.push_str("\n\n");
            outputs.push(item);
        }
        let completed = serde_json::json!({
            "type": "response.completed",
            "response": {"id": "resp_test", "output": outputs}
        });
        out.push_str("event: response.completed\ndata: ");
        out.push_str(&completed.to_string());
        out.push_str("\n\n");
        out
    }

    fn push_response_delta(out: &mut String, index: usize, kind: &str, text: &str) {
        let payload = serde_json::json!({
            "type": kind,
            "item_id": format!("fc_{index}"),
            "output_index": index,
            "delta": text
        });
        out.push_str("event: ");
        out.push_str(kind);
        out.push_str("\ndata: ");
        out.push_str(&payload.to_string());
        out.push_str("\n\n");
    }

    fn chat_text_sse(left: &str, right: &str) -> String {
        let mut out = String::new();
        for part in [left, right] {
            let payload = serde_json::json!({
                "choices": [{"index": 0, "delta": {"content": part}}]
            });
            out.push_str("data: ");
            out.push_str(&payload.to_string());
            out.push_str("\n\n");
        }
        out.push_str(
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
        );
        out
    }

    fn anthropic_text_sse(left: &str, right: &str) -> String {
        let mut out = String::from(
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        );
        push_anthropic_delta(&mut out, 0, "text_delta", "text", left);
        push_anthropic_delta(&mut out, 0, "text_delta", "text", right);
        out.push_str(
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        );
        out
    }

    fn responses_text_sse(left: &str, right: &str) -> String {
        let mut out = String::new();
        for part in [left, right] {
            let payload = serde_json::json!({
                "type": "response.output_text.delta",
                "item_id": "msg_1",
                "output_index": 0,
                "content_index": 0,
                "delta": part
            });
            out.push_str("event: response.output_text.delta\ndata: ");
            out.push_str(&payload.to_string());
            out.push_str("\n\n");
        }
        let full = format!("{left}{right}");
        let done = serde_json::json!({
            "type": "response.output_text.done",
            "item_id": "msg_1",
            "output_index": 0,
            "content_index": 0,
            "text": full
        });
        out.push_str("event: response.output_text.done\ndata: ");
        out.push_str(&done.to_string());
        out.push_str("\n\n");
        out
    }

    fn joined_args(body: &str, shape: &str, index: usize) -> String {
        let mut out = String::new();
        for value in frames(body) {
            match shape {
                "chat" => {
                    let Some(calls) = value
                        .pointer("/choices/0/delta/tool_calls")
                        .and_then(Value::as_array)
                    else {
                        continue;
                    };
                    for call in calls {
                        if call.get("index").and_then(Value::as_u64) != Some(index as u64) {
                            continue;
                        }
                        if let Some(args) =
                            call.pointer("/function/arguments").and_then(Value::as_str)
                        {
                            out.push_str(args);
                        }
                    }
                }
                "anthropic" => {
                    if value.get("index").and_then(Value::as_u64) != Some(index as u64) {
                        continue;
                    }
                    if value.pointer("/delta/type").and_then(Value::as_str)
                        != Some("input_json_delta")
                    {
                        continue;
                    }
                    if let Some(part) = value.pointer("/delta/partial_json").and_then(Value::as_str)
                    {
                        out.push_str(part);
                    }
                }
                "responses" => {
                    if value.get("type").and_then(Value::as_str)
                        != Some("response.function_call_arguments.delta")
                    {
                        continue;
                    }
                    if value.get("output_index").and_then(Value::as_u64) != Some(index as u64) {
                        continue;
                    }
                    if let Some(part) = value.get("delta").and_then(Value::as_str) {
                        out.push_str(part);
                    }
                }
                _ => unreachable!(),
            }
        }
        out
    }

    fn joined_done_args(body: &str, index: usize) -> String {
        for value in frames(body) {
            if value.get("type").and_then(Value::as_str)
                != Some("response.function_call_arguments.done")
            {
                continue;
            }
            if value.get("output_index").and_then(Value::as_u64) != Some(index as u64) {
                continue;
            }
            if let Some(args) = value.get("arguments").and_then(Value::as_str) {
                return args.to_string();
            }
        }
        String::new()
    }

    fn joined_text(body: &str, shape: &str) -> String {
        let mut out = String::new();
        for value in frames(body) {
            match shape {
                "chat" => {
                    if let Some(text) = value
                        .pointer("/choices/0/delta/content")
                        .and_then(Value::as_str)
                    {
                        out.push_str(text);
                    }
                }
                "anthropic" => {
                    if value.pointer("/delta/type").and_then(Value::as_str) == Some("text_delta") {
                        if let Some(text) = value.pointer("/delta/text").and_then(Value::as_str) {
                            out.push_str(text);
                        }
                    }
                }
                "thinking" => {
                    if value.pointer("/delta/type").and_then(Value::as_str)
                        == Some("thinking_delta")
                    {
                        if let Some(text) = value.pointer("/delta/thinking").and_then(Value::as_str)
                        {
                            out.push_str(text);
                        }
                    }
                }
                "responses" => {
                    if value.get("type").and_then(Value::as_str)
                        == Some("response.output_text.delta")
                    {
                        if let Some(text) = value.get("delta").and_then(Value::as_str) {
                            out.push_str(text);
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        out
    }
}
