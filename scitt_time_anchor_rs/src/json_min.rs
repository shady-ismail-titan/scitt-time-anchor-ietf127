//! Minimal safe RFC 8259 JSON parser & serializer for zero-dependency JSONL CLI cross-checking.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum JsonVal {
    Null,
    Bool(bool),
    Num(i64),
    Str(String),
    Arr(Vec<JsonVal>),
    Obj(BTreeMap<String, JsonVal>),
}

impl JsonVal {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Num(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[JsonVal]> {
        match self {
            Self::Arr(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&BTreeMap<String, JsonVal>> {
        match self {
            Self::Obj(m) => Some(m),
            _ => None,
        }
    }
}

struct JsonParser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.b.len() && self.b[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn parse_val(&mut self) -> Option<JsonVal> {
        self.skip_ws();
        if self.pos >= self.b.len() {
            return None;
        }
        match self.b[self.pos] {
            b'n' => {
                if self.b.get(self.pos..self.pos + 4)? == b"null" {
                    self.pos += 4;
                    Some(JsonVal::Null)
                } else {
                    None
                }
            }
            b't' => {
                if self.b.get(self.pos..self.pos + 4)? == b"true" {
                    self.pos += 4;
                    Some(JsonVal::Bool(true))
                } else {
                    None
                }
            }
            b'f' => {
                if self.b.get(self.pos..self.pos + 5)? == b"false" {
                    self.pos += 5;
                    Some(JsonVal::Bool(false))
                } else {
                    None
                }
            }
            b'"' => self.parse_str().map(JsonVal::Str),
            b'[' => self.parse_arr().map(JsonVal::Arr),
            b'{' => self.parse_obj().map(JsonVal::Obj),
            b'-' | b'0'..=b'9' => self.parse_num().map(JsonVal::Num),
            _ => None,
        }
    }

    fn parse_str(&mut self) -> Option<String> {
        if self.b.get(self.pos)? != &b'"' {
            return None;
        }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.b.len() {
            let c = self.b[self.pos];
            self.pos += 1;
            if c == b'"' {
                return Some(out);
            }
            if c == b'\\' {
                let esc = *self.b.get(self.pos)?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\x08'),
                    b'f' => out.push('\x0c'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hex_slice = self.b.get(self.pos..self.pos + 4)?;
                        let hex_str = core::str::from_utf8(hex_slice).ok()?;
                        let code = u32::from_str_radix(hex_str, 16).ok()?;
                        self.pos += 4;
                        out.push(char::from_u32(code)?);
                    }
                    _ => return None,
                }
            } else {
                out.push(c as char);
            }
        }
        None
    }

    fn parse_num(&mut self) -> Option<i64> {
        let start = self.pos;
        if self.b.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        while self.pos < self.b.len() && self.b[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let s = core::str::from_utf8(&self.b[start..self.pos]).ok()?;
        s.parse::<i64>().ok()
    }

    fn parse_arr(&mut self) -> Option<Vec<JsonVal>> {
        if self.b.get(self.pos)? != &b'[' {
            return None;
        }
        self.pos += 1;
        let mut arr = Vec::new();
        self.skip_ws();
        if self.b.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Some(arr);
        }
        loop {
            let val = self.parse_val()?;
            arr.push(val);
            self.skip_ws();
            match self.b.get(self.pos)? {
                b',' => self.pos += 1,
                b']' => {
                    self.pos += 1;
                    return Some(arr);
                }
                _ => return None,
            }
        }
    }

    fn parse_obj(&mut self) -> Option<BTreeMap<String, JsonVal>> {
        if self.b.get(self.pos)? != &b'{' {
            return None;
        }
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.b.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Some(map);
        }
        loop {
            self.skip_ws();
            let key = self.parse_str()?;
            self.skip_ws();
            if self.b.get(self.pos)? != &b':' {
                return None;
            }
            self.pos += 1;
            let val = self.parse_val()?;
            map.insert(key, val);
            self.skip_ws();
            match self.b.get(self.pos)? {
                b',' => self.pos += 1,
                b'}' => {
                    self.pos += 1;
                    return Some(map);
                }
                _ => return None,
            }
        }
    }
}

pub fn parse_json_object(line: &str) -> Option<BTreeMap<String, JsonVal>> {
    let mut p = JsonParser {
        b: line.as_bytes(),
        pos: 0,
    };
    let val = p.parse_val()?;
    p.skip_ws();
    if p.pos != p.b.len() {
        return None;
    }
    match val {
        JsonVal::Obj(m) => Some(m),
        _ => None,
    }
}

pub fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
