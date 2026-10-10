//! A minimal JSON reader (RFC 8259) for the reference observation files: objects, arrays,
//! strings with the common escapes, integers, booleans and null. Fractions and exponents
//! are kept as text, which these files only use inside strings.

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(entries) => entries
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .unwrap_or(&Json::Null),
            _ => &Json::Null,
        }
    }

    pub fn as_i64(&self) -> i64 {
        match self {
            Json::Int(n) => *n,
            other => panic!("not an integer: {other:?}"),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            other => panic!("not a string: {other:?}"),
        }
    }

    pub fn as_bool(&self) -> bool {
        match self {
            Json::Bool(b) => *b,
            other => panic!("not a boolean: {other:?}"),
        }
    }

    pub fn as_array(&self) -> &[Json] {
        match self {
            Json::Arr(items) => items,
            other => panic!("not an array: {other:?}"),
        }
    }

    pub fn as_object(&self) -> &[(String, Json)] {
        match self {
            Json::Obj(entries) => entries,
            other => panic!("not an object: {other:?}"),
        }
    }
}

pub(super) fn parse(text: &str) -> Json {
    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let value = p.value();
    p.ws();
    assert_eq!(p.pos, p.bytes.len(), "trailing JSON");
    value
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.bytes.get(self.pos), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, byte: u8) {
        self.ws();
        assert_eq!(
            self.bytes.get(self.pos),
            Some(&byte),
            "expected {:?} at {}",
            byte as char,
            self.pos
        );
        self.pos += 1;
    }

    fn literal(&mut self, word: &str) {
        assert!(self.bytes[self.pos..].starts_with(word.as_bytes()));
        self.pos += word.len();
    }

    fn value(&mut self) -> Json {
        self.ws();
        match self.bytes[self.pos] {
            b'{' => {
                self.pos += 1;
                let mut entries = Vec::new();
                self.ws();
                if self.bytes[self.pos] == b'}' {
                    self.pos += 1;
                    return Json::Obj(entries);
                }
                loop {
                    self.ws();
                    let key = self.string();
                    self.eat(b':');
                    entries.push((key, self.value()));
                    self.ws();
                    match self.bytes[self.pos] {
                        b',' => self.pos += 1,
                        b'}' => {
                            self.pos += 1;
                            return Json::Obj(entries);
                        }
                        other => panic!("unexpected {:?}", other as char),
                    }
                }
            }
            b'[' => {
                self.pos += 1;
                let mut items = Vec::new();
                self.ws();
                if self.bytes[self.pos] == b']' {
                    self.pos += 1;
                    return Json::Arr(items);
                }
                loop {
                    items.push(self.value());
                    self.ws();
                    match self.bytes[self.pos] {
                        b',' => self.pos += 1,
                        b']' => {
                            self.pos += 1;
                            return Json::Arr(items);
                        }
                        other => panic!("unexpected {:?}", other as char),
                    }
                }
            }
            b'"' => Json::Str(self.string()),
            b't' => {
                self.literal("true");
                Json::Bool(true)
            }
            b'f' => {
                self.literal("false");
                Json::Bool(false)
            }
            b'n' => {
                self.literal("null");
                Json::Null
            }
            _ => {
                let start = self.pos;
                while matches!(self.bytes.get(self.pos), Some(b'-' | b'0'..=b'9')) {
                    self.pos += 1;
                }
                let text = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap();
                Json::Int(text.parse().unwrap())
            }
        }
    }

    fn string(&mut self) -> String {
        self.eat(b'"');
        let mut out = String::new();
        loop {
            let c = self.bytes[self.pos];
            self.pos += 1;
            match c {
                b'"' => return out,
                b'\\' => {
                    let e = self.bytes[self.pos];
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'u' => {
                            let hex =
                                std::str::from_utf8(&self.bytes[self.pos..self.pos + 4]).unwrap();
                            self.pos += 4;
                            out.push(
                                char::from_u32(u32::from_str_radix(hex, 16).unwrap()).unwrap(),
                            );
                        }
                        other => panic!("bad escape {:?}", other as char),
                    }
                }
                _ => {
                    // Copy one UTF-8 sequence.
                    let start = self.pos - 1;
                    let mut end = self.pos;
                    while end < self.bytes.len() && self.bytes[end] & 0xC0 == 0x80 {
                        end += 1;
                    }
                    out.push_str(std::str::from_utf8(&self.bytes[start..end]).unwrap());
                    self.pos = end;
                }
            }
        }
    }
}

#[test]
fn parses_nested_documents() {
    let v = parse(r#"{"a": [1, -2, true, null], "b": {"c": "x\"y"}}"#);
    assert_eq!(v.get("a").as_array().len(), 4);
    assert_eq!(v.get("a").as_array()[1].as_i64(), -2);
    assert_eq!(v.get("b").get("c").as_str(), "x\"y");
}
