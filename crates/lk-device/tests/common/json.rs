//! A small JSON reader (RFC 8259) for the reference observation files: objects, arrays,
//! strings without escapes beyond `\"` and `\\`, integers, booleans and null.

#![allow(dead_code)]

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
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
            Json::Obj(members) => members
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("missing JSON member {key}")),
            other => panic!("not an object: {other:?}"),
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
            Json::Obj(members) => members,
            other => panic!("not an object: {other:?}"),
        }
    }
}

pub fn parse(text: &str) -> Json {
    let mut parser = Parser { s: text.as_bytes(), i: 0 };
    let value = parser.value();
    parser.ws();
    assert_eq!(parser.i, parser.s.len(), "trailing JSON");
    value
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) {
        self.ws();
        assert_eq!(self.s[self.i], c, "JSON: expected {:?} at {}", c as char, self.i);
        self.i += 1;
    }

    fn peek(&mut self) -> u8 {
        self.ws();
        self.s[self.i]
    }

    fn value(&mut self) -> Json {
        match self.peek() {
            b'{' => {
                self.eat(b'{');
                let mut members = Vec::new();
                if self.peek() == b'}' {
                    self.eat(b'}');
                    return Json::Obj(members);
                }
                loop {
                    let key = self.string();
                    self.eat(b':');
                    members.push((key, self.value()));
                    if self.peek() == b',' {
                        self.eat(b',');
                    } else {
                        self.eat(b'}');
                        return Json::Obj(members);
                    }
                }
            }
            b'[' => {
                self.eat(b'[');
                let mut items = Vec::new();
                if self.peek() == b']' {
                    self.eat(b']');
                    return Json::Arr(items);
                }
                loop {
                    items.push(self.value());
                    if self.peek() == b',' {
                        self.eat(b',');
                    } else {
                        self.eat(b']');
                        return Json::Arr(items);
                    }
                }
            }
            b'"' => Json::Str(self.string()),
            b't' => self.word("true", Json::Bool(true)),
            b'f' => self.word("false", Json::Bool(false)),
            b'n' => self.word("null", Json::Null),
            _ => {
                let start = self.i;
                while self.i < self.s.len() && (self.s[self.i] == b'-' || self.s[self.i].is_ascii_digit()) {
                    self.i += 1;
                }
                let text = std::str::from_utf8(&self.s[start..self.i]).unwrap_or_default();
                Json::Int(text.parse().unwrap_or_else(|_| panic!("JSON number at {start}: {text:?}")))
            }
        }
    }

    fn word(&mut self, word: &str, value: Json) -> Json {
        assert!(self.s[self.i..].starts_with(word.as_bytes()), "JSON literal at {}", self.i);
        self.i += word.len();
        value
    }

    fn string(&mut self) -> String {
        self.eat(b'"');
        let mut out = Vec::new();
        while self.s[self.i] != b'"' {
            if self.s[self.i] == b'\\' {
                self.i += 1;
                assert!(matches!(self.s[self.i], b'"' | b'\\' | b'/'), "unsupported JSON escape");
            }
            out.push(self.s[self.i]);
            self.i += 1;
        }
        self.i += 1;
        String::from_utf8(out).unwrap_or_default()
    }
}
