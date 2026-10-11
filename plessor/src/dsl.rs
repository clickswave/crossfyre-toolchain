//! A small expression evaluator for nuclei-style `dsl` matcher/extractor
//! expressions. It supports the practical subset that real templates use:
//! comparisons, boolean logic, arithmetic, string helpers and regex, evaluated
//! against a response context (status_code, body, headers, content_length).
//!
//! This is deliberately self-contained (its own tokenizer + recursive-descent
//! parser + evaluator) so plessor gains DSL coverage without a scripting-engine
//! dependency. Unknown identifiers/functions evaluate to a safe empty value so a
//! template using an unsupported helper simply fails to match rather than erroring.

use regex::Regex;

/// The response context an expression is evaluated against.
pub struct Ctx<'a> {
    pub status_code: u16,
    pub body: &'a str,
    pub headers: &'a str,
    pub content_length: usize,
}

#[derive(Clone, Debug)]
enum Val {
    Str(String),
    Num(f64),
    Bool(bool),
}

/// Evaluate an expression to a boolean (the matcher use). Parse/eval failures
/// return false so a bad expression never becomes a spurious match.
pub fn eval_bool(expr: &str, ctx: &Ctx) -> bool {
    match eval_value(expr, ctx) {
        Some(v) => to_bool(&v),
        None => false,
    }
}

/// Evaluate an expression to its string form (the extractor use), or None.
#[allow(dead_code)] // DSL helper, no current caller
pub fn eval_string(expr: &str, ctx: &Ctx) -> Option<String> {
    eval_value(expr, ctx).map(|v| to_str(&v))
}

fn eval_value(expr: &str, ctx: &Ctx) -> Option<Val> {
    let toks = tokenize(expr)?;
    let mut p = Parser { toks, pos: 0 };
    let node = p.parse_or()?;
    if p.pos != p.toks.len() {
        return None; // trailing garbage
    }
    Some(eval(&node, ctx))
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Num(f64),
    Str(String),
    Ident(String),
    // operators / punctuation
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr,
    Bang,
    Plus,
    Minus,
    Star,
    Slash,
    LParen,
    RParen,
    Comma,
}

fn tokenize(s: &str) -> Option<Vec<Tok>> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        match c {
            b'"' | b'\'' => {
                let quote = c;
                i += 1;
                let mut lit = String::new();
                while i < b.len() && b[i] != quote {
                    if b[i] == b'\\' && i + 1 < b.len() {
                        // basic escapes
                        let n = b[i + 1];
                        lit.push(match n {
                            b'n' => '\n',
                            b't' => '\t',
                            b'r' => '\r',
                            other => other as char,
                        });
                        i += 2;
                    } else {
                        lit.push(b[i] as char);
                        i += 1;
                    }
                }
                if i >= b.len() {
                    return None; // unterminated string
                }
                i += 1; // closing quote
                out.push(Tok::Str(lit));
            }
            b'0'..=b'9' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                    i += 1;
                }
                let num: f64 = s[start..i].parse().ok()?;
                out.push(Tok::Num(num));
            }
            b'=' if i + 1 < b.len() && b[i + 1] == b'=' => {
                out.push(Tok::EqEq);
                i += 2;
            }
            b'!' if i + 1 < b.len() && b[i + 1] == b'=' => {
                out.push(Tok::NotEq);
                i += 2;
            }
            b'<' if i + 1 < b.len() && b[i + 1] == b'=' => {
                out.push(Tok::Le);
                i += 2;
            }
            b'>' if i + 1 < b.len() && b[i + 1] == b'=' => {
                out.push(Tok::Ge);
                i += 2;
            }
            b'&' if i + 1 < b.len() && b[i + 1] == b'&' => {
                out.push(Tok::AndAnd);
                i += 2;
            }
            b'|' if i + 1 < b.len() && b[i + 1] == b'|' => {
                out.push(Tok::OrOr);
                i += 2;
            }
            b'<' => {
                out.push(Tok::Lt);
                i += 1;
            }
            b'>' => {
                out.push(Tok::Gt);
                i += 1;
            }
            b'!' => {
                out.push(Tok::Bang);
                i += 1;
            }
            b'+' => {
                out.push(Tok::Plus);
                i += 1;
            }
            b'-' => {
                out.push(Tok::Minus);
                i += 1;
            }
            b'*' => {
                out.push(Tok::Star);
                i += 1;
            }
            b'/' => {
                out.push(Tok::Slash);
                i += 1;
            }
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            _ if c == b'_' || c.is_ascii_alphabetic() => {
                let start = i;
                while i < b.len() && (b[i] == b'_' || b[i].is_ascii_alphanumeric()) {
                    i += 1;
                }
                out.push(Tok::Ident(s[start..i].to_string()));
            }
            _ => return None, // unknown character
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Parser (recursive descent) -> AST
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Node {
    Num(f64),
    Str(String),
    Bool(bool),
    Var(String),
    Call(String, Vec<Node>),
    Unary(Tok, Box<Node>),
    Binary(Tok, Box<Node>, Box<Node>),
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn eat(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn expect(&mut self, t: &Tok) -> Option<()> {
        if self.peek() == Some(t) {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }

    fn parse_or(&mut self) -> Option<Node> {
        let mut left = self.parse_and()?;
        while self.peek() == Some(&Tok::OrOr) {
            self.eat();
            let right = self.parse_and()?;
            left = Node::Binary(Tok::OrOr, Box::new(left), Box::new(right));
        }
        Some(left)
    }
    fn parse_and(&mut self) -> Option<Node> {
        let mut left = self.parse_not()?;
        while self.peek() == Some(&Tok::AndAnd) {
            self.eat();
            let right = self.parse_not()?;
            left = Node::Binary(Tok::AndAnd, Box::new(left), Box::new(right));
        }
        Some(left)
    }
    fn parse_not(&mut self) -> Option<Node> {
        if self.peek() == Some(&Tok::Bang) {
            self.eat();
            let inner = self.parse_not()?;
            return Some(Node::Unary(Tok::Bang, Box::new(inner)));
        }
        self.parse_cmp()
    }
    fn parse_cmp(&mut self) -> Option<Node> {
        let left = self.parse_add()?;
        if let Some(op) = self.peek().cloned()
            && matches!(
                op,
                Tok::EqEq | Tok::NotEq | Tok::Lt | Tok::Le | Tok::Gt | Tok::Ge
            )
        {
            self.eat();
            let right = self.parse_add()?;
            return Some(Node::Binary(op, Box::new(left), Box::new(right)));
        }
        Some(left)
    }
    fn parse_add(&mut self) -> Option<Node> {
        let mut left = self.parse_mul()?;
        while let Some(op) = self.peek().cloned() {
            if matches!(op, Tok::Plus | Tok::Minus) {
                self.eat();
                let right = self.parse_mul()?;
                left = Node::Binary(op, Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Some(left)
    }
    fn parse_mul(&mut self) -> Option<Node> {
        let mut left = self.parse_unary()?;
        while let Some(op) = self.peek().cloned() {
            if matches!(op, Tok::Star | Tok::Slash) {
                self.eat();
                let right = self.parse_unary()?;
                left = Node::Binary(op, Box::new(left), Box::new(right));
            } else {
                break;
            }
        }
        Some(left)
    }
    fn parse_unary(&mut self) -> Option<Node> {
        if self.peek() == Some(&Tok::Minus) {
            self.eat();
            let inner = self.parse_unary()?;
            return Some(Node::Unary(Tok::Minus, Box::new(inner)));
        }
        self.parse_primary()
    }
    fn parse_primary(&mut self) -> Option<Node> {
        match self.eat()? {
            Tok::Num(n) => Some(Node::Num(n)),
            Tok::Str(s) => Some(Node::Str(s)),
            Tok::LParen => {
                let e = self.parse_or()?;
                self.expect(&Tok::RParen)?;
                Some(e)
            }
            Tok::Ident(name) => {
                if self.peek() == Some(&Tok::LParen) {
                    self.eat();
                    let mut args = Vec::new();
                    if self.peek() != Some(&Tok::RParen) {
                        loop {
                            args.push(self.parse_or()?);
                            match self.peek() {
                                Some(&Tok::Comma) => {
                                    self.eat();
                                }
                                _ => break,
                            }
                        }
                    }
                    self.expect(&Tok::RParen)?;
                    Some(Node::Call(name.to_lowercase(), args))
                } else {
                    match name.as_str() {
                        "true" => Some(Node::Bool(true)),
                        "false" => Some(Node::Bool(false)),
                        _ => Some(Node::Var(name)),
                    }
                }
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

fn eval(node: &Node, ctx: &Ctx) -> Val {
    match node {
        Node::Num(n) => Val::Num(*n),
        Node::Str(s) => Val::Str(s.clone()),
        Node::Bool(b) => Val::Bool(*b),
        Node::Var(name) => match name.as_str() {
            "status_code" | "status" => Val::Num(ctx.status_code as f64),
            "body" => Val::Str(ctx.body.to_string()),
            "header" | "all_headers" | "headers" => Val::Str(ctx.headers.to_string()),
            "content_length" => Val::Num(ctx.content_length as f64),
            _ => Val::Str(String::new()),
        },
        Node::Unary(op, inner) => {
            let v = eval(inner, ctx);
            match op {
                Tok::Bang => Val::Bool(!to_bool(&v)),
                Tok::Minus => Val::Num(-to_num(&v)),
                _ => Val::Bool(false),
            }
        }
        Node::Binary(op, l, r) => eval_binary(op, l, r, ctx),
        Node::Call(name, args) => eval_call(name, args, ctx),
    }
}

fn eval_binary(op: &Tok, l: &Node, r: &Node, ctx: &Ctx) -> Val {
    // Short-circuit boolean ops.
    match op {
        Tok::AndAnd => return Val::Bool(to_bool(&eval(l, ctx)) && to_bool(&eval(r, ctx))),
        Tok::OrOr => return Val::Bool(to_bool(&eval(l, ctx)) || to_bool(&eval(r, ctx))),
        _ => {}
    }
    let lv = eval(l, ctx);
    let rv = eval(r, ctx);
    match op {
        Tok::EqEq => Val::Bool(values_eq(&lv, &rv)),
        Tok::NotEq => Val::Bool(!values_eq(&lv, &rv)),
        Tok::Lt => Val::Bool(to_num(&lv) < to_num(&rv)),
        Tok::Le => Val::Bool(to_num(&lv) <= to_num(&rv)),
        Tok::Gt => Val::Bool(to_num(&lv) > to_num(&rv)),
        Tok::Ge => Val::Bool(to_num(&lv) >= to_num(&rv)),
        Tok::Plus => {
            // Numeric add when both look numeric, else string concat.
            if matches!(lv, Val::Num(_)) && matches!(rv, Val::Num(_)) {
                Val::Num(to_num(&lv) + to_num(&rv))
            } else {
                Val::Str(format!("{}{}", to_str(&lv), to_str(&rv)))
            }
        }
        Tok::Minus => Val::Num(to_num(&lv) - to_num(&rv)),
        Tok::Star => Val::Num(to_num(&lv) * to_num(&rv)),
        Tok::Slash => {
            let d = to_num(&rv);
            Val::Num(if d == 0.0 { 0.0 } else { to_num(&lv) / d })
        }
        _ => Val::Bool(false),
    }
}

fn eval_call(name: &str, args: &[Node], ctx: &Ctx) -> Val {
    let a: Vec<Val> = args.iter().map(|n| eval(n, ctx)).collect();
    let s = |i: usize| a.get(i).map(to_str).unwrap_or_default();
    match name {
        "contains" => Val::Bool(s(0).contains(&s(1))),
        "icontains" => Val::Bool(s(0).to_lowercase().contains(&s(1).to_lowercase())),
        "startswith" => Val::Bool(s(0).starts_with(&s(1))),
        "endswith" => Val::Bool(s(0).ends_with(&s(1))),
        "equals_any" | "contains_any" => {
            let hay = s(0);
            Val::Bool(a.iter().skip(1).any(|v| hay.contains(&to_str(v))))
        }
        "contains_all" => {
            let hay = s(0);
            Val::Bool(a.iter().skip(1).all(|v| hay.contains(&to_str(v))))
        }
        "len" => Val::Num(s(0).len() as f64),
        "tolower" => Val::Str(s(0).to_lowercase()),
        "toupper" => Val::Str(s(0).to_uppercase()),
        "trim" => Val::Str(s(0).trim().to_string()),
        "regex" => {
            // regex(pattern, input)
            match Regex::new(&s(0)) {
                Ok(re) => Val::Bool(re.is_match(&s(1))),
                Err(_) => Val::Bool(false),
            }
        }
        "status_code" => Val::Num(ctx.status_code as f64),
        _ => Val::Str(String::new()),
    }
}

fn values_eq(l: &Val, r: &Val) -> bool {
    match (l, r) {
        (Val::Num(_), _) | (_, Val::Num(_)) => (to_num(l) - to_num(r)).abs() < f64::EPSILON,
        (Val::Bool(_), _) | (_, Val::Bool(_)) => to_bool(l) == to_bool(r),
        _ => to_str(l) == to_str(r),
    }
}

fn to_bool(v: &Val) -> bool {
    match v {
        Val::Bool(b) => *b,
        Val::Num(n) => *n != 0.0,
        Val::Str(s) => !s.is_empty() && s != "false",
    }
}

fn to_num(v: &Val) -> f64 {
    match v {
        Val::Num(n) => *n,
        Val::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Val::Str(s) => s.trim().parse().unwrap_or(0.0),
    }
}

fn to_str(v: &Val) -> String {
    match v {
        Val::Str(s) => s.clone(),
        Val::Bool(b) => b.to_string(),
        Val::Num(n) => {
            if n.fract() == 0.0 {
                format!("{}", *n as i64)
            } else {
                format!("{n}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ctx<'a>(status: u16, body: &'a str, headers: &'a str) -> Ctx<'a> {
        Ctx {
            status_code: status,
            body,
            headers,
            content_length: body.len(),
        }
    }

    #[test]
    fn basic() {
        let c = ctx(200, "hello admin world", "Server: nginx");
        assert!(eval_bool("status_code == 200", &c));
        assert!(eval_bool(
            "status_code == 200 && contains(body, \"admin\")",
            &c
        ));
        assert!(!eval_bool("status_code == 404", &c));
        assert!(eval_bool("len(body) > 5", &c));
        assert!(eval_bool("contains(tolower(header), \"nginx\")", &c));
        assert!(eval_bool("regex(\"adm.n\", body)", &c));
        assert!(eval_bool("!contains(body, \"missing\")", &c));
        assert!(eval_bool("status_code >= 200 && status_code < 300", &c));
        assert!(eval_bool("contains_all(body, \"hello\", \"admin\")", &c));
    }
}
