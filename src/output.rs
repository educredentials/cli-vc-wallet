use core::fmt;
use std::fmt::{Debug, Display, Formatter};

use std::sync::atomic::{AtomicUsize, Ordering};

use console::style;
use serde::Serialize;

static LINE_NUMBER: AtomicUsize = AtomicUsize::new(0);

enum ConsoleType {
    Info,
    Error,
    Debug,
}

impl Display for ConsoleType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let message_type = match self {
            ConsoleType::Info => " I",
            ConsoleType::Error => "!E",
            ConsoleType::Debug => " D",
        };
        write!(f, "{}", message_type)
    }
}

fn line_prefix(message_type: ConsoleType) -> String {
    let line_number = LINE_NUMBER.fetch_add(1, Ordering::SeqCst) + 1;
    let separator = "│";

    return format!(
        "{} {:>3} {}",
        style(message_type).dim(),
        style(line_number).dim(),
        style(separator).dim(),
    );
}

fn blank_prefix() -> String {
    return " ".repeat(8);
}

pub fn attn(title: &str, message: &str) {
    eprintln!(
        "\n{} {}\n{} {}",
        line_prefix(ConsoleType::Info),
        style(title).bold(),
        blank_prefix(),
        message
    );
}

pub fn info<T: Display>(message: &str, value: Option<&T>) {
    match value {
        Some(v) => eprintln!("{} {}: {}", line_prefix(ConsoleType::Info), message, v),
        None => eprintln!("{} {}", line_prefix(ConsoleType::Info), message),
    }
}

pub fn error(message: &str) {
    eprintln!("{} {}", line_prefix(ConsoleType::Error), message);
}

pub fn debug<T: Debug>(message: &str, value: Option<&T>) {
    if std::env::var("DEBUG").is_err() || std::env::var("DEBUG").unwrap() != "true" {
        return;
    }

    match value {
        Some(v) => eprintln!("{} {}: {:#?}", line_prefix(ConsoleType::Debug), message, v,),
        None => eprintln!("{} {}", line_prefix(ConsoleType::Debug), message),
    }
}

pub fn stdout<T: Serialize>(value: T) {
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
}

pub trait LogExpect<T> {
    fn log_expect(self, msg: &str) -> T;
}

impl<T, E: Debug> LogExpect<T> for Result<T, E> {
    fn log_expect(self, msg: &str) -> T {
        match self {
            Ok(value) => value,
            Err(err) => {
                error(format!("{}: {:?}", msg, err).as_str());
                panic!("Exited due to error");
            }
        }
    }
}

impl<T> LogExpect<T> for Option<T> {
    fn log_expect(self, msg: &str) -> T {
        match self {
            Some(value) => value,
            None => {
                error(msg);
                panic!("Exited due to unexpected empty value");
            }
        }
    }
}
