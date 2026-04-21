use core::fmt;
use std::fmt::{Debug, Display, Formatter};

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use console::style;
use serde::Serialize;

static LINE_NUMBER: AtomicUsize = AtomicUsize::new(0);
static QUIET_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_quiet(quiet: bool) {
    QUIET_MODE.store(quiet, Ordering::SeqCst);
}

fn is_quiet() -> bool {
    QUIET_MODE.load(Ordering::SeqCst)
}

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

    format!(
        "{} {:>3} {}",
        style(message_type).dim(),
        style(line_number).dim(),
        style(separator).dim(),
    )
}

fn blank_prefix() -> String {
    " ".repeat(8)
}

pub fn attn(title: &str, message: &str) {
    if is_quiet() { return; }
    eprintln!(
        "\n{} {}\n{} {}",
        line_prefix(ConsoleType::Info),
        style(title).bold(),
        blank_prefix(),
        message
    );
}

pub fn info<T: Display>(message: &str, value: Option<&T>) {
    if is_quiet() { return; }
    match value {
        Some(v) => eprintln!(
            "{} {}: {}",
            line_prefix(ConsoleType::Info),
            message,
            style(v).bold()
        ),
        None => eprintln!("{} {}", line_prefix(ConsoleType::Info), message),
    }
}
pub fn sub_info<T: Display>(message: &str, value: Option<&T>, level: usize) {
    if is_quiet() { return; }
    match value {
        Some(v) => eprintln!(
            "{} |{} {}: {}",
            line_prefix(ConsoleType::Info),
            "-".repeat(level),
            message,
            style(v).bold()
        ),
        None => eprintln!("{} {}", blank_prefix(), message),
    }
}

pub fn error(message: &str) {
    if is_quiet() { return; }
    eprintln!("{} {}", line_prefix(ConsoleType::Error), message);
}

pub fn debug<T: Debug>(message: &str, value: Option<&T>) {
    if is_quiet() || std::env::var("DEBUG").is_err() || std::env::var("DEBUG").unwrap() != "true" {
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
                if !is_quiet() {
                    panic!("Exited due to error");
                }
                std::process::exit(1);
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
                if !is_quiet() {
                    panic!("Exited due to unexpected empty value");
                }
                std::process::exit(1);
            }
        }
    }
}
