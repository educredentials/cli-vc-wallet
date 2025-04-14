use core::fmt;
use std::fmt::{Debug, Display, Formatter};

use lazy_static::lazy_static;
use std::sync::atomic::{AtomicUsize, Ordering};

use console::style;

pub trait Output<T: Debug> {
    fn info(&self, message: &str, value: Option<&T>);
    fn error(&self, message: &str);
    fn debug(&self, message: &str, value: Option<&T>);
}

static LINE_NUMBER: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    static ref LOGGER: ConsoleOutput = ConsoleOutput::new();
}

pub fn logger() -> &'static ConsoleOutput {
    &LOGGER
}

pub struct ConsoleOutput {}

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

impl ConsoleOutput {
    pub fn new() -> Self {
        Self {}
    }

    fn line_prefix(&self, message_type: ConsoleType) -> String {
        let line_number = LINE_NUMBER.fetch_add(1, Ordering::SeqCst) + 1;
        let separator = "│";

        return format!(
            "{} {:>3} {}",
            style(message_type).dim(),
            style(line_number).dim(),
            style(separator).dim(),
        );
    }
    fn blank_prefix(&self) -> String {
        return " ".repeat(8);
    }

    pub fn attn(&self, title: &str, message: &str) {
        println!(
            "\n{} {}\n{} {}",
            self.line_prefix(ConsoleType::Info),
            style(title).bold(),
            self.blank_prefix(),
            message
        );
    }
}

impl<T: Debug> Output<T> for ConsoleOutput {
    fn info(&self, message: &str, value: Option<&T>) {
        match value {
            Some(v) => println!(
                "{} {}: {:?}",
                self.line_prefix(ConsoleType::Info),
                message,
                v
            ),
            None => println!("{} {}", self.line_prefix(ConsoleType::Info), message),
        }
    }

    fn error(&self, message: &str) {
        eprintln!("{} {}", self.line_prefix(ConsoleType::Error), message);
    }

    fn debug(&self, message: &str, value: Option<&T>) {
        // TODO: Filter debug unless the DEBUG environment variable is set or logging set to debug

        match value {
            Some(v) => println!(
                "{} {}: {:#?}",
                self.line_prefix(ConsoleType::Debug),
                message,
                v
            ),
            None => println!("{} {}", self.line_prefix(ConsoleType::Debug), message),
        }
    }
}

pub trait LogExpect<T, E: Debug> {
    fn log_expect(self, msg: &str) -> T;
}

impl<T: Debug, E: Debug> LogExpect<T, E> for Result<T, E> {
    fn log_expect(self, msg: &str) -> T {
        match self {
            Ok(value) => value,
            Err(err) => {
                <ConsoleOutput as Output<T>>::error(
                    logger(),
                    format!("{}: {:?}", msg, err).as_str(),
                );
                panic!("Exited due to error");
            }
        }
    }
}

impl<T: Debug> LogExpect<T, T> for Option<T> {
    fn log_expect(self, msg: &str) -> T {
        match self {
            Some(value) => value,
            None => {
                <ConsoleOutput as Output<T>>::error(logger(), msg);
                panic!("Exited due to unexpected empty value");
            }
        }
    }
}
