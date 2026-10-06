use std::process::ExitCode as ProcessExitCode;

use cec::contract::parse;
use cec::engine;
use cec::types::ExitCode;

fn help_text() -> String {
    cec::contract::help_text()
}

fn main() -> ProcessExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    let options = match parse(&arguments) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("Invalid arguments: {}", error.0);
            eprintln!("{}", help_text());
            return ProcessExitCode::from(ExitCode::Usage as u8);
        }
    };
    if options.help {
        println!("{}", help_text());
        return ProcessExitCode::from(ExitCode::Success as u8);
    }
    ProcessExitCode::from(engine::run(&options) as u8)
}
