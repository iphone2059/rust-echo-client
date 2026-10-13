use std::process::ExitCode as ProcessExitCode;

use cec::contract::parse_native;
use cec::engine;
use cec::types::ExitCode;

fn main() -> ProcessExitCode {
    let arguments = match cec::native::NativeArguments::current() {
        Ok(arguments) => arguments,
        Err(error) => {
            cec::native::write_stderr(format_args!("{error}\n"));
            return ProcessExitCode::from(ExitCode::Network as u8);
        }
    };
    let options = match parse_native(&arguments) {
        Ok(options) => options,
        Err(error) => {
            cec::native::write_stderr(format_args!(
                "Invalid arguments: {}\n{}",
                error.0,
                cec::contract::help_text()
            ));
            return ProcessExitCode::from(ExitCode::Usage as u8);
        }
    };
    if options.help {
        cec::native::write_stdout(format_args!("{}", cec::contract::help_text()));
        return ProcessExitCode::from(ExitCode::Success as u8);
    }
    ProcessExitCode::from(engine::run(&options) as u8)
}
