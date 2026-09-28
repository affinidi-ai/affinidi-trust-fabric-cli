use anyhow::Result;
use clap::{CommandFactory, Parser, error::ErrorKind};
use rustyline::{DefaultEditor, error::ReadlineError};

use crate::commands::{Cli, run as run_command};

pub async fn run(initial: Cli) -> Result<()> {
    let prefix = initial.interactive_prefix();
    let mut editor = DefaultEditor::new()?;

    println!("Fabric Agent Gateway interactive shell. Type `help` for commands; `exit` or `quit` to leave.");
    loop {
        match editor.readline("fabric agent-gateway> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if matches!(line, "exit" | "quit") {
                    break;
                }
                editor.add_history_entry(line)?;
                match parse_line(&prefix, line) {
                    Ok(cli) if cli.is_interactive() => {
                        eprintln!("already in the interactive shell; type a command such as `surfaces list`");
                    }
                    Ok(mut cli) => {
                        if cli.login_wants_paste_prompt() {
                            match editor.readline("Gateway bearer token: ") {
                                Ok(entry) => {
                                    let token = entry.trim().to_owned();
                                    if token.is_empty() {
                                        eprintln!("error: bearer token must not be empty");
                                        continue;
                                    }
                                    cli.set_login_token(token);
                                }
                                Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                                    eprintln!("login cancelled");
                                    continue;
                                }
                                Err(error) => {
                                    eprintln!("error: {error}");
                                    continue;
                                }
                            }
                        }
                        if let Err(error) = run_command(cli).await {
                            eprintln!("error: {error:#}");
                        }
                    }
                    Err(error) if matches!(error.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) => {
                        print!("{error}");
                    }
                    Err(error) => eprint!("{error}"),
                }
            }
            Err(ReadlineError::Interrupted) => println!(),
            Err(ReadlineError::Eof) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn parse_line(
    prefix: &[String],
    line: &str,
) -> Result<Cli, clap::Error> {
    let words = shell_words::split(line).map_err(|error| Cli::command().error(ErrorKind::InvalidValue, error))?;
    Cli::try_parse_from(
        prefix
            .iter()
            .cloned()
            .chain(words),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell_prefix() -> Vec<String> {
        Cli::try_parse_from(["fabric", "agent-gateway", "shell"])
            .expect("shell should parse")
            .interactive_prefix()
    }

    #[test]
    fn parses_interactive_commands_with_quoted_arguments() {
        let cli = parse_line(&shell_prefix(), "surfaces create --name 'Sales Agent'").unwrap();
        assert!(!cli.is_interactive());
    }

    #[test]
    fn later_command_options_override_shell_defaults() {
        let cli = parse_line(&shell_prefix(), "surfaces list --output json").unwrap();
        assert!(!cli.is_interactive());
    }

    #[test]
    fn prefix_names_the_appliance_and_keeps_startup_flags() {
        let cli = Cli::try_parse_from(["fabric", "agent-gateway", "--connection", "production", "shell"])
            .expect("shell should accept global flags");
        assert_eq!(
            cli.interactive_prefix(),
            ["fabric", "agent-gateway", "--connection", "production", "--output", "table"]
        );
    }

    #[test]
    fn shell_typed_inside_the_shell_is_recognised() {
        let cli = parse_line(&shell_prefix(), "shell").unwrap();
        assert!(cli.is_interactive());
    }

    #[test]
    fn help_inside_the_shell_describes_agent_gateway() {
        let error = parse_line(&shell_prefix(), "help").expect_err("help is reported as a clap error");
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("fabric agent-gateway"), "{help}");
        assert!(help.contains("surfaces"), "{help}");
    }
}
