# Interactive shell

The interactive shell runs Agent Gateway commands without retyping the `fabric agent-gateway` prefix.

## On this page

| Topic | What it covers |
| --- | --- |
| [Open the shell](#open-the-shell) | Starting and leaving the shell |
| [Set defaults for the session](#set-defaults-for-the-session) | Using one connection or output format for every command |
| [Keys and editing](#keys-and-editing) | History, quoting, and keyboard shortcuts |

## Open the shell

```text
$ fabric agent-gateway shell
Fabric Agent Gateway interactive shell. Type `help` for commands; `exit` or `quit` to leave.
fabric agent-gateway> surfaces list
fabric agent-gateway> surfaces create --name "Sales Agent" --description "Routes sales traffic"
fabric agent-gateway> help
fabric agent-gateway> exit
```

Good to know:

- Type commands without the `fabric agent-gateway` prefix. They use the same parser and options as one-shot commands. A failed command prints its error, and the shell keeps running.
- Type `help` to list commands, and `exit` or `quit` to leave.
- `fabric agent-gateway` with no command prints its help. It doesn't open the shell.

## Set defaults for the session

Global options given when you start the shell become defaults for every command in it:

```sh
fabric agent-gateway --connection production --output json shell
```

You can still override a default on a single command.

## Keys and editing

| Key or feature | What it does |
| --- | --- |
| Quotes | Group an argument that contains spaces, such as `--name "Sales Agent"` |
| History | Recalls commands from the current session |
| Ctrl-C | Cancels the current line |
| Ctrl-D | Exits the shell |

## Related

- [Authentication](AUTHENTICATION.md): saved connections
- [Scripting and output](SCRIPTING_AND_OUTPUT.md): output formats
