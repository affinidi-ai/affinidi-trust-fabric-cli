//! `fabric agent-stream prompts`: the prompt templates of an Agent Stream.
//!
//! A template keeps its numbered versions inside one document, and Agent
//! Stream has no route for a single version and no version check, so every
//! change reads the template, changes it on this machine, reads it again to
//! stop if it was saved meanwhile, and sends the whole template back.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Subcommand, ValueEnum};
use reqwest::Method;
use serde_json::{Map, Value, json};

use crate::{
    client::{GatewayClient, pretty_json_for_terminal, sanitize_for_terminal, sanitize_multiline},
    commands::{Output, confirmation_line, entity_path, print_list, print_outcome, read_json},
    surface_validate,
    tables::{self, Scope},
};

/// Where Agent Stream serves its prompt templates.
const PROMPTS_PATH: &str = "/v1/prompts";

/// Longest template id Agent Stream accepts.
const MAX_ID_LEN: usize = 128;

/// The top-level fields of an Agent Stream prompt template, as Agent Stream
/// stores and returns it.
const PROMPT_FIELDS: [&str; 10] = [
    "id",
    "name",
    "description",
    "status",
    "tenant_id",
    "test_fixture",
    "versions",
    "default_version",
    "created_at",
    "updated_at",
];

/// The fields of one version of a template.
const VERSION_FIELDS: [&str; 4] = ["version", "messages", "label", "created_at"];

/// The fields of one message of a version.
const MESSAGE_FIELDS: [&str; 2] = ["role", "content"];

/// The fields of an `update --file` document that are replaced with the
/// stored ones, because Agent Stream keeps its own.
const KEPT_FROM_STORED: [&str; 3] = ["created_at", "updated_at", "tenant_id"];

/// The end of a dry run in table output.
const DRY_RUN_NOTE: &str = "\nDry run: nothing was saved.";

#[derive(Debug, Subcommand)]
pub enum PromptCommand {
    /// List prompt templates.
    ///
    /// Shows each template's id, name, status, version numbers, default
    /// version, and when it was last saved, never its messages. --output json
    /// prints each template as Agent Stream sent it, with the messages of
    /// every version left out; read them with `prompts get`. Agent Stream
    /// lists enabled templates only, so a disabled one is left out too.
    #[command(after_long_help = LIST_EXAMPLES)]
    List,
    /// Get a prompt template by id, as the whole JSON document Agent Stream
    /// keeps, messages included.
    ///
    /// A disabled template is returned too.
    #[command(after_long_help = GET_EXAMPLES)]
    Get {
        /// Id of the template (see `fabric agent-stream prompts list`).
        id: String,
    },
    /// Create a prompt template from flags or a complete JSON document.
    ///
    /// With flags, --id, --name, and at least one --message are required.
    /// Each --message adds one message, in order, to version 1, which becomes
    /// the default version. With --file, the document is sent as it is.
    ///
    /// Before anything is sent, the CLI checks the template as Agent Stream
    /// would: an id of letters, digits, `-`, and `_`, up to 128 characters; a
    /// name; at least one version, and no two with one number; at least one
    /// message in each version, each with a role; a default version that exists; and only
    /// field names Agent Stream knows.
    ///
    /// --dry-run prints the template and sends nothing, so it needs no saved
    /// login; with --output json it prints the same preview as `update
    /// --dry-run`. Table output prints the new template's id; --output json
    /// prints the template Agent Stream answered with.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(CreateArgs),
    /// Change a template's name, description, or status, or replace it with
    /// a JSON document.
    ///
    /// The CLI reads the template, applies the change on this machine, and
    /// checks it. It then reads the template again, stops if it was saved
    /// meanwhile, and otherwise sends the whole template. Agent Stream has no
    /// version check, so a save that lands in the short gap between that last
    /// read and the send is still overwritten. A change that leaves the
    /// template as it is sends nothing.
    ///
    /// --file replaces the whole template, versions included, so a version
    /// left out of it is removed; a file with no versions is refused. It must hold the `updated_at` the template
    /// has now, so start it from `prompts get`; a copy read before another
    /// save is refused. Its `created_at`, `updated_at`, and `tenant_id` are
    /// replaced with the stored ones.
    ///
    /// Table output lists each changed field; --output json prints the
    /// template as Agent Stream has it after the save. --dry-run shows the
    /// changes, or with --output json the changes and the whole new template,
    /// and saves nothing.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update(UpdateArgs),
    /// Delete a prompt template.
    ///
    /// Requests that name the template are refused from then on, and there
    /// is no confirmation prompt. A template with the same id can be created
    /// again later.
    #[command(after_long_help = DELETE_EXAMPLES)]
    Delete {
        /// Id of the template (see `fabric agent-stream prompts list`).
        id: String,
    },
    /// Add a version to a template.
    ///
    /// The version's messages come from --message flags, in order, or from
    /// --file, a JSON object with `messages` and optionally `label` and
    /// `version`. Its number is --version, else the file's `version`, else one
    /// more than the highest version; a number the template already has is
    /// refused, so an existing version is never overwritten.
    ///
    /// Callers that name no version get the default version. --make-default
    /// makes the new version the default. Without it, the default stays as
    /// it is; when the template has no `default_version`, which means callers
    /// get the highest version, the CLI sets `default_version` to the
    /// version they get now, so the new version does not reach them.
    ///
    /// The save works as `prompts update` does, --dry-run included.
    #[command(after_long_help = ADD_VERSION_EXAMPLES)]
    AddVersion(AddVersionArgs),
    /// Set the version callers get when they name no version.
    ///
    /// This is how a template is rolled back: set the default to an earlier
    /// version. It changes what every caller that names no version gets, on
    /// their next request. The save works as `prompts update` does, --dry-run
    /// included.
    #[command(after_long_help = SET_DEFAULT_EXAMPLES)]
    SetDefault(SetDefaultArgs),
    /// Remove a version from a template.
    ///
    /// The version callers get by default can't be removed: the
    /// `default_version`, or the highest version when the template has none.
    /// Set another default first. The last version can't be removed either;
    /// delete the template instead. Agent Stream keeps no copy of a removed
    /// version. The save works as `prompts update` does, --dry-run included.
    #[command(after_long_help = REMOVE_VERSION_EXAMPLES)]
    RemoveVersion(RemoveVersionArgs),
    /// Show the messages a template gives for some variables, without calling
    /// a model.
    ///
    /// Agent Stream fills each `{{name}}` placeholder from the variables and
    /// returns the messages, with the names of the variables the version
    /// uses. A missing variable is refused, with all the missing names. Table
    /// output prints each message's role and content; --output json prints
    /// Agent Stream's answer. A disabled template can't be rendered.
    #[command(after_long_help = RENDER_EXAMPLES)]
    Render(RenderArgs),
}

/// Examples shown at the bottom of `prompts list --help`.
const LIST_EXAMPLES: &str = r#"Examples:
  List templates:
    fabric agent-stream prompts list

  Print the ids for a script:
    fabric agent-stream prompts list --output json | jq -r '.[].id'"#;

/// Examples shown at the bottom of `prompts get --help`.
const GET_EXAMPLES: &str = r#"Examples:
  Show a template, messages included:
    fabric agent-stream prompts get support-greeter

  Keep a copy to edit or to restore later:
    fabric agent-stream prompts get support-greeter > template.json"#;

/// Examples shown at the bottom of `prompts delete --help`.
const DELETE_EXAMPLES: &str = r#"Examples:
  Keep a copy, then delete the template:
    fabric agent-stream prompts get support-greeter > template.json
    fabric agent-stream prompts delete support-greeter"#;

/// Examples shown at the bottom of `prompts set-default --help`.
const SET_DEFAULT_EXAMPLES: &str = r#"Examples:
  Roll callers back to version 1, after a dry run:
    fabric agent-stream prompts set-default support-greeter 1 --dry-run
    fabric agent-stream prompts set-default support-greeter 1"#;

/// Examples shown at the bottom of `prompts remove-version --help`.
const REMOVE_VERSION_EXAMPLES: &str = r#"Examples:
  Remove version 2, which is not the default:
    fabric agent-stream prompts remove-version support-greeter 2"#;

/// Examples shown at the bottom of `prompts create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Create a template from text files, one per message:
    fabric agent-stream prompts create --id support-greeter \
      --name "Support greeter" \
      --message system=system.txt --message user=user.txt

  Check a JSON document without sending it, then create it:
    fabric agent-stream prompts create --file template.json --dry-run
    fabric agent-stream prompts create --file template.json"#;

/// Examples shown at the bottom of `prompts update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Disable a template:
    fabric agent-stream prompts update support-greeter --status disabled

  Edit the whole document:
    fabric agent-stream prompts get support-greeter > template.json
    fabric agent-stream prompts update support-greeter --file template.json --dry-run
    fabric agent-stream prompts update support-greeter --file template.json"#;

/// Examples shown at the bottom of `prompts add-version --help`.
const ADD_VERSION_EXAMPLES: &str = r#"Examples:
  Add a version from text files, without changing the default:
    fabric agent-stream prompts add-version support-greeter \
      --message system=system-v2.txt --message user=user.txt --label shorter

  Add a version and make it the default, after a dry run:
    fabric agent-stream prompts add-version support-greeter --file v3.json \
      --make-default --dry-run"#;

/// Examples shown at the bottom of `prompts render --help`.
const RENDER_EXAMPLES: &str = r#"Examples:
  Render the default version:
    fabric agent-stream prompts render support-greeter --var product=Widgets

  Render version 2 with variables from a JSON file:
    fabric agent-stream prompts render support-greeter --version 2 \
      --vars-file variables.json"#;

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("source").required(true).args(["file", "id"])))]
pub struct CreateArgs {
    /// Id of the new template, which requests name it by: letters, digits,
    /// `-`, and `_`, up to 128 characters.
    #[arg(long, requires_all = ["name", "message"], conflicts_with = "file")]
    id: Option<String>,
    /// Display name of the template.
    #[arg(long, conflicts_with = "file")]
    name: Option<String>,
    /// What the template is for.
    #[arg(long, conflicts_with = "file")]
    description: Option<String>,
    /// One message of version 1: its role and a text file holding its
    /// content, such as `system=system.txt`. The file is read as UTF-8, and
    /// one line break at its end is dropped. Repeat for each message, in
    /// order.
    #[arg(long, value_name = "ROLE=FILE", conflicts_with = "file")]
    message: Vec<String>,
    /// Label of version 1.
    #[arg(long, conflicts_with = "file")]
    label: Option<String>,
    /// JSON document of the template, or - for standard input.
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Print the template that would be sent, or with --output json the
    /// preview `update --dry-run` prints, and send nothing. Needs no saved
    /// login.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("change").required(true).multiple(true).args(["file", "name", "description", "status"])))]
pub struct UpdateArgs {
    /// Id of the template (see `fabric agent-stream prompts list`).
    id: String,
    /// New display name.
    #[arg(long)]
    name: Option<String>,
    /// New description.
    #[arg(long)]
    description: Option<String>,
    /// New status. A disabled template is left out of `prompts list` and
    /// can't be used or rendered. Use `prompts delete` to delete one.
    #[arg(long, value_enum)]
    status: Option<Status>,
    /// Complete template JSON that replaces the stored template, or - for
    /// standard input. Start from a fresh `prompts get`.
    #[arg(short, long, conflicts_with_all = ["name", "description", "status"])]
    file: Option<PathBuf>,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("messages").required(true).args(["file", "message"])))]
pub struct AddVersionArgs {
    /// Id of the template (see `fabric agent-stream prompts list`).
    id: String,
    /// One message of the new version: its role and a text file holding its
    /// content, such as `user=user.txt`. The file is read as UTF-8, and one
    /// line break at its end is dropped. Repeat for each message, in order.
    #[arg(long, value_name = "ROLE=FILE")]
    message: Vec<String>,
    /// JSON object of the new version, with `messages` and optionally
    /// `label` and `version`, or - for standard input.
    #[arg(short, long, conflicts_with = "message")]
    file: Option<PathBuf>,
    /// Number of the new version. Defaults to the file's `version`, else one
    /// more than the highest version.
    #[arg(long)]
    version: Option<u32>,
    /// Label of the new version, in place of any label in --file.
    #[arg(long)]
    label: Option<String>,
    /// Make the new version the one callers get when they name no version.
    #[arg(long)]
    make_default: bool,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct SetDefaultArgs {
    /// Id of the template (see `fabric agent-stream prompts list`).
    id: String,
    /// The version callers get when they name none.
    version: u32,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct RemoveVersionArgs {
    /// Id of the template (see `fabric agent-stream prompts list`).
    id: String,
    /// The version to remove.
    version: u32,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct RenderArgs {
    /// Id of the template (see `fabric agent-stream prompts list`).
    id: String,
    /// Version to render. Defaults to the version callers get when they name
    /// none.
    #[arg(long)]
    version: Option<u32>,
    /// A variable, as `name=value`; the value is used as text. Repeatable,
    /// and given after --vars-file, so it wins over the same name there.
    #[arg(long = "var", value_name = "NAME=VALUE")]
    vars: Vec<String>,
    /// JSON object of variables, or - for standard input. A value that is not
    /// text is filled in as its JSON.
    #[arg(long)]
    vars_file: Option<PathBuf>,
}

/// The statuses `prompts update --status` can set.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Status {
    Enabled,
    Disabled,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

/// Runs one `prompts` command. `connect` gives the client of the Agent Stream
/// to talk to, and is only called for a command that sends something, so
/// `create --dry-run` needs no saved login.
pub async fn run(
    command: PromptCommand,
    output: Output,
    connect: impl AsyncFnOnce() -> Result<GatewayClient>,
) -> Result<()> {
    let command = match command {
        PromptCommand::Create(args) if args.dry_run => {
            let template = create_body(args)?;
            println!("{}", preview_create(&template, output)?);
            if let Output::Table = output {
                eprintln!("Dry run: nothing was sent.");
            }
            return Ok(());
        }
        command => command,
    };
    let client = connect().await?;
    match command {
        PromptCommand::List => {
            let templates = client
                .request(Method::GET, PROMPTS_PATH, None)
                .await?;
            let shown = match output {
                Output::Table => list_rows(&templates)?,
                Output::Json => without_messages(&templates)?,
            };
            print_list(&shown, output, &tables::AGENT_STREAM_PROMPTS, Scope::All)
        }
        PromptCommand::Get { id } => {
            let template = read_template(&client, &id).await?;
            println!("{}", pretty_json_for_terminal(&template)?);
            Ok(())
        }
        PromptCommand::Create(args) => {
            let template = create_body(args)?;
            let id = text_field(&template, "id").to_owned();
            let answer = client
                .request(Method::POST, PROMPTS_PATH, Some(template))
                .await?;
            print_outcome(&answer, output, &confirmation_line("Created", "prompt template", &id))
        }
        PromptCommand::Update(args) => {
            let before = read_template(&client, &args.id).await?;
            let after = updated(&before, &args)?;
            save(&client, &args.id, &before, after, args.dry_run, output).await
        }
        PromptCommand::Delete { id } => {
            let answer = client
                .request(Method::DELETE, &template_path(&id)?, None)
                .await?;
            print_outcome(&answer, output, &confirmation_line("Deleted", "prompt template", &id))
        }
        PromptCommand::AddVersion(args) => {
            let version = new_version(&args)?;
            let before = read_template(&client, &args.id).await?;
            let after = with_version(&before, version, args.make_default)?;
            save(&client, &args.id, &before, after, args.dry_run, output).await
        }
        PromptCommand::SetDefault(args) => {
            let before = read_template(&client, &args.id).await?;
            let after = with_default(&before, args.version)?;
            save(&client, &args.id, &before, after, args.dry_run, output).await
        }
        PromptCommand::RemoveVersion(args) => {
            let before = read_template(&client, &args.id).await?;
            let after = without_version(&before, args.version)?;
            save(&client, &args.id, &before, after, args.dry_run, output).await
        }
        PromptCommand::Render(args) => render(&client, args, output).await,
    }
}

/// The API path of the template `id`, once `id` follows Agent Stream's rules.
fn template_path(id: &str) -> Result<String> {
    check_id(id)?;
    Ok(entity_path(PROMPTS_PATH, id))
}

/// Refuses an id Agent Stream would refuse: empty, longer than
/// [`MAX_ID_LEN`], or holding anything but ASCII letters, digits, `-` and `_`.
fn check_id(id: &str) -> Result<()> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    if id.is_empty() || id.len() > MAX_ID_LEN || !id.chars().all(allowed) {
        bail!("template id '{}' must be 1 to {MAX_ID_LEN} letters, digits, '-', or '_'", sanitize_for_terminal(id));
    }
    Ok(())
}

/// Reads the template `id` as Agent Stream has it now.
async fn read_template(
    client: &GatewayClient,
    id: &str,
) -> Result<Value> {
    let template = client
        .request(Method::GET, &template_path(id)?, None)
        .await?;
    if !template.is_object() {
        bail!("Agent Stream did not answer with a prompt template for '{id}'");
    }
    Ok(template)
}

/// The template `prompts create` sends: the --file document, or one built
/// from the flags, checked as Agent Stream would check it.
fn create_body(args: CreateArgs) -> Result<Value> {
    let template = match args.file {
        Some(file) => read_json(&file)?,
        None => {
            let (Some(id), Some(name)) = (args.id, args.name) else {
                bail!("--id and --name are required unless --file is given");
            };
            let mut version = json!({ "version": 1, "messages": messages_from_files(&args.message)? });
            if let Some(label) = args.label {
                version["label"] = Value::String(label);
            }
            let mut template = json!({ "id": id, "name": name, "versions": [version], "default_version": 1 });
            if let Some(description) = args.description {
                template["description"] = Value::String(description);
            }
            template
        }
    };
    check_template(&template, None)?;
    Ok(template)
}

/// The --output json, or table output, of `create --dry-run`.
fn preview_create(
    template: &Value,
    output: Output,
) -> Result<String> {
    match output {
        Output::Table => pretty_json_for_terminal(template),
        Output::Json => {
            let changes = template_changes(&json!({}), template);
            pretty_json_for_terminal(&preview_document(&changes, template))
        }
    }
}

/// The messages of `--message ROLE=FILE` flags, in order, each file read as
/// UTF-8 text with one line break at its end dropped.
fn messages_from_files(flags: &[String]) -> Result<Vec<Value>> {
    flags
        .iter()
        .map(|flag| {
            let (role, file) = flag
                .split_once('=')
                .filter(|(role, file)| !role.trim().is_empty() && !file.is_empty())
                .with_context(|| format!("--message '{}' must be ROLE=FILE", sanitize_for_terminal(flag)))?;
            let content = read_text(Path::new(file))?;
            Ok(json!({ "role": role.trim(), "content": content }))
        })
        .collect()
}

/// The text of `path`, with one line break at its end dropped, since editors
/// add one the author did not mean as part of the prompt.
fn read_text(path: &Path) -> Result<String> {
    let mut text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    Ok(text)
}

/// The template `prompts update` would save: `before` with the flags applied,
/// or the --file document with the fields Agent Stream keeps put back.
fn updated(
    before: &Value,
    args: &UpdateArgs,
) -> Result<Value> {
    if let Some(file) = &args.file {
        return replacement(read_json(file)?, before, &args.id);
    }
    let mut after = before.clone();
    if let Some(name) = &args.name {
        after["name"] = Value::String(name.clone());
    }
    if let Some(description) = &args.description {
        after["description"] = Value::String(description.clone());
    }
    if let Some(status) = args.status {
        after["status"] = Value::String(status.as_str().to_owned());
    }
    Ok(after)
}

/// The --file document of `update`, refused when it names another template
/// or was read before the stored template was last saved, with the fields
/// Agent Stream keeps set back to the stored ones.
fn replacement(
    mut document: Value,
    before: &Value,
    id: &str,
) -> Result<Value> {
    let Some(fields) = document.as_object_mut() else {
        bail!("the --file document must be a JSON object");
    };
    match fields
        .get("id")
        .filter(|value| !value.is_null())
    {
        None => {
            fields.insert("id".to_owned(), Value::String(id.to_owned()));
        }
        Some(Value::String(given)) if given == id => {}
        Some(other) => {
            bail!("the --file document is for template {}, not '{id}'", sanitize_for_terminal(&other.to_string()))
        }
    }
    if present(fields.get("updated_at")) != present(before.get("updated_at")) {
        bail!(
            "the --file document's updated_at does not match template '{id}' as stored, so it was read before \
             another save or is not from `prompts get`; start again from `fabric agent-stream prompts get {id}`"
        );
    }
    for field in KEPT_FROM_STORED {
        match before.get(field) {
            Some(value) => fields.insert(field.to_owned(), value.clone()),
            None => fields.remove(field),
        };
    }
    Ok(document)
}

/// The version `add-version` adds, from --message flags or --file, with
/// --version and --label applied. Its number is left out when neither the
/// flag nor the file gives one.
fn new_version(args: &AddVersionArgs) -> Result<Map<String, Value>> {
    let mut version = match &args.file {
        Some(file) => match read_json(file)? {
            Value::Object(version) => version,
            _ => bail!("the --file document must be a JSON object with `messages`"),
        },
        None => {
            let mut version = Map::new();
            version.insert("messages".to_owned(), Value::Array(messages_from_files(&args.message)?));
            version
        }
    };
    if let Some(number) = args.version {
        version.insert("version".to_owned(), json!(number));
    }
    if let Some(label) = &args.label {
        version.insert("label".to_owned(), Value::String(label.clone()));
    }
    Ok(version)
}

/// `before` with `version` added, numbered one more than the highest version
/// when it has no number. A number already in use is refused. The default
/// version moves to the new one with `make_default`; otherwise, a template
/// with no `default_version` gets the one callers get now, so they keep it.
fn with_version(
    before: &Value,
    mut version: Map<String, Value>,
    make_default: bool,
) -> Result<Value> {
    let numbers = version_numbers(before)?;
    let number = match version.get("version") {
        None => {
            let next = numbers
                .last()
                .map_or(Some(1), |highest| highest.checked_add(1))
                .context("the template's highest version number has no next number")?;
            version.insert("version".to_owned(), json!(next));
            next
        }
        Some(value) => as_version_number(value).context("the new version's `version` must be a whole number")?,
    };
    if numbers.contains(&number) {
        bail!("template already has version {number}; give another --version, or remove that version first");
    }
    let current_default = effective_default(before)?;
    let mut after = before.clone();
    let versions = after
        .as_object_mut()
        .context("the template is not a JSON object")?
        .entry("versions")
        .or_insert_with(|| Value::Array(Vec::new()));
    versions
        .as_array_mut()
        .context("the template's `versions` is not a list")?
        .push(Value::Object(version));
    if make_default {
        after["default_version"] = json!(number);
    } else if before
        .get("default_version")
        .is_none_or(Value::is_null)
        && let Some(current) = current_default
    {
        eprintln!(
            "note: the template has no default_version, so callers get its highest version; this change sets \
             default_version to {current} so they keep it. Use --make-default to give them version {number}."
        );
        after["default_version"] = json!(current);
    }
    Ok(after)
}

/// `before` with `default_version` set to `number`, which must be a version
/// it has.
fn with_default(
    before: &Value,
    number: u32,
) -> Result<Value> {
    if !version_numbers(before)?.contains(&number) {
        bail!("template has no version {number}");
    }
    let mut after = before.clone();
    after["default_version"] = json!(number);
    Ok(after)
}

/// `before` without version `number`. Refused for a version it lacks, the
/// version callers get by default, and its last version.
fn without_version(
    before: &Value,
    number: u32,
) -> Result<Value> {
    let numbers = version_numbers(before)?;
    if !numbers.contains(&number) {
        bail!("template has no version {number}");
    }
    if effective_default(before)? == Some(number) {
        bail!(
            "version {number} is the one callers get when they name no version; set another with `prompts \
             set-default` first"
        );
    }
    if numbers.len() == 1 {
        bail!("version {number} is the template's last version; delete the template instead");
    }
    let mut after = before.clone();
    if let Some(versions) = after
        .get_mut("versions")
        .and_then(Value::as_array_mut)
    {
        versions.retain(|version| {
            version
                .get("version")
                .and_then(as_version_number)
                != Some(number)
        });
    }
    Ok(after)
}

/// The version numbers of `template`, in order. A version without a whole
/// number is refused.
fn version_numbers(template: &Value) -> Result<Vec<u32>> {
    let mut numbers = versions_of(template)
        .iter()
        .map(|version| {
            version
                .get("version")
                .and_then(as_version_number)
                .context("a version of the template has no whole-number `version`")
        })
        .collect::<Result<Vec<u32>>>()?;
    numbers.sort_unstable();
    Ok(numbers)
}

/// The version a caller that names none gets: `default_version`, else the
/// highest version, as Agent Stream picks it.
fn effective_default(template: &Value) -> Result<Option<u32>> {
    match template
        .get("default_version")
        .filter(|value| !value.is_null())
    {
        Some(value) => as_version_number(value)
            .map(Some)
            .context("the template's `default_version` is not a whole number"),
        None => Ok(version_numbers(template)?
            .last()
            .copied()),
    }
}

/// A field's value, with `null` counted as absent.
fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

fn versions_of(template: &Value) -> &[Value] {
    template
        .get("versions")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn as_version_number(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
}

fn text_field<'a>(
    value: &'a Value,
    field: &str,
) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// Refuses a template Agent Stream would refuse, or would save without a
/// field it does not know: Agent Stream drops an unknown field without an
/// error, so a mistyped name would be lost. A field name the `stored`
/// template already has counts as known too, at the same level, for a field
/// a newer Agent Stream added.
fn check_template(
    template: &Value,
    stored: Option<&Value>,
) -> Result<()> {
    let Some(fields) = template.as_object() else {
        bail!("a prompt template must be a JSON object");
    };
    let stored_versions = stored.map_or(&[][..], versions_of);
    let stored_messages: Vec<&Value> = stored_versions
        .iter()
        .flat_map(|version| {
            version
                .get("messages")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
        })
        .collect();
    let template_known = known_names(&PROMPT_FIELDS, stored.into_iter());
    let version_known = known_names(&VERSION_FIELDS, stored_versions.iter());
    let message_known = known_names(&MESSAGE_FIELDS, stored_messages.into_iter());
    check_fields(fields, &template_known, "the template")?;
    match fields.get("id") {
        Some(Value::String(id)) => check_id(id)?,
        _ => bail!("the template needs an `id`"),
    }
    if text_field(template, "name")
        .trim()
        .is_empty()
    {
        bail!("the template needs a `name` that is not blank");
    }
    match fields
        .get("status")
        .filter(|value| !value.is_null())
    {
        None => {}
        Some(Value::String(status)) if status == "enabled" || status == "disabled" => {}
        Some(Value::String(status)) if status == "deleted" => {
            bail!("a template can't be saved as deleted; use `fabric agent-stream prompts delete`")
        }
        Some(other) => bail!(
            "the template's `status` must be \"enabled\" or \"disabled\", not {}",
            sanitize_for_terminal(&other.to_string())
        ),
    }
    if fields
        .get("versions")
        .is_some_and(|versions| !versions.is_array())
    {
        bail!("the template's `versions` must be a list");
    }
    if versions_of(template).is_empty() {
        bail!(
            "the template needs at least one version; to remove every version, delete the template with `fabric \
             agent-stream prompts delete`"
        );
    }
    let mut seen = BTreeSet::new();
    for version in versions_of(template) {
        let Some(version_fields) = version.as_object() else {
            bail!("each version must be a JSON object");
        };
        let number = version
            .get("version")
            .and_then(as_version_number)
            .context("each version needs a whole-number `version`")?;
        check_fields(version_fields, &version_known, &format!("version {number}"))?;
        if !seen.insert(number) {
            bail!("the template has two versions numbered {number}");
        }
        let messages = version
            .get("messages")
            .and_then(Value::as_array)
            .filter(|messages| !messages.is_empty())
            .with_context(|| format!("version {number} needs at least one message"))?;
        for message in messages {
            let Some(message_fields) = message.as_object() else {
                bail!("each message of version {number} must be a JSON object");
            };
            check_fields(message_fields, &message_known, &format!("a message of version {number}"))?;
            if text_field(message, "role")
                .trim()
                .is_empty()
            {
                bail!("each message of version {number} needs a `role` that is not blank");
            }
            if !message
                .get("content")
                .is_some_and(Value::is_string)
            {
                bail!("each message of version {number} needs a text `content`");
            }
        }
        if version
            .get("label")
            .is_some_and(|label| !label.is_string() && !label.is_null())
        {
            bail!("the label of version {number} must be text");
        }
    }
    if let Some(default) = fields
        .get("default_version")
        .filter(|value| !value.is_null())
    {
        let number = as_version_number(default).context("the template's `default_version` must be a whole number")?;
        if !seen.contains(&number) {
            bail!("the template's default_version {number} is not one of its versions");
        }
    }
    Ok(())
}

/// The field names known at one level: `fields`, and every name the stored
/// `objects` at that level have.
fn known_names<'a>(
    fields: &[&str],
    objects: impl Iterator<Item = &'a Value>,
) -> BTreeSet<String> {
    let mut known: BTreeSet<String> = fields
        .iter()
        .map(|field| (*field).to_owned())
        .collect();
    for object in objects {
        if let Some(object) = object.as_object() {
            known.extend(object.keys().cloned());
        }
    }
    known
}

/// Refuses a field name outside `known`, naming where it was found.
fn check_fields(
    fields: &Map<String, Value>,
    known: &BTreeSet<String>,
    place: &str,
) -> Result<()> {
    if let Some(unknown) = fields
        .keys()
        .find(|name| !known.contains(name.as_str()))
    {
        // Known names include ones the stored template has, which come from
        // Agent Stream, so each is made safe for the terminal.
        let names: Vec<String> = known
            .iter()
            .map(|name| sanitize_for_terminal(name))
            .collect();
        bail!(
            "{place} has a field Agent Stream does not know, '{}', which it would drop without an error; known \
             fields are {}",
            sanitize_for_terminal(unknown),
            names.join(", ")
        );
    }
    Ok(())
}

/// Saves `after` in place of the template `before`, read as `id`: checks it,
/// shows the changes, and stops with nothing sent on a dry run, on no change,
/// or when the template was saved by someone else since `before` was read.
async fn save(
    client: &GatewayClient,
    id: &str,
    before: &Value,
    after: Value,
    dry_run: bool,
    output: Output,
) -> Result<()> {
    check_template(&after, Some(before))?;
    let changes = template_changes(before, &after);
    if dry_run {
        let printed = match output {
            Output::Json => pretty_json_for_terminal(&preview_document(&changes, &after))?,
            Output::Table => changes_table(&changes, DRY_RUN_NOTE),
        };
        println!("{printed}");
        return Ok(());
    }
    if changes.is_empty() {
        eprintln!("Prompt template '{id}' already matches, so nothing was sent.");
        if let Output::Json = output {
            println!("{}", pretty_json_for_terminal(before)?);
        }
        return Ok(());
    }
    let current = read_template(client, id).await?;
    if present(current.get("updated_at")) != present(before.get("updated_at")) {
        bail!(
            "prompt template '{id}' was saved by someone else after it was read, so nothing was saved; run the \
             command again to change the new version"
        );
    }
    let path = template_path(id)?;
    client
        .request(Method::PUT, &path, Some(after))
        .await?;
    match output {
        Output::Table => println!("{}", changes_table(&changes, &confirmation_line("Updated", "prompt template", id))),
        Output::Json => {
            let saved = client
                .request(Method::GET, &path, None)
                .await
                .with_context(|| format!("prompt template '{id}' was saved, but reading it back failed"))?;
            println!("{}", pretty_json_for_terminal(&saved)?);
        }
    }
    Ok(())
}

/// One change to a template: a field outside `versions`, or one version
/// added, removed, or changed.
#[derive(Debug, PartialEq)]
enum TemplateChange {
    Field(surface_validate::Change),
    VersionAdded(u32),
    VersionRemoved(u32),
    VersionChanged(u32),
}

/// What differs between `before` and `after`: each field outside `versions`,
/// and each version by number, so a change never prints a version's messages.
fn template_changes(
    before: &Value,
    after: &Value,
) -> Vec<TemplateChange> {
    let without_versions = |template: &Value| {
        let mut copy = template.clone();
        if let Some(fields) = copy.as_object_mut() {
            fields.remove("versions");
        }
        copy
    };
    let mut changes: Vec<TemplateChange> =
        surface_validate::changes(&without_versions(before), &without_versions(after))
            .into_iter()
            .map(TemplateChange::Field)
            .collect();
    let by_number = |template: &Value| {
        versions_of(template)
            .iter()
            .filter_map(|version| {
                version
                    .get("version")
                    .and_then(as_version_number)
                    .map(|number| (number, version.clone()))
            })
            .collect::<std::collections::BTreeMap<u32, Value>>()
    };
    let (old, new) = (by_number(before), by_number(after));
    for (number, version) in &old {
        match new.get(number) {
            None => changes.push(TemplateChange::VersionRemoved(*number)),
            Some(other) if other != version => changes.push(TemplateChange::VersionChanged(*number)),
            Some(_) => {}
        }
    }
    for number in new.keys() {
        if !old.contains_key(number) {
            changes.push(TemplateChange::VersionAdded(*number));
        }
    }
    changes
}

/// `Changes:`, one line per change, and `last`, as table output prints them on
/// a dry run and after a save.
fn changes_table(
    changes: &[TemplateChange],
    last: &str,
) -> String {
    let mut lines = vec!["Changes:".to_owned()];
    lines.extend(change_lines(changes));
    lines.push(last.to_owned());
    lines.join("\n")
}

/// One line per change, or `  none`.
fn change_lines(changes: &[TemplateChange]) -> Vec<String> {
    if changes.is_empty() {
        return vec!["  none".to_owned()];
    }
    changes
        .iter()
        .map(|change| match change {
            TemplateChange::Field(change) => format!(
                "  {}: {} -> {}",
                tables::flatten_capped(&change.path),
                describe(change.before.as_ref()),
                describe(change.after.as_ref())
            ),
            TemplateChange::VersionAdded(number) => format!("  versions: added version {number}"),
            TemplateChange::VersionRemoved(number) => format!("  versions: removed version {number}"),
            TemplateChange::VersionChanged(number) => format!("  versions: changed version {number}"),
        })
        .collect()
}

/// A field's value on one line, safe for the terminal, or `(absent)`.
fn describe(value: Option<&Value>) -> String {
    value.map_or_else(|| "(absent)".to_owned(), |value| tables::flatten_capped(&value.to_string()))
}

/// The --output json of a dry run: `dry_run`, each change, and the whole
/// template that would be sent.
fn preview_document(
    changes: &[TemplateChange],
    after: &Value,
) -> Value {
    let changes: Vec<Value> = changes
        .iter()
        .map(|change| match change {
            TemplateChange::Field(field) => {
                json!({ "path": field.path, "before": field.before, "after": field.after })
            }
            TemplateChange::VersionAdded(number) => json!({ "version": number, "change": "added" }),
            TemplateChange::VersionRemoved(number) => json!({ "version": number, "change": "removed" }),
            TemplateChange::VersionChanged(number) => json!({ "version": number, "change": "changed" }),
        })
        .collect();
    json!({ "dry_run": true, "changes": changes, "after": after })
}

/// The templates of `prompts list`, refused when Agent Stream did not answer
/// with a list.
fn listed(templates: &Value) -> Result<&[Value]> {
    templates
        .as_array()
        .map(Vec::as_slice)
        .context("Agent Stream did not answer with a list of prompt templates")
}

/// The rows of `prompts list` in table output: each template's own fields
/// with `version_numbers`, such as `1, 2`, in place of its versions, so never
/// its messages.
fn list_rows(templates: &Value) -> Result<Value> {
    let rows = listed(templates)?
        .iter()
        .map(|template| {
            let numbers: Vec<String> = versions_of(template)
                .iter()
                .filter_map(|version| version.get("version"))
                .map(Value::to_string)
                .collect();
            let mut row = Map::new();
            for field in ["id", "name", "status", "default_version", "updated_at"] {
                if let Some(value) = template.get(field) {
                    row.insert(field.to_owned(), value.clone());
                }
            }
            row.insert("version_numbers".to_owned(), Value::String(numbers.join(", ")));
            Value::Object(row)
        })
        .collect();
    Ok(Value::Array(rows))
}

/// The --output json of `prompts list`: each template as Agent Stream sent
/// it, with the `messages` of every version left out.
fn without_messages(templates: &Value) -> Result<Value> {
    let templates = listed(templates)?
        .iter()
        .map(|template| {
            let mut template = template.clone();
            if let Some(versions) = template
                .get_mut("versions")
                .and_then(Value::as_array_mut)
            {
                for version in versions {
                    if let Some(version) = version.as_object_mut() {
                        version.remove("messages");
                    }
                }
            }
            template
        })
        .collect();
    Ok(Value::Array(templates))
}

/// `prompts render`: the messages Agent Stream makes of the template for the
/// variables given.
async fn render(
    client: &GatewayClient,
    args: RenderArgs,
    output: Output,
) -> Result<()> {
    let mut variables = match &args.vars_file {
        Some(file) => match read_json(file)? {
            Value::Object(variables) => variables,
            _ => bail!("--vars-file must hold a JSON object of variables"),
        },
        None => Map::new(),
    };
    for flag in &args.vars {
        let (name, value) = flag
            .split_once('=')
            .filter(|(name, _)| !name.trim().is_empty())
            .with_context(|| format!("--var '{}' must be NAME=VALUE", sanitize_for_terminal(flag)))?;
        variables.insert(name.trim().to_owned(), Value::String(value.to_owned()));
    }
    let mut body = json!({ "variables": variables });
    if let Some(version) = args.version {
        body["version"] = json!(version);
    }
    let path = format!("{}/render", template_path(&args.id)?);
    let answer = client
        .request(Method::POST, &path, Some(body))
        .await?;
    match output {
        Output::Json => println!("{}", pretty_json_for_terminal(&answer)?),
        Output::Table => {
            let messages = answer
                .get("messages")
                .and_then(Value::as_array)
                .context("Agent Stream did not answer with rendered messages")?;
            let shown: Vec<String> = messages
                .iter()
                .map(|message| {
                    format!(
                        "[{}]\n{}",
                        sanitize_for_terminal(text_field(message, "role")),
                        sanitize_multiline(text_field(message, "content"))
                    )
                })
                .collect();
            println!("{}", shown.join("\n\n"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        super::test_support::{
            Route, UnusedKeyring, json_file, request_body, run_stream, saved_login, scripted_agent_stream,
            sends_bearer, start_lines,
        },
        *,
    };
    use crate::config::Config;

    const ACCESS_TOKEN: &str = "aspat_live-secret";

    /// A stored template with versions 1 and 2, the default 1.
    const STORED: &str = r#"{"id":"greeter","name":"Greeter","status":"enabled","default_version":1,
        "versions":[{"version":1,"messages":[{"role":"system","content":"Be kind to {{name}}"}]},
                    {"version":2,"label":"short","messages":[{"role":"system","content":"Hi {{name}}"}]}],
        "created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-02T00:00:00Z"}"#;

    /// The same template, saved again by someone else.
    const STORED_LATER: &str = r#"{"id":"greeter","name":"Greeter","status":"enabled","default_version":1,
        "versions":[{"version":1,"messages":[{"role":"system","content":"Be kind to {{name}}"}]},
                    {"version":2,"label":"short","messages":[{"role":"system","content":"Hi {{name}}"}]}],
        "created_at":"2026-11-01T00:00:00Z","updated_at":"2026-11-03T00:00:00Z"}"#;

    /// A stored template with no `default_version`, so callers get version 2.
    const STORED_NO_DEFAULT: &str = r#"{"id":"greeter","name":"Greeter","status":"enabled",
        "versions":[{"version":1,"messages":[{"role":"system","content":"a"}]},
                    {"version":2,"messages":[{"role":"system","content":"b"}]}],
        "updated_at":"2026-11-02T00:00:00Z"}"#;

    const GET_STORED: Route = ("GET /api/v1/prompts/greeter", "HTTP/1.1 200 OK", STORED);
    const PUT_OK: Route = ("PUT /api/v1/prompts/greeter", "HTTP/1.1 200 OK", STORED);

    /// Runs `fabric agent-stream <words>` with a saved access token against
    /// an Agent Stream answering `routes`, and returns the result and the
    /// requests it got.
    async fn run_prompts(
        words: &[&str],
        routes: Vec<Route>,
    ) -> (Result<()>, Arc<Mutex<Vec<String>>>) {
        let (host, requests) = scripted_agent_stream(routes).await;
        let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);
        let result = run_stream(words, saved, &credentials).await;
        (result, requests)
    }

    /// The JSON body of the recorded request at `index`.
    fn body_of(
        requests: &Arc<Mutex<Vec<String>>>,
        index: usize,
    ) -> Value {
        let recorded = requests.lock().unwrap();
        serde_json::from_str(request_body(&recorded[index])).unwrap_or_else(|error| panic!("{error}"))
    }

    fn error_text(result: Result<()>) -> String {
        match result {
            Err(error) => format!("{error:#}"),
            Ok(()) => panic!("expected the command to fail"),
        }
    }

    #[tokio::test]
    async fn list_sends_the_token_to_the_prompts_route() {
        let list = r#"[]"#;
        let (result, requests) =
            run_prompts(&["prompts", "list"], vec![("GET /api/v1/prompts", "HTTP/1.1 200 OK", list)]).await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["GET /api/v1/prompts HTTP/1.1"]);
        assert!(sends_bearer(&requests.lock().unwrap()[0], ACCESS_TOKEN));
    }

    #[test]
    fn list_rows_keep_metadata_and_version_numbers_but_never_messages() {
        let stored: Value = serde_json::from_str(STORED).unwrap();
        let rows = list_rows(&json!([stored])).unwrap();
        assert_eq!(
            rows,
            json!([{"id":"greeter","name":"Greeter","status":"enabled","default_version":1,
                    "updated_at":"2026-11-02T00:00:00Z","version_numbers":"1, 2"}])
        );
        assert!(
            !rows
                .to_string()
                .contains("Be kind")
        );
    }

    #[test]
    fn list_json_keeps_each_template_but_leaves_out_messages_and_a_non_list_is_refused() {
        let stored: Value = serde_json::from_str(STORED).unwrap();
        let shown = without_messages(&json!([stored])).unwrap();
        assert_eq!(shown[0]["versions"], json!([{"version":1},{"version":2,"label":"short"}]));
        assert_eq!(shown[0]["updated_at"], json!("2026-11-02T00:00:00Z"));
        assert!(
            !shown
                .to_string()
                .contains("Be kind")
        );
        assert!(without_messages(&json!({"error":"x"})).is_err());
        assert!(list_rows(&json!({"error":"x"})).is_err());
    }

    #[tokio::test]
    async fn a_field_a_newer_agent_stream_returns_does_not_block_a_save() {
        let newer = r#"{"id":"greeter","name":"Greeter","owner":"u-1","default_version":1,
            "versions":[{"version":1,"hash":"abc","messages":[{"role":"system","content":"a","cache":true}]},
                        {"version":2,"messages":[{"role":"system","content":"b"}]}],
            "updated_at":"2026-11-02T00:00:00Z"}"#;
        let (result, requests) = run_prompts(
            &["prompts", "set-default", "greeter", "2"],
            vec![("GET /api/v1/prompts/greeter", "HTTP/1.1 200 OK", newer), PUT_OK],
        )
        .await;
        result.unwrap();
        assert_eq!(body_of(&requests, 2)["owner"], json!("u-1"));
    }

    #[test]
    fn a_null_id_or_updated_at_in_an_update_file_counts_as_absent() {
        let before = json!({"id":"greeter","name":"G","versions":[]});
        let after = replacement(json!({"id":null,"name":"New","updated_at":null}), &before, "greeter").unwrap();
        assert_eq!(after["id"], json!("greeter"));
        assert_eq!(after["name"], json!("New"));
    }

    #[tokio::test]
    async fn create_from_message_files_sends_version_1_as_the_default_without_the_trailing_line_break() {
        let system = json_file("You greet {{name}}.\n");
        let user = json_file("Hello\r\n");
        let message_system = format!("system={}", system.path().display());
        let message_user = format!("user={}", user.path().display());
        let (result, requests) = run_prompts(
            &[
                "prompts",
                "create",
                "--id",
                "greeter",
                "--name",
                "Greeter",
                "--message",
                &message_system,
                "--message",
                &message_user,
                "--label",
                "first",
            ],
            vec![("POST /api/v1/prompts", "HTTP/1.1 200 OK", STORED)],
        )
        .await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["POST /api/v1/prompts HTTP/1.1"]);
        assert_eq!(
            body_of(&requests, 0),
            json!({"id":"greeter","name":"Greeter","default_version":1,"versions":[{"version":1,"label":"first",
                   "messages":[{"role":"system","content":"You greet {{name}}."},{"role":"user","content":"Hello"}]}]})
        );
    }

    #[tokio::test]
    async fn create_from_a_file_sends_the_document_as_it_is() {
        let file = json_file(
            r#"{"id":"greeter","name":"Greeter","versions":[{"version":3,"messages":[{"role":"user","content":"x"}]}]}"#,
        );
        let (result, requests) = run_prompts(
            &["prompts", "create", "--file", file.path().to_str().unwrap()],
            vec![("POST /api/v1/prompts", "HTTP/1.1 200 OK", STORED)],
        )
        .await;
        result.unwrap();
        assert_eq!(
            body_of(&requests, 0),
            json!({"id":"greeter","name":"Greeter","versions":[{"version":3,"messages":[{"role":"user","content":"x"}]}]})
        );
    }

    #[tokio::test]
    async fn create_dry_run_needs_no_login_and_sends_nothing() {
        let file = json_file(
            r#"{"id":"greeter","name":"Greeter","versions":[{"version":1,"messages":[{"role":"user","content":"x"}]}]}"#,
        );
        let dir = tempfile::tempdir().unwrap();
        super::super::dispatch_with(
            super::super::test_support::stream_args(&[
                "prompts",
                "create",
                "--file",
                file.path().to_str().unwrap(),
                "--dry-run",
            ]),
            Config::default(),
            &UnusedKeyring,
            &dir.path()
                .join("agent-stream.toml"),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn create_refuses_a_template_agent_stream_would_refuse_or_silently_change_before_sending() {
        let cases = [
            (r#"{"id":"greeter","name":"Greeter","defualt_version":1}"#, "'defualt_version'"),
            (r#"{"id":"bad id","name":"Greeter"}"#, "template id 'bad id'"),
            (r#"{"id":"greeter","name":"  "}"#, "`name` that is not blank"),
            (
                r#"{"id":"greeter","name":"G","default_version":2,"versions":[{"version":1,"messages":[{"role":"user","content":"x"}]}]}"#,
                "default_version 2",
            ),
            (r#"{"id":"greeter","name":"G","versions":[{"version":1,"messages":[]}]}"#, "at least one message"),
            (
                r#"{"id":"greeter","name":"G","versions":[{"version":1,"messages":[{"role":" ","content":"x"}]}]}"#,
                "`role`",
            ),
            (
                r#"{"id":"greeter","name":"G","versions":[{"version":1,"messages":[{"role":"user","content":"x"}]},{"version":1,"messages":[{"role":"user","content":"y"}]}]}"#,
                "two versions numbered 1",
            ),
            (
                r#"{"id":"greeter","name":"G","versions":[{"version":1,"messages":[{"role":"user","content":"x","name":"n"}]}]}"#,
                "'name'",
            ),
            (r#"{"id":"greeter","name":"G","status":"deleted"}"#, "prompts delete"),
            (r#"{"id":"greeter","name":"G"}"#, "needs at least one version"),
            (r#"{"id":"greeter","name":"G","versions":[]}"#, "needs at least one version"),
        ];
        for (document, expected) in cases {
            let file = json_file(document);
            let (result, requests) =
                run_prompts(&["prompts", "create", "--file", file.path().to_str().unwrap()], vec![]).await;
            let text = error_text(result);
            assert!(text.contains(expected), "{document}: {text}");
            assert!(start_lines(&requests).is_empty(), "{document}");
        }
    }

    #[tokio::test]
    async fn create_shows_agent_stream_plain_text_refusal() {
        let file = json_file(
            r#"{"id":"greeter","name":"Greeter","versions":[{"version":1,"messages":[{"role":"user","content":"x"}]}]}"#,
        );
        let (result, _) = run_prompts(
            &["prompts", "create", "--file", file.path().to_str().unwrap()],
            vec![("POST /api/v1/prompts", "HTTP/1.1 409 Conflict", "A prompt with id 'greeter' already exists")],
        )
        .await;
        let text = error_text(result);
        assert!(text.contains("A prompt with id 'greeter' already exists"), "{text}");
        assert!(!text.contains(ACCESS_TOKEN), "{text}");
    }

    #[tokio::test]
    async fn get_reads_the_template_by_id() {
        let (result, requests) = run_prompts(&["prompts", "get", "greeter"], vec![GET_STORED]).await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["GET /api/v1/prompts/greeter HTTP/1.1"]);
    }

    #[tokio::test]
    async fn update_with_json_output_reads_the_template_back_after_the_save() {
        let (result, requests) =
            run_prompts(&["-o", "json", "prompts", "update", "greeter", "--name", "New"], vec![GET_STORED, PUT_OK])
                .await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/prompts/greeter HTTP/1.1",
                "GET /api/v1/prompts/greeter HTTP/1.1",
                "PUT /api/v1/prompts/greeter HTTP/1.1",
                "GET /api/v1/prompts/greeter HTTP/1.1"
            ]
        );
    }

    #[tokio::test]
    async fn an_update_file_with_no_versions_is_refused_before_saving() {
        let mut document: Value = serde_json::from_str(STORED).unwrap();
        document["versions"] = json!([]);
        document
            .as_object_mut()
            .unwrap()
            .remove("default_version");
        let file = json_file(&document.to_string());
        let (result, requests) = run_prompts(
            &["prompts", "update", "greeter", "--file", file.path().to_str().unwrap()],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        assert!(error_text(result).contains("needs at least one version"));
        assert_eq!(start_lines(&requests), ["GET /api/v1/prompts/greeter HTTP/1.1"]);
    }

    #[tokio::test]
    async fn update_reads_twice_then_sends_the_whole_template_with_the_change() {
        let (result, requests) =
            run_prompts(&["prompts", "update", "greeter", "--status", "disabled"], vec![GET_STORED, PUT_OK]).await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/prompts/greeter HTTP/1.1",
                "GET /api/v1/prompts/greeter HTTP/1.1",
                "PUT /api/v1/prompts/greeter HTTP/1.1"
            ]
        );
        let mut expected: Value = serde_json::from_str(STORED).unwrap();
        expected["status"] = json!("disabled");
        assert_eq!(body_of(&requests, 2), expected);
    }

    #[tokio::test]
    async fn update_stops_when_the_template_was_saved_after_it_was_read() {
        let (result, requests) = run_prompts(
            &["prompts", "update", "greeter", "--name", "New"],
            vec![GET_STORED, ("GET /api/v1/prompts/greeter", "HTTP/1.1 200 OK", STORED_LATER), PUT_OK],
        )
        .await;
        assert!(error_text(result).contains("saved by someone else"));
        assert!(
            !start_lines(&requests)
                .iter()
                .any(|line| line.starts_with("PUT"))
        );
    }

    #[tokio::test]
    async fn update_with_no_change_or_a_dry_run_sends_nothing() {
        for words in [
            &["prompts", "update", "greeter", "--name", "Greeter"][..],
            &["prompts", "update", "greeter", "--name", "New", "--dry-run"],
        ] {
            let (result, requests) = run_prompts(words, vec![GET_STORED, PUT_OK]).await;
            result.unwrap();
            assert_eq!(start_lines(&requests), ["GET /api/v1/prompts/greeter HTTP/1.1"], "{words:?}");
        }
    }

    #[tokio::test]
    async fn update_file_read_before_another_save_is_refused() {
        let file = json_file(STORED_LATER);
        let (result, requests) = run_prompts(
            &["prompts", "update", "greeter", "--file", file.path().to_str().unwrap()],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        assert!(error_text(result).contains("updated_at does not match"));
        assert_eq!(start_lines(&requests), ["GET /api/v1/prompts/greeter HTTP/1.1"]);
    }

    #[tokio::test]
    async fn update_file_keeps_the_stored_server_fields() {
        let mut document: Value = serde_json::from_str(STORED).unwrap();
        document["name"] = json!("Renamed");
        document["created_at"] = json!("1999-01-01T00:00:00Z");
        let file = json_file(&document.to_string());
        let (result, requests) = run_prompts(
            &["prompts", "update", "greeter", "--file", file.path().to_str().unwrap()],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        result.unwrap();
        let sent = body_of(&requests, 2);
        assert_eq!(sent["name"], json!("Renamed"));
        assert_eq!(sent["created_at"], json!("2026-11-01T00:00:00Z"));
    }

    #[tokio::test]
    async fn add_version_numbers_the_new_version_after_the_highest_and_keeps_the_default() {
        let file = json_file(r#"{"messages":[{"role":"user","content":"v3"}]}"#);
        let (result, requests) = run_prompts(
            &["prompts", "add-version", "greeter", "--file", file.path().to_str().unwrap(), "--label", "third"],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        result.unwrap();
        let sent = body_of(&requests, 2);
        assert_eq!(sent["default_version"], json!(1));
        assert_eq!(
            sent["versions"][2],
            json!({"version":3,"label":"third","messages":[{"role":"user","content":"v3"}]})
        );
    }

    #[tokio::test]
    async fn add_version_make_default_moves_the_default_to_the_new_version() {
        let file = json_file("Hello");
        let message = format!("user={}", file.path().display());
        let (result, requests) = run_prompts(
            &["prompts", "add-version", "greeter", "--message", &message, "--version", "7", "--make-default"],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        result.unwrap();
        let sent = body_of(&requests, 2);
        assert_eq!(sent["default_version"], json!(7));
        assert_eq!(sent["versions"][2]["version"], json!(7));
    }

    #[test]
    fn add_version_to_a_template_without_a_default_pins_the_version_callers_get_now() {
        let before: Value = serde_json::from_str(STORED_NO_DEFAULT).unwrap();
        let mut version = Map::new();
        version.insert("messages".to_owned(), json!([{"role":"user","content":"c"}]));
        let after = with_version(&before, version, false).unwrap();
        assert_eq!(after["default_version"], json!(2));
        assert_eq!(after["versions"][2]["version"], json!(3));
    }

    #[tokio::test]
    async fn add_version_never_overwrites_an_existing_version() {
        let file = json_file("Hello");
        let message = format!("user={}", file.path().display());
        let (result, requests) = run_prompts(
            &["prompts", "add-version", "greeter", "--message", &message, "--version", "2"],
            vec![GET_STORED, PUT_OK],
        )
        .await;
        assert!(error_text(result).contains("already has version 2"));
        assert_eq!(start_lines(&requests), ["GET /api/v1/prompts/greeter HTTP/1.1"]);
    }

    #[tokio::test]
    async fn set_default_sends_the_new_default_and_refuses_a_missing_version() {
        let (result, requests) =
            run_prompts(&["prompts", "set-default", "greeter", "2"], vec![GET_STORED, PUT_OK]).await;
        result.unwrap();
        assert_eq!(body_of(&requests, 2)["default_version"], json!(2));

        let (result, requests) =
            run_prompts(&["prompts", "set-default", "greeter", "9"], vec![GET_STORED, PUT_OK]).await;
        assert!(error_text(result).contains("no version 9"));
        assert_eq!(start_lines(&requests).len(), 1);
    }

    #[tokio::test]
    async fn remove_version_drops_a_version_but_refuses_the_default_and_the_last() {
        let (result, requests) =
            run_prompts(&["prompts", "remove-version", "greeter", "2"], vec![GET_STORED, PUT_OK]).await;
        result.unwrap();
        let sent = body_of(&requests, 2);
        assert_eq!(
            sent["versions"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(sent["versions"][0]["version"], json!(1));

        let (result, _) = run_prompts(&["prompts", "remove-version", "greeter", "1"], vec![GET_STORED, PUT_OK]).await;
        assert!(error_text(result).contains("set-default"));

        let before: Value = serde_json::from_str(STORED_NO_DEFAULT).unwrap();
        assert!(without_version(&before, 2).is_err(), "the highest is the default without default_version");
        let single = json!({"id":"g","name":"G","versions":[{"version":1,"messages":[]}],"default_version":null});
        assert!(format!("{:#}", without_version(&single, 1).unwrap_err()).contains("set-default"));
    }

    #[tokio::test]
    async fn render_sends_the_variables_with_typed_vars_winning_over_the_file() {
        let vars = json_file(r#"{"name":"from file","count":2}"#);
        let answer = r#"{"messages":[{"role":"system","content":"Hi Ada"}],"variables":["name"]}"#;
        let (result, requests) = run_prompts(
            &[
                "prompts",
                "render",
                "greeter",
                "--version",
                "2",
                "--vars-file",
                vars.path().to_str().unwrap(),
                "--var",
                "name=Ada",
            ],
            vec![("POST /api/v1/prompts/greeter/render", "HTTP/1.1 200 OK", answer)],
        )
        .await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["POST /api/v1/prompts/greeter/render HTTP/1.1"]);
        assert_eq!(body_of(&requests, 0), json!({"version":2,"variables":{"name":"Ada","count":2}}));
    }

    #[tokio::test]
    async fn delete_sends_delete_and_a_bad_id_sends_nothing() {
        let (result, requests) = run_prompts(
            &["prompts", "delete", "greeter"],
            vec![("DELETE /api/v1/prompts/greeter", "HTTP/1.1 204 No Content", "")],
        )
        .await;
        result.unwrap();
        assert_eq!(start_lines(&requests), ["DELETE /api/v1/prompts/greeter HTTP/1.1"]);

        let (result, requests) = run_prompts(&["prompts", "delete", "../users"], vec![]).await;
        assert!(error_text(result).contains("must be 1 to 128"));
        assert!(start_lines(&requests).is_empty());
    }

    #[test]
    fn change_lines_name_versions_by_number_and_never_print_messages() {
        let before: Value = serde_json::from_str(STORED).unwrap();
        let mut after = without_version(&before, 2).unwrap();
        after["name"] = json!("New");
        let lines = change_lines(&template_changes(&before, &after));
        assert_eq!(lines, ["  name: \"Greeter\" -> \"New\"", "  versions: removed version 2"]);
    }

    #[test]
    fn prompts_help_renders() {
        use clap::CommandFactory;
        let mut cli = crate::commands::Cli::command();
        cli.build();
        let stream = cli
            .find_subcommand_mut("agent-stream")
            .and_then(|stream| stream.find_subcommand_mut("prompts"))
            .expect("prompts group");
        for name in
            ["list", "get", "create", "update", "delete", "add-version", "set-default", "remove-version", "render"]
        {
            assert!(
                stream
                    .find_subcommand(name)
                    .is_some(),
                "{name}"
            );
        }
    }
}
