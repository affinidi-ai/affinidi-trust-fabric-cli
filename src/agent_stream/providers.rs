//! `fabric agent-stream providers`: the Model catalog of an Agent Stream, the
//! LLM providers it knows with their endpoints, models, and prices.
//!
//! Agent Stream keeps providers in two stores. Built-in providers can be read,
//! replaced, and deleted one at a time, but a catalog refresh overwrites them.
//! Custom providers survive a refresh, and are changed only by replacing the
//! whole custom catalog. The CLI shows both as one list, adds a new provider
//! to the custom catalog, and changes each provider through the route of the
//! store it is in. Neither store has a version check, so every change reads
//! the store again just before it saves and stops if it changed.
//!
//! The catalog holds no API keys: a provider's key is a secret that a surface
//! names.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Subcommand};
use reqwest::Method;
use serde_json::{Map, Value, json};

use crate::{
    client::{GatewayClient, pretty_json_for_terminal, sanitize_for_terminal},
    commands::{Output, confirmation_line, entity_path, print_list, read_json},
    surface_patch,
    surface_validate::{self, Change},
    tables::{self, Scope},
};

/// The built-in providers, and the route of one built-in provider below it.
const BUILT_IN_PATH: &str = "/v1/llm-providers";

/// The whole custom catalog, as one document.
const CUSTOM_PATH: &str = "/v1/llm-providers/custom";

/// Longest provider id (`enum_value`) Agent Stream accepts.
const MAX_ID_LEN: usize = 128;

/// Highest price Agent Stream accepts, in USD per 1,000 tokens.
const MAX_PRICE: f64 = 100.0;

/// The values Agent Stream accepts for `api_key_validation`.
const KEY_VALIDATIONS: [&str; 3] = ["mandatory", "optional", "none"];

#[derive(Debug, Subcommand)]
pub enum ProviderCommand {
    /// List the providers of the Model catalog, built-in and custom.
    ///
    /// SOURCE is `built-in` for a provider Agent Stream ships, which a catalog
    /// refresh replaces, and `custom` for one added here or in the dashboard.
    /// ENABLED is `no` only for a provider with `enabled` set to false, since
    /// Agent Stream treats one with no `enabled` as on. MODELS is the number
    /// of models it lists. --output json prints each
    /// provider as Agent Stream keeps it, with `source` added.
    #[command(after_long_help = LIST_EXAMPLES)]
    List,
    /// Get a provider by id, as the JSON document Agent Stream keeps.
    ///
    /// When a built-in and a custom provider share the id, which a catalog
    /// refresh can cause, the built-in one is shown with a warning: the custom
    /// one blocks every custom save until it gets another id.
    #[command(after_long_help = GET_EXAMPLES)]
    Get {
        /// Id of the provider, its `enum_value` (see `fabric agent-stream
        /// providers list`).
        id: String,
    },
    /// Add a provider to the custom catalog, from flags or a JSON document.
    ///
    /// A custom provider survives a catalog refresh. With flags, --id and
    /// --name are required; add endpoints and models afterwards with
    /// `providers update`, or give the whole provider with --file. An id
    /// holds letters, digits, `-`, and `_`, up to 128 characters, and can't be
    /// one another provider, built-in or custom, already has, whatever its
    /// case.
    ///
    /// The provider is saved with `enabled` true, unless --disabled is given
    /// or the --file document sets `enabled` itself. Agent Stream treats a
    /// provider with no `enabled` as on, but some dashboard pages show it as
    /// disabled, so the CLI always writes it.
    ///
    /// Before anything is sent, the CLI checks the provider as Agent Stream
    /// would: an id and a name; when set, an `api_key_validation` of
    /// mandatory, optional, or none; a name and a path on each endpoint; a
    /// name and a value on each model, with no two models sharing a value;
    /// and prices from 0 to 100 USD per 1,000 tokens. Agent Stream also
    /// requires a base URL that resolves to a public address.
    ///
    /// The provider is added by reading the custom catalog, adding it, and
    /// sending the whole custom catalog back, as `providers update` does for
    /// a custom provider. --dry-run reads the catalog, shows the new
    /// provider, and saves nothing.
    #[command(after_long_help = CREATE_EXAMPLES)]
    Create(CreateArgs),
    /// Change a provider with --set, --unset, --add and --remove, or replace
    /// it with a JSON document.
    ///
    /// The CLI reads the provider, applies the change on this machine, and
    /// checks it as `create` does. It then reads again and stops if, since
    /// the first read, the provider changed (for a built-in one) or anything
    /// in the custom catalog changed (for a custom one); otherwise it saves. A
    /// built-in provider is replaced on its own. A custom provider is saved by
    /// sending the whole custom catalog with only this provider changed. A
    /// custom catalog that holds an entry Agent Stream refuses, such as one
    /// whose id a built-in provider also has, blocks every custom save, and
    /// the error names it. Agent Stream has no version check, so a save that lands in
    /// the short gap between that last read and the send is still
    /// overwritten. A change that leaves the provider as it is sends nothing.
    ///
    /// A flag path is field names joined by `.`, such as `default_base_url`
    /// or `hero.title`; it can't use brackets or a list position. To change a
    /// list, give its path to --add or --remove, or use the model commands.
    /// `enum_value` can't be changed.
    ///
    /// Table output lists each changed field; --output json prints the
    /// provider as Agent Stream has it after the save. --dry-run shows the
    /// changes, or with --output json the changes and the whole new provider,
    /// and saves nothing. A built-in provider changed here is replaced again
    /// by the next catalog refresh.
    #[command(after_long_help = UPDATE_EXAMPLES)]
    Update(UpdateArgs),
    /// Delete a provider.
    ///
    /// A built-in provider is deleted on its own. A custom provider is removed
    /// by sending the custom catalog without it, as `providers update` does.
    /// There is no confirmation prompt. A surface that uses the provider stops
    /// working, and a built-in provider comes back with the next catalog
    /// refresh. Table output prints one line; --output json prints
    /// `{"deleted": "<id>"}` for either store.
    #[command(after_long_help = DELETE_EXAMPLES)]
    Delete(DeleteArgs),
    /// List the models of a provider, with their prices.
    ///
    /// ENABLED is `no` only for a model with `enabled` set to false: Agent
    /// Stream treats a model with no `enabled` as enabled. Prices are USD per
    /// 1,000 tokens, and "-" means the catalog sets none. --output json prints
    /// the provider's `models` list. For an id a built-in and a custom
    /// provider share, the built-in one's models are shown, with a warning.
    #[command(after_long_help = MODELS_EXAMPLES)]
    Models {
        /// Id of the provider (see `fabric agent-stream providers list`).
        id: String,
    },
    /// Enable a model of a provider, so surfaces can choose it.
    ///
    /// Sets the model's `enabled` to true. A model with no `enabled` is
    /// already enabled, as Agent Stream reads it, so nothing is sent. The save
    /// works as `providers update` does, --dry-run included.
    #[command(after_long_help = ENABLE_MODEL_EXAMPLES)]
    EnableModel(ModelArgs),
    /// Disable a model of a provider.
    ///
    /// Sets the model's `enabled` to false. Agent Stream hides a disabled
    /// model from the dashboard's model pickers and refuses to save a surface
    /// that uses it. The save works as `providers update` does, --dry-run
    /// included.
    #[command(after_long_help = DISABLE_MODEL_EXAMPLES)]
    DisableModel(ModelArgs),
    /// Set the input and output prices of a model of a provider.
    ///
    /// Prices are USD per 1,000 tokens, from 0 to 100. Give --input-price,
    /// --output-price, or both. Agent Stream uses them to work out the cost of every call to
    /// the model on a surface that sets no price of its own, so a change
    /// changes every cost and budget figure from then on. The save works as
    /// `providers update` does, --dry-run included.
    #[command(after_long_help = SET_PRICE_EXAMPLES)]
    SetPrice(SetPriceArgs),
}

/// Examples shown at the bottom of `providers list --help`.
const LIST_EXAMPLES: &str = r#"Examples:
  List providers:
    fabric agent-stream providers list

  Print the ids of the custom providers:
    fabric agent-stream providers list --output json | jq -r \
      '.[] | select(.source == "custom") | .enum_value'"#;

/// Examples shown at the bottom of `providers get --help`.
const GET_EXAMPLES: &str = r#"Examples:
  Show a provider:
    fabric agent-stream providers get openai

  Keep a copy to edit:
    fabric agent-stream providers get openai > provider.json"#;

/// Examples shown at the bottom of `providers create --help`.
const CREATE_EXAMPLES: &str = r#"Examples:
  Add a self-hosted, OpenAI-compatible provider:
    fabric agent-stream providers create --id acme-llm --name "Acme LLM" \
      --base-url https://llm.acme.example --api-schema openai

  Check a whole provider document, then add it:
    fabric agent-stream providers create --file provider.json --dry-run
    fabric agent-stream providers create --file provider.json"#;

/// Examples shown at the bottom of `providers update --help`.
const UPDATE_EXAMPLES: &str = r#"Examples:
  Change the base URL, after a dry run:
    fabric agent-stream providers update acme-llm \
      --set default_base_url=https://llm2.acme.example --dry-run

  Add a model:
    fabric agent-stream providers update acme-llm \
      --add 'models={"name":"Acme Large","value":"acme-large"}'

  Replace the whole provider:
    fabric agent-stream providers get acme-llm > provider.json
    fabric agent-stream providers update acme-llm --file provider.json"#;

/// Examples shown at the bottom of `providers delete --help`.
const DELETE_EXAMPLES: &str = r#"Examples:
  Keep a copy, then delete a custom provider:
    fabric agent-stream providers get acme-llm > provider.json
    fabric agent-stream providers delete acme-llm"#;

/// Examples shown at the bottom of `providers models --help`.
const MODELS_EXAMPLES: &str = r#"Examples:
  List the models of a provider:
    fabric agent-stream providers models openai"#;

/// Examples shown at the bottom of `providers enable-model --help`.
const ENABLE_MODEL_EXAMPLES: &str = r#"Examples:
  Enable a model:
    fabric agent-stream providers enable-model openai gpt-4o-mini"#;

/// Examples shown at the bottom of `providers disable-model --help`.
const DISABLE_MODEL_EXAMPLES: &str = r#"Examples:
  Disable a model, after a dry run:
    fabric agent-stream providers disable-model openai gpt-4o --dry-run
    fabric agent-stream providers disable-model openai gpt-4o"#;

/// Examples shown at the bottom of `providers set-price --help`.
const SET_PRICE_EXAMPLES: &str = r#"Examples:
  Set both prices of a model, in USD per 1,000 tokens:
    fabric agent-stream providers set-price openai gpt-4o-mini \
      --input-price 0.00015 --output-price 0.0006"#;

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("source").required(true).args(["file", "id"])))]
pub struct CreateArgs {
    /// Id of the new provider, its `enum_value`: letters, digits, `-`, and
    /// `_`, up to 128 characters. A surface names the provider by it.
    #[arg(long, requires = "name", conflicts_with = "file")]
    id: Option<String>,
    /// Display name of the provider.
    #[arg(long, conflicts_with = "file")]
    name: Option<String>,
    /// The provider's API address (`default_base_url`), without `/v1`.
    #[arg(long, conflicts_with = "file")]
    base_url: Option<String>,
    /// The API format the provider speaks (`api_schema`), such as `openai`.
    #[arg(long, conflicts_with = "file")]
    api_schema: Option<String>,
    /// What the provider is.
    #[arg(long, conflicts_with = "file")]
    description: Option<String>,
    /// Save the provider with `enabled` false, so it is in the catalog but
    /// turned off.
    #[arg(long, conflicts_with = "file")]
    disabled: bool,
    /// JSON document of the provider, or - for standard input. When it has no
    /// `enabled`, the provider is saved with `enabled` true.
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Show the new provider, and save nothing. The catalog is still read, to
    /// check the id is free.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("change").required(true).multiple(true).args(["file", "set", "unset", "add", "remove"])))]
pub struct UpdateArgs {
    /// Id of the provider (see `fabric agent-stream providers list`).
    id: String,
    /// Complete provider JSON that replaces the stored provider, or - for
    /// standard input. Its `enum_value` must be the provider's id. A provider
    /// has no version or `updated_at`, so the CLI can't tell whether the file
    /// was copied before someone else saved the provider, and would overwrite
    /// that save: start from a fresh `providers get` and save soon after.
    #[arg(short, long, conflicts_with_all = ["set", "unset", "add", "remove"])]
    file: Option<PathBuf>,
    /// Set a field, as a dot path such as `default_base_url` and a value read
    /// as JSON when it parses (`100`, `true`, `{"title":"x"}`) and as plain
    /// text otherwise. Repeatable.
    #[arg(long, value_name = "PATH=VALUE")]
    set: Vec<String>,
    /// Remove a field, as a dot path such as `hero`. Repeatable.
    #[arg(long, value_name = "PATH")]
    unset: Vec<String>,
    /// Add one item to a list, as the list's dot path and the item, read the
    /// same way as a --set value, such as
    /// `models={"name":"Acme Large","value":"acme-large"}`. An item equal to
    /// one already in the list is refused, and so is a second model with the
    /// same value. Repeatable.
    #[arg(long, value_name = "PATH=ITEM")]
    add: Vec<String>,
    /// Remove one item from a list: text by its value, an object by some of
    /// its fields as JSON, such as `models={"value":"acme-large"}`. Removes run
    /// before adds. Repeatable.
    #[arg(long, value_name = "PATH=ITEM")]
    remove: Vec<String>,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    /// Id of the provider (see `fabric agent-stream providers list`).
    id: String,
}

#[derive(Debug, Args)]
pub struct ModelArgs {
    /// Id of the provider (see `fabric agent-stream providers list`).
    id: String,
    /// The model, by its `value` (see `fabric agent-stream providers models`).
    model: String,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("price").required(true).multiple(true).args(["input_price", "output_price"])))]
pub struct SetPriceArgs {
    /// Id of the provider (see `fabric agent-stream providers list`).
    id: String,
    /// The model, by its `value` (see `fabric agent-stream providers models`).
    model: String,
    /// Price of 1,000 input tokens, in USD (`cost_per_1k_input`).
    #[arg(long)]
    input_price: Option<f64>,
    /// Price of 1,000 output tokens, in USD (`cost_per_1k_output`).
    #[arg(long)]
    output_price: Option<f64>,
    /// Show what would change, and save nothing.
    #[arg(long)]
    dry_run: bool,
}

/// Runs one `providers` command against the Agent Stream `client` gives.
pub async fn run(
    command: ProviderCommand,
    output: Output,
    connect: impl AsyncFnOnce() -> Result<GatewayClient>,
) -> Result<()> {
    let client = connect().await?;
    match command {
        ProviderCommand::List => {
            let catalog = Catalog::read(&client).await?;
            let rows = catalog.listed();
            match output {
                Output::Json => println!("{}", pretty_json_for_terminal(&Value::Array(rows))?),
                Output::Table => {
                    let rows = rows
                        .iter()
                        .map(list_row)
                        .collect();
                    print_list(&Value::Array(rows), output, &tables::AGENT_STREAM_PROVIDERS, Scope::All)?;
                }
            }
            Ok(())
        }
        ProviderCommand::Get { id } => {
            let provider = Catalog::read(&client)
                .await?
                .find_to_read(&id)?
                .provider;
            println!("{}", pretty_json_for_terminal(&provider)?);
            Ok(())
        }
        ProviderCommand::Models { id } => {
            let provider = Catalog::read(&client)
                .await?
                .find_to_read(&id)?
                .provider;
            let models = provider
                .get("models")
                .cloned()
                .unwrap_or_else(|| json!([]));
            let shown = match output {
                Output::Json => models,
                Output::Table => Value::Array(
                    models
                        .as_array()
                        .map_or(&[][..], Vec::as_slice)
                        .iter()
                        .map(model_row)
                        .collect(),
                ),
            };
            print_list(&shown, output, &tables::AGENT_STREAM_MODELS, Scope::All)
        }
        ProviderCommand::Create(args) => create(&client, args, output).await,
        ProviderCommand::Update(args) => {
            check_flag_paths(&args.set, &args.unset, &args.add, &args.remove)?;
            let found = Catalog::read(&client)
                .await?
                .find(&args.id)?;
            let after = updated(&found.provider, &args)?;
            save(&client, found, after, args.dry_run, output).await
        }
        ProviderCommand::Delete(args) => delete(&client, &args.id, output).await,
        ProviderCommand::EnableModel(args) => set_enabled(&client, args, true, output).await,
        ProviderCommand::DisableModel(args) => set_enabled(&client, args, false, output).await,
        ProviderCommand::SetPrice(args) => set_price(&client, args, output).await,
    }
}

/// Which store a provider is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    BuiltIn,
    Custom,
}

impl Source {
    fn label(self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in",
            Self::Custom => "custom",
        }
    }
}

/// Both stores of the Model catalog as Agent Stream has them now.
#[derive(Debug)]
struct Catalog {
    built_in: Vec<Value>,
    /// The custom catalog document as Agent Stream stores it.
    custom: Value,
}

/// The built-in providers as Agent Stream has them now.
async fn read_built_in(client: &GatewayClient) -> Result<Vec<Value>> {
    client
        .request(Method::GET, BUILT_IN_PATH, None)
        .await?
        .get("providers")
        .and_then(Value::as_array)
        .cloned()
        .context("Agent Stream did not answer with its built-in providers")
}

/// A provider, with the store it is in, read from a [`Catalog`].
#[derive(Debug)]
struct Found {
    provider: Value,
    source: Source,
    /// The custom catalog the provider was read from, for a custom provider.
    custom: Value,
}

impl Catalog {
    /// Reads both stores.
    async fn read(client: &GatewayClient) -> Result<Self> {
        let built_in = read_built_in(client).await?;
        let custom = read_custom(client).await?;
        Ok(Self { built_in, custom })
    }

    /// Every provider, built-in first, each with `source` added.
    fn listed(&self) -> Vec<Value> {
        let with_source = |provider: &Value, source: Source| {
            let mut provider = provider.clone();
            if let Some(fields) = provider.as_object_mut() {
                fields.insert("source".to_owned(), Value::String(source.label().to_owned()));
            }
            provider
        };
        self.built_in
            .iter()
            .map(|provider| with_source(provider, Source::BuiltIn))
            .chain(
                custom_providers(&self.custom)
                    .iter()
                    .map(|provider| with_source(provider, Source::Custom)),
            )
            .collect()
    }

    /// The provider `id` to change, from whichever store has it. An id both
    /// stores have, in any case, is refused, since the change could reach the
    /// wrong provider and Agent Stream refuses every custom save until the
    /// custom one gets another id.
    fn find(
        self,
        id: &str,
    ) -> Result<Found> {
        check_id(id)?;
        if self.in_both_stores(id) {
            bail!(
                "'{id}' names both a built-in provider and a custom one, which a catalog refresh can cause; Agent \
                 Stream refuses to save the custom catalog until the custom one gets another id, so change it in the \
                 dashboard's custom catalog"
            );
        }
        self.locate(id)
    }

    /// The provider `id` to read. For an id both stores have, the built-in
    /// one is returned, with a warning that the custom one blocks custom
    /// saves.
    fn find_to_read(
        self,
        id: &str,
    ) -> Result<Found> {
        check_id(id)?;
        if self.in_both_stores(id) {
            eprintln!(
                "warning: '{id}' names both a built-in provider and a custom one; showing the built-in one. Agent \
                 Stream refuses every custom save until the custom one gets another id in the dashboard's custom \
                 catalog"
            );
        }
        self.locate(id)
    }

    /// Whether both stores have a provider with the id `id`, in any case.
    fn in_both_stores(
        &self,
        id: &str,
    ) -> bool {
        self.built_in
            .iter()
            .any(|provider| enum_value(provider).eq_ignore_ascii_case(id))
            && custom_providers(&self.custom)
                .iter()
                .any(|provider| enum_value(provider).eq_ignore_ascii_case(id))
    }

    /// The provider `id`, built-in first. Ids are matched exactly, as a
    /// surface names them.
    fn locate(
        self,
        id: &str,
    ) -> Result<Found> {
        if let Some(provider) = self
            .built_in
            .iter()
            .find(|provider| enum_value(provider) == id)
        {
            return Ok(Found {
                provider: provider.clone(),
                source: Source::BuiltIn,
                custom: self.custom,
            });
        }
        if let Some(provider) = custom_providers(&self.custom)
            .iter()
            .find(|provider| enum_value(provider) == id)
        {
            return Ok(Found {
                provider: provider.clone(),
                source: Source::Custom,
                custom: self.custom.clone(),
            });
        }
        bail!("the Model catalog has no provider '{id}'; see `fabric agent-stream providers list`")
    }

    /// Whether any provider, built-in or custom, has the id `id` in any case,
    /// which Agent Stream refuses for a new one.
    fn has_id(
        &self,
        id: &str,
    ) -> bool {
        self.built_in
            .iter()
            .chain(custom_providers(&self.custom))
            .any(|provider| enum_value(provider).eq_ignore_ascii_case(id))
    }
}

/// The custom catalog document as Agent Stream stores it. Its `raw` text is
/// read rather than its parsed `providers`, which leave out any entry Agent
/// Stream can't use, so a save never drops one without a word.
async fn read_custom(client: &GatewayClient) -> Result<Value> {
    let answer = client
        .request(Method::GET, CUSTOM_PATH, None)
        .await?;
    let raw = answer
        .get("raw")
        .and_then(Value::as_str)
        .context("Agent Stream did not answer with its custom catalog")?;
    if raw.trim().is_empty() {
        return Ok(json!({ "providers": [] }));
    }
    let document: Value = serde_json::from_str(raw).context(
        "Agent Stream's custom catalog is not valid JSON; fix it in the dashboard's Custom Model (JSON) tab first",
    )?;
    if !document
        .get("providers")
        .is_some_and(Value::is_array)
    {
        bail!("Agent Stream's custom catalog has no `providers` list; fix it in the dashboard first");
    }
    Ok(document)
}

fn custom_providers(custom: &Value) -> &[Value] {
    custom
        .get("providers")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn enum_value(provider: &Value) -> &str {
    text_field(provider, "enum_value")
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

/// Refuses an id Agent Stream would refuse: empty, longer than
/// [`MAX_ID_LEN`], or holding anything but ASCII letters, digits, `-` and `_`.
fn check_id(id: &str) -> Result<()> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    if id.is_empty() || id.len() > MAX_ID_LEN || !id.chars().all(allowed) {
        bail!("provider id '{}' must be 1 to {MAX_ID_LEN} letters, digits, '-', or '_'", sanitize_for_terminal(id));
    }
    Ok(())
}

/// `providers create`: checks the new provider and adds it to the custom
/// catalog.
async fn create(
    client: &GatewayClient,
    args: CreateArgs,
    output: Output,
) -> Result<()> {
    let dry_run = args.dry_run;
    let mut provider = match args.file {
        Some(file) => read_json(&file)?,
        None => {
            let (Some(id), Some(name)) = (args.id, args.name) else {
                bail!("--id and --name are required unless --file is given");
            };
            let mut provider = Map::new();
            provider.insert("enum_value".to_owned(), Value::String(id));
            provider.insert("name".to_owned(), Value::String(name));
            for (field, value) in [
                ("default_base_url", args.base_url),
                ("api_schema", args.api_schema),
                ("description", args.description),
            ] {
                if let Some(value) = value {
                    provider.insert(field.to_owned(), Value::String(value));
                }
            }
            Value::Object(provider)
        }
    };
    if let Some(fields) = provider.as_object_mut() {
        fields
            .entry("enabled")
            .or_insert(Value::Bool(!args.disabled));
    }
    check_provider(&provider)?;
    let id = enum_value(&provider).to_owned();
    let catalog = Catalog::read(client).await?;
    if catalog.has_id(&id) {
        bail!("the Model catalog already has a provider '{id}', whatever the case; choose another id");
    }
    let change = Change {
        path: format!("providers.{id}"),
        before: None,
        after: Some(provider.clone()),
    };
    if dry_run {
        println!("{}", preview(&[change], &provider, output)?);
        return Ok(());
    }
    let new = provider.clone();
    edit_custom(client, &catalog.custom, |providers| providers.push(new)).await?;
    match output {
        Output::Table => println!("{}", confirmation_line("Created", "custom provider", &id)),
        Output::Json => println!("{}", pretty_json_for_terminal(&read_back(client, &id).await?)?),
    }
    Ok(())
}

/// The provider `providers update` would save: `before` with the flags
/// applied, or the --file document.
fn updated(
    before: &Value,
    args: &UpdateArgs,
) -> Result<Value> {
    let id = enum_value(before);
    if let Some(file) = &args.file {
        let document = read_json(file)?;
        if !document.is_object() {
            bail!("the --file document must be a JSON object");
        }
        if enum_value(&document) != id {
            bail!(
                "the --file document's enum_value must be '{id}'; a provider's id can't be changed, so create a new \
                 provider instead"
            );
        }
        return Ok(document);
    }
    let patch = surface_patch::build_patch(&args.set, &args.unset, &args.add, &args.remove, before)?;
    let mut after = before.clone();
    surface_validate::merge(&mut after, &patch);
    Ok(after)
}

/// Refuses a flag path a provider can't take, before anything is read: an
/// empty one, one with brackets or a list position, which only Agent Gateway
/// paths use, or one in `enum_value`, the provider's id.
fn check_flag_paths(
    sets: &[String],
    unsets: &[String],
    adds: &[String],
    removes: &[String],
) -> Result<()> {
    let value_path = |given: &String| {
        given
            .split_once('=')
            .map_or(given.clone(), |(path, _)| path.to_owned())
    };
    let item_path =
        |given: &String| surface_patch::split_flag(given).map_or(given.clone(), |(path, _)| path.to_owned());
    let paths = sets
        .iter()
        .map(|given| ("--set", value_path(given)))
        .chain(
            unsets
                .iter()
                .map(|given| ("--unset", given.clone())),
        )
        .chain(
            adds.iter()
                .map(|given| ("--add", item_path(given))),
        )
        .chain(
            removes
                .iter()
                .map(|given| ("--remove", item_path(given))),
        );
    for (flag, path) in paths {
        if path.is_empty() {
            bail!("{flag} needs a field path, such as default_base_url");
        }
        if path.contains('[')
            || path.split('.').any(|key| {
                !key.is_empty()
                    && key
                        .chars()
                        .all(|c| c.is_ascii_digit())
            })
        {
            bail!(
                "{flag} path '{}' can't name a list item: a provider path is field names joined by '.', such as \
                 hero.title; give a list's own path to --add or --remove, or use enable-model, disable-model, or \
                 set-price for a model",
                tables::flatten(&path)
            );
        }
        if path.split('.').next() == Some("enum_value") {
            bail!("{flag} can't change `enum_value`, the provider's id; create a new provider instead");
        }
    }
    Ok(())
}

/// The model `model` of `provider`, to change in place.
fn model_mut<'a>(
    provider: &'a mut Value,
    id: &str,
    model: &str,
) -> Result<&'a mut Map<String, Value>> {
    provider
        .get_mut("models")
        .and_then(Value::as_array_mut)
        .and_then(|models| {
            models
                .iter_mut()
                .find(|candidate| text_field(candidate, "value") == model)
        })
        .and_then(Value::as_object_mut)
        .with_context(|| {
            format!(
                "provider '{id}' has no model '{}'; see `fabric agent-stream providers models {id}`",
                sanitize_for_terminal(model)
            )
        })
}

/// `providers enable-model` and `disable-model`.
async fn set_enabled(
    client: &GatewayClient,
    args: ModelArgs,
    enabled: bool,
    output: Output,
) -> Result<()> {
    let found = Catalog::read(client)
        .await?
        .find(&args.id)?;
    let mut after = found.provider.clone();
    let model = model_mut(&mut after, &args.id, &args.model)?;
    // Agent Stream treats a model with no `enabled` as enabled, so enabling
    // one leaves it as it is and sends nothing.
    if !enabled || model.contains_key("enabled") {
        model.insert("enabled".to_owned(), json!(enabled));
    }
    save(client, found, after, args.dry_run, output).await
}

/// `providers set-price`: checks the prices, then sets them on the model.
async fn set_price(
    client: &GatewayClient,
    args: SetPriceArgs,
    output: Output,
) -> Result<()> {
    for price in [args.input_price, args.output_price]
        .into_iter()
        .flatten()
    {
        check_price_value(price)?;
    }
    let found = Catalog::read(client)
        .await?
        .find(&args.id)?;
    let mut after = found.provider.clone();
    let model = model_mut(&mut after, &args.id, &args.model)?;
    if let Some(input) = args.input_price {
        model.insert("cost_per_1k_input".to_owned(), json!(input));
    }
    if let Some(price) = args.output_price {
        model.insert("cost_per_1k_output".to_owned(), json!(price));
    }
    save(client, found, after, args.dry_run, output).await
}

/// Refuses a price Agent Stream would refuse.
fn check_price_value(price: f64) -> Result<()> {
    if !price.is_finite() || !(0.0..=MAX_PRICE).contains(&price) {
        bail!("a price must be a number from 0 to {MAX_PRICE} USD per 1,000 tokens, not {price}");
    }
    Ok(())
}

/// Refuses a provider Agent Stream would refuse. Agent Stream keeps a field
/// it does not know, so field names are not checked.
fn check_provider(provider: &Value) -> Result<()> {
    let Some(fields) = provider.as_object() else {
        bail!("a provider must be a JSON object");
    };
    match fields.get("enum_value") {
        Some(Value::String(id)) => check_id(id)?,
        _ => bail!("the provider needs an `enum_value`, its id"),
    }
    if text_field(provider, "name")
        .trim()
        .is_empty()
    {
        bail!("the provider needs a `name` that is not blank");
    }
    for flag in ["enabled", "api_key_required", "requires_forward_caller_token"] {
        if fields
            .get(flag)
            .is_some_and(|value| !value.is_boolean())
        {
            bail!("the provider's `{flag}` must be true or false");
        }
    }
    if let Some(validation) = fields.get("api_key_validation")
        && !validation
            .as_str()
            .is_some_and(|value| KEY_VALIDATIONS.contains(&value))
    {
        bail!("the provider's `api_key_validation` must be mandatory, optional, or none");
    }
    let mut model_values = std::collections::BTreeSet::new();
    for model in fields
        .get("models")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
    {
        let value = text_field(model, "value");
        if !value.is_empty() && !model_values.insert(value) {
            bail!(
                "the provider has two models with the value '{}'; a model is named by its value, so each must be \
                 unique",
                sanitize_for_terminal(value)
            );
        }
    }
    for (list, required) in [("endpoints", ["name", "path"]), ("models", ["name", "value"])] {
        let Some(entries) = fields.get(list) else {
            continue;
        };
        let Some(entries) = entries.as_array() else {
            bail!("the provider's `{list}` must be a list");
        };
        for entry in entries {
            if !entry.is_object() {
                bail!("each of the provider's `{list}` must be a JSON object");
            }
            for field in required {
                if text_field(entry, field)
                    .trim()
                    .is_empty()
                {
                    bail!("each of the provider's `{list}` needs a `{field}` that is not blank");
                }
            }
            for price in ["cost_per_1k_input", "cost_per_1k_output"] {
                if let Some(value) = entry.get(price) {
                    let value = value
                        .as_f64()
                        .with_context(|| format!("`{price}` must be a number"))?;
                    check_price_value(value)?;
                }
            }
            if entry
                .get("enabled")
                .is_some_and(|value| !value.is_boolean())
            {
                bail!("the `enabled` of each of the provider's `{list}` must be true or false");
            }
        }
    }
    Ok(())
}

/// Saves `after` in place of the provider `found`: checks it, shows the
/// changes, and stops with nothing sent on a dry run, on no change, or when
/// the provider's store changed since `found` was read.
async fn save(
    client: &GatewayClient,
    found: Found,
    after: Value,
    dry_run: bool,
    output: Output,
) -> Result<()> {
    check_provider(&after)?;
    let id = enum_value(&found.provider).to_owned();
    let changes = surface_validate::changes(&found.provider, &after);
    if dry_run {
        println!("{}", preview(&changes, &after, output)?);
        return Ok(());
    }
    if changes.is_empty() {
        eprintln!("Provider '{id}' already matches, so nothing was sent.");
        if let Output::Json = output {
            println!("{}", pretty_json_for_terminal(&found.provider)?);
        }
        return Ok(());
    }
    match found.source {
        Source::BuiltIn => {
            let path = entity_path(BUILT_IN_PATH, &id);
            let current = read_built_in(client).await?;
            if !current.contains(&found.provider) {
                bail!(stale_message(&id));
            }
            client
                .request(Method::PUT, &path, Some(after))
                .await?;
        }
        Source::Custom => {
            edit_custom(client, &found.custom, |providers| {
                if let Some(slot) = providers
                    .iter_mut()
                    .find(|provider| enum_value(provider) == id)
                {
                    *slot = after;
                }
            })
            .await?;
        }
    }
    match output {
        Output::Table => {
            let mut lines = vec!["Changes:".to_owned()];
            lines.extend(change_lines(&changes));
            lines.push(confirmation_line("Updated", &format!("{} provider", found.source.label()), &id));
            println!("{}", lines.join("\n"));
        }
        Output::Json => println!("{}", pretty_json_for_terminal(&read_back(client, &id).await?)?),
    }
    Ok(())
}

/// Saves the custom catalog `before` with `edit` applied to its providers,
/// through [`save_custom`].
async fn edit_custom(
    client: &GatewayClient,
    before: &Value,
    edit: impl FnOnce(&mut Vec<Value>),
) -> Result<()> {
    let mut after = before.clone();
    if let Some(providers) = after
        .get_mut("providers")
        .and_then(Value::as_array_mut)
    {
        edit(providers);
    }
    save_custom(client, before, after).await
}

/// Sends `after` as the whole custom catalog, once a fresh read shows the
/// catalog is still `before`. Custom entries Agent Stream would refuse in
/// any save are named first, since they would block this one.
async fn save_custom(
    client: &GatewayClient,
    before: &Value,
    after: Value,
) -> Result<()> {
    let built_in = read_built_in(client).await?;
    let blocking: Vec<String> = custom_providers(before)
        .iter()
        .map(enum_value)
        .filter(|id| {
            check_id(id).is_err()
                || built_in
                    .iter()
                    .any(|provider| enum_value(provider).eq_ignore_ascii_case(id))
        })
        .map(|id| format!("'{}'", sanitize_for_terminal(id)))
        .collect();
    if !blocking.is_empty() {
        bail!(
            "the custom catalog has entries Agent Stream refuses, which block every custom save: {} (an id that is \
             not 1 to {MAX_ID_LEN} letters, digits, '-', or '_', or one a built-in provider also has); fix them in the \
             dashboard's custom catalog first",
            blocking.join(", ")
        );
    }
    if &read_custom(client).await? != before {
        bail!(
            "the custom catalog was saved by someone else after it was read, so nothing was saved; run the command \
             again to change the new version"
        );
    }
    client
        .request(Method::PUT, CUSTOM_PATH, Some(after))
        .await?;
    Ok(())
}

fn stale_message(id: &str) -> String {
    format!(
        "provider '{id}' was saved by someone else after it was read, so nothing was saved; run the command again to \
         change the new version"
    )
}

/// The provider `id` as Agent Stream has it after a save.
async fn read_back(
    client: &GatewayClient,
    id: &str,
) -> Result<Value> {
    Catalog::read(client)
        .await
        .and_then(|catalog| catalog.find(id))
        .map(|found| found.provider)
        .with_context(|| format!("provider '{id}' was saved, but reading it back failed"))
}

/// `providers delete`: deletes a built-in provider on its own, or sends the
/// custom catalog without a custom one.
async fn delete(
    client: &GatewayClient,
    id: &str,
    output: Output,
) -> Result<()> {
    let found = Catalog::read(client)
        .await?
        .find(id)?;
    let answer = match found.source {
        Source::BuiltIn => {
            client
                .request(Method::DELETE, &entity_path(BUILT_IN_PATH, id), None)
                .await?
        }
        Source::Custom => {
            edit_custom(client, &found.custom, |providers| {
                providers.retain(|provider| enum_value(provider) != id);
            })
            .await?;
            json!({ "deleted": id })
        }
    };
    match output {
        Output::Table => {
            println!("{}", confirmation_line("Deleted", &format!("{} provider", found.source.label()), id))
        }
        Output::Json => println!("{}", pretty_json_for_terminal(&answer)?),
    }
    Ok(())
}

/// What a dry run prints: the changes, or with --output json the changes and
/// the whole provider that would be saved.
fn preview(
    changes: &[Change],
    after: &Value,
    output: Output,
) -> Result<String> {
    match output {
        Output::Json => {
            let changes: Vec<Value> = changes
                .iter()
                .map(|change| json!({ "path": change.path, "before": change.before, "after": change.after }))
                .collect();
            pretty_json_for_terminal(&json!({ "dry_run": true, "changes": changes, "after": after }))
        }
        Output::Table => {
            let mut lines = vec!["Changes:".to_owned()];
            lines.extend(change_lines(changes));
            lines.push("\nDry run: nothing was saved.".to_owned());
            Ok(lines.join("\n"))
        }
    }
}

/// One line per changed field, `  path: old -> new`, or `  none`.
fn change_lines(changes: &[Change]) -> Vec<String> {
    if changes.is_empty() {
        return vec!["  none".to_owned()];
    }
    changes
        .iter()
        .map(|change| {
            format!(
                "  {}: {} -> {}",
                tables::flatten_capped(&change.path),
                describe(change.before.as_ref()),
                describe(change.after.as_ref())
            )
        })
        .collect()
}

fn describe(value: Option<&Value>) -> String {
    value.map_or_else(|| "(absent)".to_owned(), |value| tables::flatten_capped(&value.to_string()))
}

/// The row of `providers list` in table output.
fn list_row(provider: &Value) -> Value {
    let models = provider
        .get("models")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    // Agent Stream treats a provider with no `enabled` as on.
    let enabled = if provider.get("enabled") == Some(&Value::Bool(false)) {
        "no"
    } else {
        "yes"
    };
    json!({
        "enum_value": enum_value(provider),
        "name": text_field(provider, "name"),
        "source": text_field(provider, "source"),
        "enabled": enabled,
        "model_count": models,
    })
}

/// The row of `providers models` in table output.
fn model_row(model: &Value) -> Value {
    let enabled = if model.get("enabled") == Some(&Value::Bool(false)) {
        "no"
    } else {
        "yes"
    };
    let mut row = json!({
        "value": text_field(model, "value"),
        "name": text_field(model, "name"),
        "enabled": enabled,
    });
    for price in ["cost_per_1k_input", "cost_per_1k_output"] {
        if let Some(value) = model.get(price) {
            row[price] = value.clone();
        }
    }
    row
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        super::test_support::{
            Route, json_file, request_body, run_stream, saved_login, scripted_agent_stream, sends_bearer, start_lines,
        },
        *,
    };

    const ACCESS_TOKEN: &str = "aspat_live-secret";

    const BUILT_IN: &str = r#"{"providers":[{"enum_value":"openai","name":"OpenAI","enabled":true,
        "models":[{"name":"GPT-4o mini","value":"gpt-4o-mini","cost_per_1k_input":0.00015},
                  {"name":"GPT-4o","value":"gpt-4o","enabled":false}]}]}"#;
    const BUILT_IN_LATER: &str = r#"{"providers":[{"enum_value":"openai","name":"OpenAI v2","enabled":true,
        "models":[{"name":"GPT-4o mini","value":"gpt-4o-mini","cost_per_1k_input":0.00015},
                  {"name":"GPT-4o","value":"gpt-4o","enabled":false}]}]}"#;
    const CUSTOM: &str = r#"{"raw":"{\"providers\":[{\"enum_value\":\"acme\",\"name\":\"Acme\",\"models\":[{\"name\":\"A\",\"value\":\"a\"}]},{\"enum_value\":\"other\",\"name\":\"Other\",\"extra\":1}]}","providers":[]}"#;
    const CUSTOM_LATER: &str =
        r#"{"raw":"{\"providers\":[{\"enum_value\":\"acme\",\"name\":\"Acme 2\"}]}","providers":[]}"#;

    const GET_BUILT_IN: Route = ("GET /api/v1/llm-providers", "HTTP/1.1 200 OK", BUILT_IN);
    const GET_CUSTOM: Route = ("GET /api/v1/llm-providers/custom", "HTTP/1.1 200 OK", CUSTOM);
    const PUT_CUSTOM: Route = ("PUT /api/v1/llm-providers/custom", "HTTP/1.1 200 OK", r#"{"providers":[]}"#);
    const PUT_OPENAI: Route = ("PUT /api/v1/llm-providers/openai", "HTTP/1.1 200 OK", "{}");

    async fn run_providers(
        words: &[&str],
        routes: Vec<Route>,
    ) -> (Result<()>, Arc<Mutex<Vec<String>>>) {
        let (host, requests) = scripted_agent_stream(routes).await;
        let (saved, credentials) = saved_login(&host, ACCESS_TOKEN);
        let result = run_stream(words, saved, &credentials).await;
        (result, requests)
    }

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

    fn sent_writes(requests: &Arc<Mutex<Vec<String>>>) -> usize {
        start_lines(requests)
            .iter()
            .filter(|line| line.starts_with("PUT") || line.starts_with("DELETE"))
            .count()
    }

    #[tokio::test]
    async fn list_reads_both_stores_with_the_token() {
        let (result, requests) = run_providers(&["providers", "list"], vec![GET_BUILT_IN, GET_CUSTOM]).await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests),
            ["GET /api/v1/llm-providers HTTP/1.1", "GET /api/v1/llm-providers/custom HTTP/1.1"]
        );
        assert!(sends_bearer(&requests.lock().unwrap()[0], ACCESS_TOKEN));
    }

    #[test]
    fn the_list_marks_each_provider_with_its_source_and_reads_custom_from_the_raw_document() {
        let catalog = Catalog {
            built_in: serde_json::from_str::<Value>(BUILT_IN).unwrap()["providers"]
                .as_array()
                .unwrap()
                .clone(),
            custom: serde_json::from_str(
                serde_json::from_str::<Value>(CUSTOM).unwrap()["raw"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        };
        let rows: Vec<Value> = catalog
            .listed()
            .iter()
            .map(list_row)
            .collect();
        assert_eq!(
            rows,
            [
                json!({"enum_value":"openai","name":"OpenAI","source":"built-in","enabled":"yes","model_count":2}),
                json!({"enum_value":"acme","name":"Acme","source":"custom","enabled":"yes","model_count":1}),
                json!({"enum_value":"other","name":"Other","source":"custom","enabled":"yes","model_count":0}),
            ]
        );
        assert!(catalog.has_id("OpenAI"));
        assert!(!catalog.has_id("new"));
    }

    #[tokio::test]
    async fn create_adds_the_provider_to_the_custom_catalog_after_a_second_read() {
        let (result, requests) = run_providers(
            &["providers", "create", "--id", "new-llm", "--name", "New", "--base-url", "https://llm.example"],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_CUSTOM],
        )
        .await;
        result.unwrap();
        assert_eq!(
            start_lines(&requests),
            [
                "GET /api/v1/llm-providers HTTP/1.1",
                "GET /api/v1/llm-providers/custom HTTP/1.1",
                "GET /api/v1/llm-providers HTTP/1.1",
                "GET /api/v1/llm-providers/custom HTTP/1.1",
                "PUT /api/v1/llm-providers/custom HTTP/1.1",
            ]
        );
        let sent = body_of(&requests, 4);
        let providers = sent["providers"]
            .as_array()
            .unwrap();
        assert_eq!(providers.len(), 3);
        assert_eq!(providers[1], json!({"enum_value":"other","name":"Other","extra":1}));
        assert_eq!(
            providers[2],
            json!({"enum_value":"new-llm","name":"New","default_base_url":"https://llm.example","enabled":true})
        );
    }

    #[tokio::test]
    async fn create_refuses_an_id_in_use_in_any_case_and_a_dry_run_sends_nothing() {
        let (result, requests) = run_providers(
            &["providers", "create", "--id", "OpenAI", "--name", "Copy"],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_CUSTOM],
        )
        .await;
        assert!(error_text(result).contains("already has a provider 'OpenAI'"));
        assert_eq!(sent_writes(&requests), 0);

        let (result, requests) = run_providers(
            &["providers", "create", "--id", "new-llm", "--name", "New", "--dry-run"],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_CUSTOM],
        )
        .await;
        result.unwrap();
        assert_eq!(sent_writes(&requests), 0);
    }

    #[tokio::test]
    async fn create_refuses_a_provider_agent_stream_would_refuse_before_reading_anything() {
        for (document, expected) in [
            (r#"{"name":"X"}"#, "`enum_value`"),
            (r#"{"enum_value":"bad id","name":"X"}"#, "provider id 'bad id'"),
            (r#"{"enum_value":"x","name":" "}"#, "`name` that is not blank"),
            (r#"{"enum_value":"x","name":"X","api_key_validation":"always"}"#, "mandatory, optional, or none"),
            (r#"{"enum_value":"x","name":"X","models":[{"name":"M"}]}"#, "`value`"),
            (r#"{"enum_value":"x","name":"X","endpoints":[{"name":"E"}]}"#, "`path`"),
            (
                r#"{"enum_value":"x","name":"X","models":[{"name":"M","value":"m","cost_per_1k_output":101}]}"#,
                "from 0 to 100",
            ),
        ] {
            let file = json_file(document);
            let (result, requests) =
                run_providers(&["providers", "create", "--file", file.path().to_str().unwrap()], vec![]).await;
            assert!(error_text(result).contains(expected), "{document}");
            assert!(start_lines(&requests).is_empty(), "{document}");
        }
    }

    #[tokio::test]
    async fn disable_model_on_a_built_in_provider_replaces_that_provider_only() {
        let (result, requests) = run_providers(
            &["providers", "disable-model", "openai", "gpt-4o-mini"],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_OPENAI],
        )
        .await;
        result.unwrap();
        let lines = start_lines(&requests);
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert_eq!(lines[3], "PUT /api/v1/llm-providers/openai HTTP/1.1");
        let sent = body_of(&requests, 3);
        assert_eq!(sent["models"][0]["enabled"], json!(false));
        assert_eq!(sent["models"][0]["cost_per_1k_input"], json!(0.00015));
    }

    #[tokio::test]
    async fn set_price_on_a_custom_provider_sends_the_whole_custom_catalog_with_only_that_model_changed() {
        let (result, requests) = run_providers(
            &["providers", "set-price", "acme", "a", "--input-price", "0.5", "--output-price", "1.5"],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_CUSTOM],
        )
        .await;
        result.unwrap();
        let lines = start_lines(&requests);
        assert_eq!(lines[4], "PUT /api/v1/llm-providers/custom HTTP/1.1");
        assert_eq!(
            body_of(&requests, 4),
            json!({"providers":[
                {"enum_value":"acme","name":"Acme","models":[{"name":"A","value":"a","cost_per_1k_input":0.5,"cost_per_1k_output":1.5}]},
                {"enum_value":"other","name":"Other","extra":1}]})
        );
    }

    #[tokio::test]
    async fn a_price_out_of_range_or_an_unknown_model_is_refused_before_saving() {
        let (result, requests) = run_providers(
            &["providers", "set-price", "acme", "a", "--input-price", "250"],
            vec![GET_BUILT_IN, GET_CUSTOM],
        )
        .await;
        assert!(error_text(result).contains("from 0 to 100"));
        assert!(start_lines(&requests).is_empty());

        let (result, requests) =
            run_providers(&["providers", "enable-model", "acme", "nope"], vec![GET_BUILT_IN, GET_CUSTOM]).await;
        assert!(error_text(result).contains("has no model 'nope'"));
        assert_eq!(sent_writes(&requests), 0);
    }

    #[tokio::test]
    async fn a_store_saved_after_it_was_read_stops_the_save() {
        let (result, requests) = run_providers(
            &["providers", "update", "acme", "--set", "description=x"],
            vec![
                GET_BUILT_IN,
                GET_CUSTOM,
                ("GET /api/v1/llm-providers/custom", "HTTP/1.1 200 OK", CUSTOM_LATER),
                PUT_CUSTOM,
            ],
        )
        .await;
        assert!(error_text(result).contains("custom catalog was saved by someone else"));
        assert_eq!(sent_writes(&requests), 0);

        let (result, requests) = run_providers(
            &["providers", "enable-model", "openai", "gpt-4o"],
            vec![
                GET_BUILT_IN,
                GET_CUSTOM,
                ("GET /api/v1/llm-providers", "HTTP/1.1 200 OK", BUILT_IN_LATER),
                PUT_OPENAI,
            ],
        )
        .await;
        assert!(error_text(result).contains("provider 'openai' was saved by someone else"));
        assert_eq!(sent_writes(&requests), 0);
    }

    #[tokio::test]
    async fn update_flags_can_t_name_a_list_item_or_the_id_and_a_file_can_t_rename() {
        for (flag, expected) in [
            ("models[a].enabled=false", "can't name a list item"),
            ("models.0.enabled=false", "can't name a list item"),
            ("enum_value=renamed", "can't change `enum_value`"),
        ] {
            let (result, requests) =
                run_providers(&["providers", "update", "acme", "--set", flag], vec![GET_BUILT_IN, GET_CUSTOM]).await;
            assert!(error_text(result).contains(expected), "{flag}");
            assert!(start_lines(&requests).is_empty(), "{flag}: checked before anything is read");
        }
        let file = json_file(r#"{"enum_value":"renamed","name":"Acme"}"#);
        let (result, requests) = run_providers(
            &["providers", "update", "acme", "--file", file.path().to_str().unwrap()],
            vec![GET_BUILT_IN, GET_CUSTOM],
        )
        .await;
        assert!(error_text(result).contains("enum_value must be 'acme'"));
        assert_eq!(sent_writes(&requests), 0);
    }

    #[tokio::test]
    async fn update_with_no_change_or_a_dry_run_sends_nothing() {
        for words in [
            &["providers", "update", "acme", "--set", "name=Acme"][..],
            &["providers", "update", "acme", "--set", "name=New", "--dry-run"],
        ] {
            let (result, requests) = run_providers(words, vec![GET_BUILT_IN, GET_CUSTOM, PUT_CUSTOM]).await;
            result.unwrap();
            assert_eq!(start_lines(&requests).len(), 2, "{words:?}");
        }
    }

    #[tokio::test]
    async fn delete_uses_the_route_of_the_store_the_provider_is_in() {
        let (result, requests) = run_providers(
            &["providers", "delete", "openai"],
            vec![
                GET_BUILT_IN,
                GET_CUSTOM,
                ("DELETE /api/v1/llm-providers/openai", "HTTP/1.1 200 OK", r#"{"deleted":"openai"}"#),
            ],
        )
        .await;
        result.unwrap();
        assert_eq!(start_lines(&requests)[2], "DELETE /api/v1/llm-providers/openai HTTP/1.1");

        let (result, requests) =
            run_providers(&["providers", "delete", "acme"], vec![GET_BUILT_IN, GET_CUSTOM, PUT_CUSTOM]).await;
        result.unwrap();
        assert_eq!(body_of(&requests, 4), json!({"providers":[{"enum_value":"other","name":"Other","extra":1}]}));
    }

    #[tokio::test]
    async fn a_custom_catalog_that_is_not_json_is_reported_and_nothing_is_saved() {
        let broken = r#"{"raw":"{not json","providers":[]}"#;
        let (result, requests) = run_providers(
            &["providers", "list"],
            vec![GET_BUILT_IN, ("GET /api/v1/llm-providers/custom", "HTTP/1.1 200 OK", broken)],
        )
        .await;
        assert!(error_text(result).contains("custom catalog is not valid JSON"));
        assert_eq!(sent_writes(&requests), 0);
    }

    #[tokio::test]
    async fn get_finds_a_custom_provider_and_an_unknown_one_is_refused() {
        let (result, _) = run_providers(&["providers", "get", "acme"], vec![GET_BUILT_IN, GET_CUSTOM]).await;
        result.unwrap();
        let (result, _) = run_providers(&["providers", "get", "nope"], vec![GET_BUILT_IN, GET_CUSTOM]).await;
        assert!(error_text(result).contains("has no provider 'nope'"));
    }

    #[tokio::test]
    async fn an_update_file_for_a_built_in_provider_replaces_it() {
        let file = json_file(r#"{"enum_value":"openai","name":"OpenAI","description":"new","models":[]}"#);
        let (result, requests) = run_providers(
            &["providers", "update", "openai", "--file", file.path().to_str().unwrap()],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_OPENAI],
        )
        .await;
        result.unwrap();
        assert_eq!(
            body_of(&requests, 3),
            json!({"enum_value":"openai","name":"OpenAI","description":"new","models":[]})
        );
    }

    #[tokio::test]
    async fn a_second_model_with_the_same_value_is_refused() {
        let (result, requests) = run_providers(
            &["providers", "update", "acme", "--add", r#"models={"name":"Other name","value":"a"}"#],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_CUSTOM],
        )
        .await;
        assert!(error_text(result).contains("two models with the value 'a'"));
        assert_eq!(sent_writes(&requests), 0);
    }

    #[tokio::test]
    async fn a_custom_entry_agent_stream_refuses_is_named_and_an_id_in_both_stores_is_refused() {
        let clashing = r#"{"raw":"{\"providers\":[{\"enum_value\":\"acme\",\"name\":\"Acme\"},{\"enum_value\":\"OPENAI\",\"name\":\"Copy\"}]}","providers":[]}"#;
        let routes =
            || vec![GET_BUILT_IN, ("GET /api/v1/llm-providers/custom", "HTTP/1.1 200 OK", clashing), PUT_CUSTOM];
        let (result, requests) =
            run_providers(&["providers", "update", "acme", "--set", "description=x"], routes()).await;
        let text = error_text(result);
        assert!(text.contains("block every custom save: 'OPENAI'"), "{text}");
        assert_eq!(sent_writes(&requests), 0);

        let (result, requests) = run_providers(&["providers", "delete", "openai"], routes()).await;
        assert!(error_text(result).contains("names both a built-in provider and a custom one"));
        assert_eq!(sent_writes(&requests), 0);
        let (result, requests) = run_providers(&["providers", "enable-model", "openai", "gpt-4o"], routes()).await;
        assert!(error_text(result).contains("names both a built-in provider and a custom one"));
        assert_eq!(sent_writes(&requests), 0);

        // Reads still work, returning the built-in one with a warning.
        for words in [&["providers", "get", "openai"][..], &["providers", "models", "openai"]] {
            let (result, requests) = run_providers(words, routes()).await;
            result.unwrap_or_else(|error| panic!("{words:?}: {error:#}"));
            assert_eq!(sent_writes(&requests), 0, "{words:?}");
        }
        let catalog = Catalog {
            built_in: serde_json::from_str::<Value>(BUILT_IN).unwrap()["providers"]
                .as_array()
                .unwrap()
                .clone(),
            custom: json!({"providers":[{"enum_value":"OPENAI","name":"Copy"}]}),
        };
        assert_eq!(
            catalog
                .find_to_read("openai")
                .unwrap()
                .source,
            Source::BuiltIn
        );
    }

    #[tokio::test]
    async fn enabling_a_model_enabled_by_default_sends_nothing() {
        let (result, requests) = run_providers(
            &["providers", "enable-model", "openai", "gpt-4o-mini"],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_OPENAI],
        )
        .await;
        result.unwrap();
        assert_eq!(sent_writes(&requests), 0);
        assert_eq!(start_lines(&requests).len(), 2);
    }

    #[test]
    fn a_dry_run_in_json_shows_dry_run_the_changes_and_the_whole_provider() {
        let before = json!({"enum_value":"acme","name":"Acme"});
        let after = json!({"enum_value":"acme","name":"Acme","description":"x"});
        let changes = surface_validate::changes(&before, &after);
        let printed: Value = serde_json::from_str(&preview(&changes, &after, Output::Json).unwrap()).unwrap();
        assert_eq!(
            printed,
            json!({"dry_run":true,"changes":[{"path":"description","before":null,"after":"x"}],"after":after})
        );
        let table = preview(&changes, &after, Output::Table).unwrap();
        assert_eq!(table, "Changes:\n  description: (absent) -> \"x\"\n\nDry run: nothing was saved.");
    }

    #[tokio::test]
    async fn an_empty_custom_catalog_reads_as_no_custom_providers() {
        let (result, _) = run_providers(
            &["providers", "get", "openai"],
            vec![
                GET_BUILT_IN,
                ("GET /api/v1/llm-providers/custom", "HTTP/1.1 200 OK", r#"{"raw":"  ","providers":[]}"#),
            ],
        )
        .await;
        result.unwrap();
    }

    #[tokio::test]
    async fn create_saves_enabled_unless_disabled_or_set_by_the_file() {
        let last_provider = |requests: &Arc<Mutex<Vec<String>>>| {
            let index = start_lines(requests).len() - 1;
            body_of(requests, index)["providers"][2].clone()
        };
        let (result, requests) = run_providers(
            &["providers", "create", "--id", "off-llm", "--name", "Off", "--disabled"],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_CUSTOM],
        )
        .await;
        result.unwrap();
        assert_eq!(last_provider(&requests), json!({"enum_value":"off-llm","name":"Off","enabled":false}));

        let file = json_file(r#"{"enum_value":"file-llm","name":"File","enabled":false}"#);
        let (result, requests) = run_providers(
            &["providers", "create", "--file", file.path().to_str().unwrap()],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_CUSTOM],
        )
        .await;
        result.unwrap();
        assert_eq!(last_provider(&requests)["enabled"], json!(false));

        let file = json_file(r#"{"enum_value":"plain-llm","name":"Plain"}"#);
        let (result, requests) = run_providers(
            &["providers", "create", "--file", file.path().to_str().unwrap()],
            vec![GET_BUILT_IN, GET_CUSTOM, PUT_CUSTOM],
        )
        .await;
        result.unwrap();
        assert_eq!(last_provider(&requests)["enabled"], json!(true));
    }

    #[test]
    fn no_providers_flag_takes_a_key() {
        use clap::CommandFactory;
        let mut cli = crate::commands::Cli::command();
        cli.build();
        let providers = cli
            .find_subcommand("agent-stream")
            .and_then(|stream| stream.find_subcommand("providers"))
            .expect("providers group");
        for command in providers.get_subcommands() {
            for arg in command.get_arguments() {
                let name = arg
                    .get_long()
                    .unwrap_or_default();
                assert!(!name.contains("key") && !name.contains("secret"), "{} --{name}", command.get_name());
            }
        }
    }
}
