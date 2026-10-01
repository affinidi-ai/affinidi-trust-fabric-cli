//! The one table every `list` command prints: a header row, columns padded to
//! line up, and a short line when there is nothing to show.

use serde_json::Value;

use crate::client::{sanitize_for_terminal, sanitize_whole};

/// Longest a normal cell gets before it is cut short with `...`.
const NORMAL_WIDTH: usize = 40;
/// Longest a cell for a URL or DID gets before it is cut short.
const WIDE_WIDTH: usize = 60;

/// One column of a list: its header and where to find its value in a row.
pub struct Column {
    header: &'static str,
    /// Dotted paths into the row, tried in order. The first one with a value wins.
    keys: &'static [&'static str],
    max_width: usize,
    /// What to print when the row has no value, for a column where a missing
    /// value means something other than "nothing".
    when_empty: &'static str,
}

/// Why a list came back empty, which decides the line printed for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Nothing was asked for but everything: an empty list means none yet.
    All,
    /// A filter was given: an empty list means nothing matched it.
    Filtered,
    /// Some of the sources failed: an empty list means nothing came back.
    Partial,
}

/// The columns of one resource's list, and what to print when it is empty.
pub struct Layout {
    empty: &'static str,
    columns: &'static [Column],
}

const fn col(
    header: &'static str,
    keys: &'static [&'static str],
) -> Column {
    Column {
        header,
        keys,
        max_width: NORMAL_WIDTH,
        when_empty: "-",
    }
}

const fn wide(
    header: &'static str,
    keys: &'static [&'static str],
) -> Column {
    Column {
        header,
        keys,
        max_width: WIDE_WIDTH,
        when_empty: "-",
    }
}

/// A column of identifiers (ID, DID, client ID and the like) is never cut
/// short, since people copy them into the next command.
const fn whole(
    header: &'static str,
    keys: &'static [&'static str],
) -> Column {
    Column {
        header,
        keys,
        max_width: usize::MAX,
        when_empty: "-",
    }
}

impl Column {
    /// Prints `text` instead of `-` when the row has no value.
    const fn or(
        mut self,
        text: &'static str,
    ) -> Self {
        self.when_empty = text;
        self
    }
}

const fn id(keys: &'static [&'static str]) -> Column {
    whole("ID", keys)
}

pub static GENERIC: Layout = Layout {
    empty: "No items yet.",
    columns: &[
        whole("NAME", &["name", "username", "did"]),
        id(&["surface_id", "id", "gateway_id", "connection_point_id", "user_id", "key_id"]),
        whole("DESCRIPTION", &["description"]),
    ],
};

pub static PAYMENTS: Layout = Layout {
    empty: "No payments yet.",
    columns: &[
        id(&["id"]),
        col("STORE", &["store"]),
        whole("SURFACE", &["surface_id"]),
        col("STATUS", &["status"]),
        col("AMOUNT", &["amount"]),
        col("CURRENCY", &["currency"]),
        col("CREATED", &["created_at"]),
    ],
};

pub static AUDIT: Layout = Layout {
    empty: "No audit events yet.",
    columns: &[
        whole("TIMESTAMP", &["timestamp"]),
        col("EVENT", &["event"]),
        whole("SURFACE", &["surface_id"]),
        col("DECISION", &["decision"]),
        wide("DETAIL", &["detail"]),
    ],
};

pub static TOKENS: Layout = Layout {
    empty: "No access tokens yet.",
    columns: &[
        whole("NAME", &["name"]),
        id(&["id"]),
        col("STATUS", &["status"]),
        col("SCOPES", &["scopes"]),
        col("CREATED", &["created_at"]),
        col("EXPIRES", &["expires_at"]),
    ],
};

pub static POLICY_VERSIONS: Layout = Layout {
    empty: "No versions yet.",
    columns: &[
        col("VERSION", &["version"]),
        whole("HASH", &["content_hash"]),
        col("CREATED", &["created_at"]),
        col("BY", &["created_by"]),
        col("NOTE", &["note"]),
    ],
};

pub static SURFACES: Layout = Layout {
    empty: "No surfaces yet.",
    columns: &[
        whole("NAME", &["name"]),
        id(&["surface_id", "id"]),
        col("PROTOCOL", &["access_point.protocol"]),
        col("ROUTE", &["access_point.route"]),
        wide("TARGET", &["target.endpoint"]),
        col("TRANSIT POINTS", &["transit.points"]),
    ],
};

pub static POLICIES: Layout = Layout {
    empty: "No policies yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["id"]),
        col("DESCRIPTION", &["description"]),
        col("ENABLED", &["enabled"]),
        col("VERSION", &["version"]),
        col("UPDATED", &["updated_at"]),
    ],
};

pub static CONNECTIONS: Layout = Layout {
    empty: "No connections yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["id", "gateway_id"]),
        col("TYPE", &["gateway_type"]),
        col("STATUS", &["status"]),
        col("UPDATED", &["updated_at"]),
    ],
};

pub static CONNECTION_POINTS: Layout = Layout {
    empty: "No connection points yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["connection_point_id", "id"]),
        whole("CONNECTION", &["gateway_id"]),
        col("ENABLED", &["enabled"]),
        col("USES", &["use_count"]),
        col("EXPIRES", &["expires_at"]).or("never"),
    ],
};

pub static ISSUERS: Layout = Layout {
    empty: "No issuers yet.",
    columns: &[col("NAME", &["name"]), id(&["id"]), whole("DID", &["did"]), col("DESCRIPTION", &["description"])],
};

pub static AUTHORITIES: Layout = Layout {
    empty: "No authorities yet.",
    columns: &[col("NAME", &["name"]), id(&["id"]), whole("DID", &["did"]), col("DESCRIPTION", &["description"])],
};

pub static TRUST_REGISTRIES: Layout = Layout {
    empty: "No trust registries yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["id"]),
        whole("DID", &["did", "main_did"]),
        col("DESCRIPTION", &["description"]),
    ],
};

pub static MEDIATORS: Layout = Layout {
    empty: "No mediators yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["id"]),
        col("STATUS", &["status"]),
        whole("DID", &["did"]),
        col("DESCRIPTION", &["description"]),
    ],
};

pub static MCP_PROXIES: Layout = Layout {
    empty: "No MCP proxies yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["id"]),
        col("STATUS", &["status"]),
        wide("BASE URL", &["base_url"]),
        col("DESCRIPTION", &["description"]),
    ],
};

pub static A2A_PROXIES: Layout = Layout {
    empty: "No A2A proxies yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["id"]),
        col("STATUS", &["status"]),
        col("DESCRIPTION", &["description"]),
        col("UPDATED", &["updated_at"]),
    ],
};

pub static STS_CLIENTS: Layout = Layout {
    empty: "No STS clients yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["id"]),
        whole("CLIENT ID", &["client_id"]),
        col("SCOPES", &["allowed_scopes"]).or("any"),
    ],
};

pub static CREDENTIAL_PROVIDERS: Layout = Layout {
    empty: "No credential providers yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["id"]),
        whole("PROVIDER ID", &["provider_id"]),
        col("TYPE", &["provider_type"]),
    ],
};

pub static INTEGRATIONS: Layout = Layout {
    empty: "No integrations yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["id"]),
        col("TYPE", &["type"]),
        col("STATUS", &["status"]),
        col("DESCRIPTION", &["description"]),
    ],
};

pub static USERS: Layout = Layout {
    empty: "No users yet.",
    columns: &[
        col("USERNAME", &["username"]),
        id(&["user_id", "id"]),
        col("ROLE", &["role"]),
        col("STATUS", &["status"]),
        col("EMAIL", &["email"]),
    ],
};

pub static JWT_STRATEGIES: Layout = Layout {
    empty: "No JWT verification strategies yet.",
    columns: &[
        col("NAME", &["name"]),
        id(&["id"]),
        wide("ISSUER", &["expected_issuer"]),
        col("UPDATED", &["updated_at"]),
    ],
};

pub static SECRETS: Layout = Layout {
    empty: "No secrets yet.",
    columns: &[
        whole("NAME", &["name"]),
        id(&["id"]),
        whole("SECRET ID", &["secret_id"]),
        col("TYPE", &["secret_type"]),
        col("DESCRIPTION", &["description"]),
    ],
};

pub static CERTIFICATES: Layout = Layout {
    empty: "No certificates yet.",
    columns: &[
        whole("NAME", &["name"]),
        id(&["id"]),
        col("KIND", &["kind"]),
        col("ACTIVE", &["active"]),
        col("UPDATED", &["updated_at"]),
    ],
};

pub static IDENTITIES: Layout = Layout {
    empty: "No identities yet.",
    columns: &[
        whole("DID", &["did"]),
        id(&["id"]),
        col("VERSION", &["version"]),
        col("ACTIVE", &["active"]),
        col("UPDATED", &["updated_at"]),
    ],
};

pub static GRANTS: Layout = Layout {
    empty: "No grants yet.",
    columns: &[
        id(&["id"]),
        whole("AGENT DID", &["agent_did"]),
        whole("PROVIDER", &["provider_id"]),
        col("EXPIRES", &["expires_at"]).or("never"),
        col("EXPIRED", &["is_expired"]),
    ],
};

pub static API_KEYS: Layout = Layout {
    empty: "No API keys yet.",
    columns: &[
        whole("KEY ID", &["key_id"]),
        whole("SURFACE", &["agent_id"]),
        whole("CLIENT ID", &["client_id"]),
        col("STATUS", &["status"]),
    ],
};

pub static CONNECTION_SETTINGS: Layout = Layout {
    empty: "No gateway connections yet.",
    columns: &[whole("NAME", &["name"]), whole("HOST", &["host"]), col("CURRENT", &["current"])],
};

/// Renders a list as a header row and one row per entry, or the layout's
/// "nothing yet" line when the list is empty. Rows that are not objects are
/// printed as they are, one per line.
#[cfg(test)]
pub fn render_list(
    layout: &Layout,
    rows: &[Value],
) -> Vec<String> {
    render_scoped(layout, rows, Scope::All)
}

/// Like [`render_list`], with the empty line worded for why the list is empty:
/// `No secrets yet.`, `No matching secrets.` or `No secrets returned.`
pub fn render_scoped(
    layout: &Layout,
    rows: &[Value],
    scope: Scope,
) -> Vec<String> {
    if rows.is_empty() {
        return vec![empty_line(layout, scope)];
    }
    if rows
        .iter()
        .any(|row| !row.is_object())
    {
        return rows
            .iter()
            .map(|row| table_cell(&row.to_string()))
            .collect();
    }
    let header: Vec<&str> = layout
        .columns
        .iter()
        .map(|column| column.header)
        .collect();
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            layout
                .columns
                .iter()
                .map(|column| cell(row, column))
                .collect()
        })
        .collect();
    format_rows(&header, &body)
}

/// Lays out a header and rows as space-padded columns with a 2-space gap. A
/// column is as wide as its widest cell, counted in characters so accented
/// names line up, though wide characters (CJK, emoji) take two screen cells and
/// can still shift the columns. The last column is left unpadded so lines carry
/// no trailing spaces.
pub fn format_rows<H: AsRef<str>>(
    header: &[H],
    rows: &[Vec<String>],
) -> Vec<String> {
    let mut widths: Vec<usize> = header
        .iter()
        .map(|cell| cell.as_ref().chars().count())
        .collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let format_row = |cells: &[&str]| -> String {
        let last = cells.len().saturating_sub(1);
        cells
            .iter()
            .enumerate()
            .map(|(index, cell)| {
                if index == last {
                    (*cell).to_owned()
                } else {
                    let padding = widths[index].saturating_sub(cell.chars().count());
                    format!("{cell}{}", " ".repeat(padding))
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut lines = Vec::with_capacity(rows.len() + 1);
    let header: Vec<&str> = header
        .iter()
        .map(AsRef::as_ref)
        .collect();
    lines.push(format_row(&header));
    for row in rows {
        let cells: Vec<&str> = row
            .iter()
            .map(String::as_str)
            .collect();
        lines.push(format_row(&cells));
    }
    lines
}

/// Text on one line that is safe to print: line breaks, tabs and carriage
/// returns become spaces, control characters are dropped, and nothing is cut.
/// Used for ids the user typed and for columns that print whole.
pub fn flatten(text: &str) -> String {
    sanitize_whole(&text.replace(['\n', '\t', '\r'], " "))
}

/// Like [`flatten`], but cut at the length cap of [`sanitize_for_terminal`],
/// for text of unknown length that goes inside a message.
pub fn flatten_capped(text: &str) -> String {
    sanitize_for_terminal(&text.replace(['\n', '\t', '\r'], " "))
}

/// Makes text from the gateway safe to print in one table cell, with `-` when
/// nothing printable is left. See [`flatten_capped`].
pub fn table_cell(text: &str) -> String {
    dash_if_blank(flatten_capped(text))
}

/// Same as [`table_cell`] without the length cap, for a column that prints
/// its value whole.
pub fn whole_cell(text: &str) -> String {
    dash_if_blank(flatten(text))
}

fn dash_if_blank(cell: String) -> String {
    if cell.trim().is_empty() {
        "-".to_owned()
    } else {
        cell
    }
}

fn cell(
    row: &Value,
    column: &Column,
) -> String {
    let Some(text) = column
        .keys
        .iter()
        .find_map(|key| value_text(lookup(row, key)?, column.max_width))
    else {
        return column.when_empty.to_owned();
    };
    if column.max_width == usize::MAX {
        return whole_cell(&text);
    }
    shorten(&table_cell(&text), column.max_width)
}

fn lookup<'a>(
    row: &'a Value,
    path: &str,
) -> Option<&'a Value> {
    path.split('.')
        .try_fold(row, |value, key| value.get(key))
}

/// Turns one gateway value into cell text. Yes or no for a flag, names joined
/// with commas for a list, and nothing for an empty or missing value.
fn value_text(
    value: &Value,
    max_width: usize,
) -> Option<String> {
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Bool(true) => "yes".to_owned(),
        Value::Bool(false) => "no".to_owned(),
        Value::Number(number) => number.to_string(),
        Value::Array(items) => list_text(items, max_width),
        Value::Null | Value::Object(_) => String::new(),
    };
    (!text.trim().is_empty()).then_some(text)
}

fn empty_line(
    layout: &Layout,
    scope: Scope,
) -> String {
    let noun = layout
        .empty
        .strip_prefix("No ")
        .and_then(|rest| rest.strip_suffix(" yet."));
    match (scope, noun) {
        (Scope::Filtered, Some(noun)) => format!("No matching {noun}."),
        (Scope::Partial, Some(noun)) => format!("No {noun} returned."),
        _ => layout.empty.to_owned(),
    }
}

/// The names in a list cell, comma-joined to fit `max_width`. Names that do
/// not fit, and items with no name, are counted in a `+N more` suffix that is
/// always kept whole.
fn list_text(
    items: &[Value],
    max_width: usize,
) -> String {
    let names: Vec<String> = items
        .iter()
        .filter_map(|item| match item {
            Value::String(text) => Some(text.clone()),
            Value::Object(object) => ["alias", "name", "id"]
                .iter()
                .find_map(|key| {
                    object
                        .get(*key)
                        .and_then(Value::as_str)
                })
                .map(str::to_owned),
            _ => None,
        })
        .collect();
    let unnamed = items.len() - names.len();
    if names.is_empty() && !items.is_empty() {
        return format!("{} items", items.len());
    }
    let all = names.join(",");
    if unnamed == 0 && all.chars().count() <= max_width {
        return all;
    }
    let mut shown = String::new();
    let mut shown_count = 0;
    for name in &names {
        let candidate = if shown.is_empty() {
            name.clone()
        } else {
            format!("{shown},{name}")
        };
        let hidden = names.len() - shown_count - 1 + unnamed;
        let suffix = if hidden > 0 {
            format!(" +{hidden} more")
                .chars()
                .count()
        } else {
            0
        };
        if candidate.chars().count() + suffix > max_width {
            break;
        }
        shown = candidate;
        shown_count += 1;
    }
    let hidden = names.len() - shown_count + unnamed;
    match (shown.is_empty(), hidden) {
        (_, 0) => shown,
        (true, hidden) => format!("+{hidden} more"),
        (false, hidden) => format!("{shown} +{hidden} more"),
    }
}

fn shorten(
    text: &str,
    max_width: usize,
) -> String {
    if text.chars().count() <= max_width {
        return text.to_owned();
    }
    let kept: String = text
        .chars()
        .take(max_width.saturating_sub(3))
        .collect();
    format!("{kept}...")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_list_prints_a_header_and_lines_the_columns_up() {
        let rows = [
            json!({"name": "Sales", "surface_id": "s-1", "access_point": {"protocol": "mcp", "route": "/sales"}}),
            json!({"name": "Customer support", "surface_id": "s-22", "access_point": {"protocol": "a2a", "route": "/help"}}),
        ];

        let lines = render_list(&SURFACES, &rows);

        assert_eq!(lines[0], "NAME              ID    PROTOCOL  ROUTE   TARGET  TRANSIT POINTS");
        assert_eq!(lines[1], "Sales             s-1   mcp       /sales  -       -");
        assert_eq!(lines[2], "Customer support  s-22  a2a       /help   -       -");
    }

    #[test]
    fn surfaces_show_protocol_route_target_and_transit_points() {
        let rows = [json!({
            "surface_id": "s-1", "name": "Sales",
            "access_point": {"listen_address": "0.0.0.0:8080", "route": "/sales", "protocol": "mcp"},
            "target": {"endpoint": "http://127.0.0.1:3000"},
            "transit": {"points": [{"alias": "gh"}, {"alias": "slack"}]},
        })];

        let lines = render_list(&SURFACES, &rows);

        assert_eq!(lines[1], "Sales  s-1  mcp       /sales  http://127.0.0.1:3000  gh,slack");
    }

    #[test]
    fn policies_show_version_and_when_they_changed() {
        let rows = [json!({
            "id": "p-1", "name": "Require header", "description": "Blocks requests without it",
            "policy_type": "agent_surface", "policy": "x", "enabled": false, "version": 3,
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-30T10:00:00Z",
        })];

        let lines = render_list(&POLICIES, &rows);

        assert_eq!(lines[0], "NAME            ID   DESCRIPTION                 ENABLED  VERSION  UPDATED");
        assert_eq!(lines[1], "Require header  p-1  Blocks requests without it  no       3        2026-09-30T10:00:00Z");
    }

    #[test]
    fn a_policy_that_was_never_edited_shows_a_dash_for_updated() {
        let rows = [json!({"id": "p-1", "name": "N", "created_at": "2026-09-01T00:00:00Z"})];

        assert!(render_list(&POLICIES, &rows)[1].ends_with("-"));
    }

    #[test]
    fn credential_providers_show_provider_id_and_type() {
        let rows = [json!({"id": "cp-1", "name": "GitHub", "provider_id": "github", "provider_type": "oauth2"})];

        let lines = render_list(&CREDENTIAL_PROVIDERS, &rows);

        assert_eq!(lines[0], "NAME    ID    PROVIDER ID  TYPE");
        assert_eq!(lines[1], "GitHub  cp-1  github       oauth2");
    }

    #[test]
    fn users_start_with_the_username() {
        let rows =
            [json!({"username": "ana", "user_id": "u-1", "role": "admin", "status": "active", "email": "a@x.io"})];

        assert_eq!(render_list(&USERS, &rows)[1], "ana       u-1  admin  active  a@x.io");
    }

    #[test]
    fn an_empty_list_says_there_is_nothing_yet() {
        assert_eq!(render_list(&SURFACES, &[]), ["No surfaces yet."]);
        assert_eq!(render_list(&GENERIC, &[]), ["No items yet."]);
    }

    #[test]
    fn long_values_are_cut_short_but_ids_are_not() {
        let long_id = "i".repeat(80);
        let rows = [json!({"id": long_id, "name": "n".repeat(100)})];

        let line = &render_list(&ISSUERS, &rows)[1];

        assert!(line.contains(&long_id), "an id is copied into the next command, so it stays whole: {line}");
        assert!(line.starts_with(&format!("{}...", "n".repeat(37))), "{line}");
    }

    #[test]
    fn did_client_id_provider_id_and_secret_id_columns_print_whole() {
        let long = "z".repeat(120);
        let row =
            json!({"id": "i", "name": "n", "did": long, "client_id": long, "provider_id": long, "secret_id": long});

        for layout in [&ISSUERS, &STS_CLIENTS, &CREDENTIAL_PROVIDERS, &SECRETS] {
            let line = &render_list(layout, std::slice::from_ref(&row))[1];
            assert!(line.contains(&long), "{line}");
        }
    }

    #[test]
    fn certificates_show_kind_active_and_updated() {
        let rows = [
            json!({"id": "c-1", "name": "Edge", "kind": "tls", "active": false, "updated_at": "2026-09-30T10:00:00Z"}),
        ];

        assert_eq!(render_list(&CERTIFICATES, &rows)[1], "Edge  c-1  tls   no      2026-09-30T10:00:00Z");
    }

    #[test]
    fn connection_points_show_enabled_uses_and_expiry() {
        let rows = [json!({"id": "cp-1", "name": "Door", "gateway_id": "gw", "enabled": true, "use_count": 0,
            "expires_at": "2027-01-01T00:00:00Z"})];

        assert_eq!(
            render_list(&CONNECTION_POINTS, &rows)[1],
            "Door  cp-1  gw          yes      0     2027-01-01T00:00:00Z"
        );
    }

    #[test]
    fn identities_start_with_the_did() {
        let rows = [
            json!({"id": "i-1", "did": "did:webvh:x", "version": 3, "active": true, "updated_at": "2026-09-30T10:00:00Z"}),
        ];

        assert_eq!(render_list(&IDENTITIES, &rows)[1], "did:webvh:x  i-1  3        yes     2026-09-30T10:00:00Z");
    }

    #[test]
    fn a_whole_column_is_not_cut_at_five_hundred_characters() {
        let long = "d".repeat(700);
        let rows = [json!({"id": "i", "name": "n", "did": long})];

        assert!(render_list(&ISSUERS, &rows)[1].contains(&long));
    }

    #[test]
    fn the_generic_table_never_cuts_names_or_descriptions() {
        let long = "w".repeat(300);
        let rows = [json!({"id": "i", "name": long, "description": long})];

        assert_eq!(
            render_list(&GENERIC, &rows)[1]
                .matches(&long)
                .count(),
            2
        );
    }

    #[test]
    fn an_empty_value_prints_the_word_that_says_what_empty_means() {
        let clients = [json!({"id": "c-1", "name": "n", "client_id": "x", "allowed_scopes": []})];
        let points = [
            json!({"id": "cp-1", "name": "n", "gateway_id": "g", "enabled": true, "use_count": 1, "expires_at": null}),
        ];
        let grants =
            [json!({"id": "g-1", "agent_did": "d", "provider_id": "p", "expires_at": null, "is_expired": false})];

        assert!(render_list(&STS_CLIENTS, &clients)[1].ends_with("any"));
        assert!(render_list(&CONNECTION_POINTS, &points)[1].ends_with("never"));
        assert!(render_list(&GRANTS, &grants)[1].contains("never"));
    }

    #[test]
    fn names_that_another_command_accepts_as_an_id_print_whole() {
        let long = "n".repeat(120);
        let row = json!({"id": "i", "surface_id": "s", "name": long});

        for layout in [&SURFACES, &SECRETS, &CERTIFICATES] {
            assert!(render_list(layout, std::slice::from_ref(&row))[1].contains(&long));
        }
    }

    /// The cells of a rendered line, split on the two-space gap.
    fn cells(line: &str) -> Vec<&str> {
        line.split("  ")
            .map(str::trim)
            .filter(|cell| !cell.is_empty())
            .collect()
    }

    #[test]
    fn an_empty_list_is_worded_for_why_it_is_empty() {
        assert_eq!(render_scoped(&SECRETS, &[], Scope::All), ["No secrets yet."]);
        assert_eq!(render_scoped(&SECRETS, &[], Scope::Filtered), ["No matching secrets."]);
        assert_eq!(render_scoped(&PAYMENTS, &[], Scope::Partial), ["No payments returned."]);
        assert_eq!(render_scoped(&AUDIT, &[], Scope::Filtered), ["No matching audit events."]);
    }

    #[test]
    fn a_long_list_cell_keeps_its_more_suffix_whole() {
        let aliases = ["alpha-service", "beta-service", "gamma-service-long"];
        let points: Vec<Value> = aliases
            .iter()
            .map(|alias| json!({"alias": alias}))
            .chain([json!({"x": 1})])
            .collect();
        let rows = [json!({"id": "s", "name": "n", "transit": {"points": points}})];

        let line = render_list(&SURFACES, &rows)[1].clone();

        assert!(line.ends_with("alpha-service,beta-service +2 more"), "{line}");
    }

    #[test]
    fn a_mixed_list_shows_the_names_and_counts_the_rest() {
        let rows = [
            json!({"id": "s", "name": "n", "transit": {"points": [{"alias": "gh"}, {"x": 1}, {"alias": "slack"}, {"y": 2}]}}),
        ];

        assert!(render_list(&SURFACES, &rows)[1].ends_with("gh,slack +2 more"));
    }

    #[test]
    fn mediators_show_status_did_and_description() {
        let rows =
            [json!({"id": "m-1", "name": "Edge", "description": "Main mediator", "did": "did:web:m.example.com",
            "status": "active", "created_at": "2026-09-01T00:00:00Z"})];

        let lines = render_list(&MEDIATORS, &rows);

        assert_eq!(cells(&lines[0]), ["NAME", "ID", "STATUS", "DID", "DESCRIPTION"]);
        assert_eq!(cells(&lines[1]), ["Edge", "m-1", "active", "did:web:m.example.com", "Main mediator"]);
    }

    #[test]
    fn a2a_proxies_show_status_description_and_updated() {
        let rows = [json!({"id": "a-1", "name": "Support bot", "description": "Direct Line", "status": "disabled",
            "backend": {"kind": "copilot_direct_line"}, "created_at": "2026-09-01T00:00:00Z",
            "updated_at": "2026-09-30T10:00:00Z"})];

        let lines = render_list(&A2A_PROXIES, &rows);

        assert_eq!(cells(&lines[0]), ["NAME", "ID", "STATUS", "DESCRIPTION", "UPDATED"]);
        assert_eq!(cells(&lines[1]), ["Support bot", "a-1", "disabled", "Direct Line", "2026-09-30T10:00:00Z"]);
    }

    #[test]
    fn authorities_show_did_and_description() {
        let rows = [
            json!({"id": "au-1", "name": "Registry", "did": "did:web:a.example.com", "created_at": "x", "updated_at": "y"}),
        ];

        let lines = render_list(&AUTHORITIES, &rows);

        assert_eq!(cells(&lines[1]), ["Registry", "au-1", "did:web:a.example.com", "-"]);
    }

    #[test]
    fn trust_registries_fall_back_to_the_main_did() {
        let with_did = json!({"id": "t-1", "name": "A", "description": "d", "oob_url": "u", "did": "did:web:one"});
        let with_main =
            json!({"id": "t-2", "name": "B", "description": "d", "oob_url": "u", "main_did": "did:web:two"});

        let lines = render_list(&TRUST_REGISTRIES, &[with_did, with_main]);

        assert_eq!(cells(&lines[1]), ["A", "t-1", "did:web:one", "d"]);
        assert_eq!(cells(&lines[2]), ["B", "t-2", "did:web:two", "d"]);
    }

    #[test]
    fn integrations_show_type_status_and_description() {
        let rows =
            [json!({"id": "in-1", "name": "Slack", "description": "Alerts", "type": "slack", "status": "enabled",
            "configuration": {}, "content": {}, "created_at": "x", "updated_at": "y"})];

        let lines = render_list(&INTEGRATIONS, &rows);

        assert_eq!(cells(&lines[0]), ["NAME", "ID", "TYPE", "STATUS", "DESCRIPTION"]);
        assert_eq!(cells(&lines[1]), ["Slack", "in-1", "slack", "enabled", "Alerts"]);
    }

    #[test]
    fn secrets_show_secret_id_type_and_description_but_never_the_value() {
        let rows = [json!({"id": "s-1", "name": "Stripe", "secret_id": "stripe-key", "description": "Billing",
            "secret_type": "api_key", "tags": [], "created_at": "x", "updated_at": "y"})];

        let lines = render_list(&SECRETS, &rows);

        assert_eq!(cells(&lines[0]), ["NAME", "ID", "SECRET ID", "TYPE", "DESCRIPTION"]);
        assert_eq!(cells(&lines[1]), ["Stripe", "s-1", "stripe-key", "api_key", "Billing"]);
        let with_value = [json!({"id": "s-1", "name": "Stripe", "value": "hunter2"})];
        assert!(!render_list(&SECRETS, &with_value)[1].contains("hunter2"));
    }

    #[test]
    fn jwt_strategies_show_issuer_and_updated() {
        let rows = [json!({"id": "j-1", "name": "Okta", "expected_issuer": "https://login.example.com",
            "jwks_source": {"type": "url"}, "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-30T10:00:00Z"})];

        let lines = render_list(&JWT_STRATEGIES, &rows);

        assert_eq!(cells(&lines[0]), ["NAME", "ID", "ISSUER", "UPDATED"]);
        assert_eq!(cells(&lines[1]), ["Okta", "j-1", "https://login.example.com", "2026-09-30T10:00:00Z"]);
    }

    #[test]
    fn sts_clients_show_client_id_and_scopes_or_any() {
        let limited =
            json!({"id": "c-1", "name": "Agent", "client_id": "agent-1", "allowed_scopes": ["read", "write"]});
        let open = json!({"id": "c-2", "name": "Open", "client_id": "open-1", "allowed_scopes": [],
            "allowed_audiences": [], "allowed_subject_token_types": []});

        let lines = render_list(&STS_CLIENTS, &[limited, open]);

        assert_eq!(cells(&lines[0]), ["NAME", "ID", "CLIENT ID", "SCOPES"]);
        assert_eq!(cells(&lines[1]), ["Agent", "c-1", "agent-1", "read,write"]);
        assert_eq!(cells(&lines[2]), ["Open", "c-2", "open-1", "any"]);
    }

    #[test]
    fn config_list_prints_names_and_hosts_whole() {
        let long = format!("https://{}.example.com", "h".repeat(100));
        let rows = [json!({"name": "n".repeat(80), "host": long, "current": true})];

        let line = &render_list(&CONNECTION_SETTINGS, &rows)[1];

        assert!(line.contains(&"n".repeat(80)) && line.contains(&long), "{line}");
    }

    #[test]
    fn a_carriage_return_becomes_a_space_like_a_line_break() {
        assert_eq!(table_cell("a\rb\nc\td"), "a b c d");
        assert_eq!(whole_cell("a\rb"), "a b");
        assert_eq!(flatten("a\rb\u{1b}"), "a b");
        assert_eq!(flatten_capped(&"x".repeat(600)).len(), 500);
        assert_eq!(flatten(&"x".repeat(600)).len(), 600);
    }

    #[test]
    fn policy_versions_show_hash_creator_and_note() {
        let rows = [json!({"version": 2, "policy": "p", "content_hash": "abc", "created_at": "2026-09-30T10:00:00Z",
            "created_by": "ana", "note": "tighten"})];

        let lines = render_list(&POLICY_VERSIONS, &rows);

        assert_eq!(cells(&lines[1]), ["2", "abc", "2026-09-30T10:00:00Z", "ana", "tighten"]);
    }

    #[test]
    fn control_characters_from_the_gateway_never_reach_the_terminal() {
        let rows = [json!({"id": "i-1", "name": "bad\u{1b}[31m\nname\ttab", "did": "\u{7}"})];

        let line = &render_list(&ISSUERS, &rows)[1];

        assert!(!line.contains('\u{1b}') && !line.contains('\u{7}'), "{line:?}");
        assert!(!line.contains('\n') && !line.contains('\t'), "{line:?}");
        assert!(line.starts_with("bad[31m name tab"), "{line:?}");
    }

    #[test]
    fn columns_line_up_when_names_have_accents() {
        let rows = [json!({"id": "a", "name": "Zoë"}), json!({"id": "b", "name": "Zoe"})];

        let lines = render_list(&GENERIC, &rows);

        assert_eq!(lines[1], "Zoë   a   -");
        assert_eq!(lines[2], "Zoe   b   -");
    }

    #[test]
    fn rows_that_are_not_objects_print_as_they_are() {
        assert_eq!(render_list(&GENERIC, &[json!("a"), json!(2)]), ["\"a\"", "2"]);
    }

    #[test]
    fn a_list_of_unnamed_objects_counts_them() {
        let rows = [json!({"id": "i", "name": "n", "transit": {"points": [{"x": 1}, {"x": 2}]}})];

        assert!(render_list(&SURFACES, &rows)[1].ends_with("2 items"));
    }
}
