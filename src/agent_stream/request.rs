//! Building the requests of the `governance` and `drift` commands: query
//! strings, ids that go into a path, and the permission a refusal names.

use anyhow::{Result, bail};
use reqwest::StatusCode;

use crate::{
    client::{response_status, status_error},
    tables::flatten,
};

/// `path` with `params` as its query string, each value percent-encoded.
/// Parameters whose value is `None` are left out.
pub fn with_query(
    path: &str,
    params: &[(&str, Option<String>)],
) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in params {
        if let Some(value) = value {
            query.append_pair(name, value);
        }
    }
    let query = query.finish();
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    }
}

/// Checks an id that goes into a request path: letters, digits, `-` and `_`
/// only, at most `max` characters, which is what Agent Stream accepts for a
/// governance record or a drift run. `what` names the id in the error.
pub fn path_id<'a>(
    what: &str,
    id: &'a str,
    max: usize,
) -> Result<&'a str> {
    let valid = !id.is_empty()
        && id.len() <= max
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    if !valid {
        bail!("{what} '{}' is not valid: use letters, digits, '-' and '_' only, at most {max} characters", flatten(id));
    }
    Ok(id)
}

/// The permission an Agent Stream command needs, named when Agent Stream
/// refuses the request with 403.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    GovernanceView,
    DriftView,
    DriftManage,
}

impl Permission {
    fn name(self) -> &'static str {
        match self {
            Self::GovernanceView => "governance.view",
            Self::DriftView => "drift.view",
            Self::DriftManage => "drift.manage",
        }
    }
}

/// Adds the permission the request needed to a 403 from Agent Stream, keeping
/// its status. Any other error is returned as it is.
pub fn name_permission<T>(
    result: Result<T>,
    permission: Permission,
) -> Result<T> {
    result.map_err(|error| {
        if response_status(&error) == Some(StatusCode::FORBIDDEN) {
            status_error(
                StatusCode::FORBIDDEN,
                format!(
                    "{error}; this needs the `{}` permission, which only administrators have by default (an access \
                     token must also list it)",
                    permission.name()
                ),
            )
        } else {
            error
        }
    })
}

/// The message of the 404 Agent Stream answers for a surface outside the
/// token's scope.
const GENERIC_NOT_FOUND: &str = "Not found";

/// Words Agent Stream's generic 404 for a surface the way the user can act
/// on: it answers a bare `Not found` for a surface outside the token's tenant
/// or resource scope. A 404 with its own message, such as `Record not found`
/// or `Run not found`, is about something else and is returned as it is.
pub fn name_missing_surface<T>(
    result: Result<T>,
    surface: &str,
) -> Result<T> {
    result.map_err(|error| {
        if response_status(&error) == Some(StatusCode::NOT_FOUND)
            && error
                .to_string()
                .eq_ignore_ascii_case(GENERIC_NOT_FOUND)
        {
            status_error(
                StatusCode::NOT_FOUND,
                format!("{error}: no surface '{}' that this login can read", flatten(surface)),
            )
        } else {
            error
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_query_encodes_values_and_drops_missing_ones() {
        let path = with_query(
            "/v1/governance/records",
            &[("surface_id", Some("s 1".to_owned())), ("cursor", None), ("stage", Some("judge,jury&x=1".to_owned()))],
        );
        assert_eq!(path, "/v1/governance/records?surface_id=s+1&stage=judge%2Cjury%26x%3D1");
        assert_eq!(with_query("/v1/governance/surfaces", &[("cursor", None)]), "/v1/governance/surfaces");
    }

    #[test]
    fn test_path_id_refuses_path_characters() {
        assert_eq!(path_id("record id", "r-1_a", 64).expect("valid"), "r-1_a");
        for id in ["", "../x", "a/b", "a.b", "a?b=1", "%2e"] {
            let error = path_id("record id", id, 64).expect_err(id);
            assert!(
                error
                    .to_string()
                    .contains("is not valid"),
                "{id}: {error}"
            );
        }
        assert!(path_id("record id", &"a".repeat(65), 64).is_err());
    }

    #[test]
    fn test_name_permission_keeps_status_and_names_permission() {
        let refused: Result<()> = Err(status_error(StatusCode::FORBIDDEN, "Insufficient permissions".to_owned()));
        let error = name_permission(refused, Permission::DriftManage).expect_err("403");
        assert_eq!(response_status(&error), Some(StatusCode::FORBIDDEN));
        assert!(
            error
                .to_string()
                .starts_with("Insufficient permissions; this needs the `drift.manage` permission")
        );

        let missing: Result<()> = Err(status_error(StatusCode::NOT_FOUND, "Not found".to_owned()));
        let error = name_permission(missing, Permission::DriftView).expect_err("404");
        assert_eq!(error.to_string(), "Not found");
    }

    #[test]
    fn test_name_missing_surface_words_a_404() {
        let missing: Result<()> = Err(status_error(StatusCode::NOT_FOUND, "Not found".to_owned()));
        let error = name_missing_surface(missing, "s1").expect_err("404");
        assert_eq!(error.to_string(), "Not found: no surface 's1' that this login can read");
    }

    #[test]
    fn test_name_missing_surface_keeps_a_404_with_its_own_message() {
        let missing: Result<()> = Err(status_error(StatusCode::NOT_FOUND, "Record not found".to_owned()));
        let error = name_missing_surface(missing, "s1").expect_err("404");
        assert_eq!(error.to_string(), "Record not found");
        assert_eq!(response_status(&error), Some(StatusCode::NOT_FOUND));
    }
}
