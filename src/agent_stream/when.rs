//! The moments and durations the `governance` and `drift` commands take on
//! the command line: `--since`, `--until`, and `--window`.

use anyhow::{Result, bail};

use crate::tables::flatten;

/// Seconds in each unit a duration such as `24h` can be written in.
const UNITS: &[(char, u64)] = &[('s', 1), ('m', 60), ('h', 3_600), ('d', 86_400), ('w', 604_800)];

/// The help shared by every flag that takes a moment.
const MOMENT_FORMS: &str = "an RFC 3339 time (2026-11-20T09:00:00Z), unix seconds, or a duration before now \
                                (30m, 24h, 7d)";

/// Reads a moment typed on the command line as unix seconds: an RFC 3339
/// time, a count of unix seconds, or a duration (see [`parse_duration`])
/// counted back from `now`. `flag` names the option in the error.
pub fn parse_moment(
    flag: &str,
    text: &str,
    now: u64,
) -> Result<u64> {
    let text = text.trim();
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_digit())
    {
        return text
            .parse()
            .map_err(|_| moment_error(flag, text));
    }
    if let Some(seconds) = duration_seconds(text) {
        return now
            .checked_sub(seconds)
            .ok_or_else(|| moment_error(flag, text));
    }
    rfc3339_seconds(text).ok_or_else(|| moment_error(flag, text))
}

/// Reads a duration such as `90s`, `30m`, `24h`, `7d` or `2w` as seconds.
/// `flag` names the option in the error.
pub fn parse_duration(
    flag: &str,
    text: &str,
) -> Result<u64> {
    let text = text.trim();
    match duration_seconds(text) {
        Some(seconds) if seconds > 0 => Ok(seconds),
        _ => bail!(
            "{flag} '{}' is not a duration; write a number and a unit: s, m, h, d or w (for example 24h)",
            flatten(text)
        ),
    }
}

fn moment_error(
    flag: &str,
    text: &str,
) -> anyhow::Error {
    anyhow::anyhow!("{flag} '{}' is not {MOMENT_FORMS}", flatten(text))
}

/// A whole number followed by one unit letter, as seconds.
fn duration_seconds(text: &str) -> Option<u64> {
    let unit = text.chars().last()?;
    let (_, scale) = UNITS
        .iter()
        .find(|(letter, _)| *letter == unit.to_ascii_lowercase())?;
    let count = &text[..text.len() - unit.len_utf8()];
    if count.is_empty()
        || !count
            .chars()
            .all(|c| c.is_ascii_digit())
    {
        return None;
    }
    count
        .parse::<u64>()
        .ok()?
        .checked_mul(*scale)
}

/// An RFC 3339 time, `YYYY-MM-DDTHH:MM:SS` with optional fractional seconds
/// (dropped) and a `Z` or `+HH:MM`/`-HH:MM` offset, as unix seconds. A time
/// before 1970 is `None`.
fn rfc3339_seconds(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || !matches!(bytes[10], b'T' | b't' | b' ') {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        part.chars()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction
            .chars()
            .take_while(char::is_ascii_digit)
            .count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            if rest.len() != 6 || rest.as_bytes()[3] != b':' {
                return None;
            }
            let hours: i64 = rest[1..3].parse().ok()?;
            let minutes: i64 = rest[4..6].parse().ok()?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            sign * (hours * 3_600 + minutes * 60)
        }
    };
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second - offset;
    u64::try_from(seconds).ok()
}

fn days_in_month(
    year: i64,
    month: i64,
) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm), the
/// inverse of the date part of `rfc3339_utc` in `commands.rs`.
fn days_from_civil(
    year: i64,
    month: i64,
    day: i64,
) -> i64 {
    let year = if month <= 2 {
        year - 1
    } else {
        year
    };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_index = if month > 2 {
        month - 3
    } else {
        month + 9
    };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_764_000_000;

    #[test]
    fn test_parse_moment_reads_rfc3339_times() {
        let cases = [
            ("1970-01-01T00:00:00Z", 0),
            ("2000-02-29T00:00:00Z", 951_782_400),
            ("2023-11-14T22:13:20Z", 1_700_000_000),
            ("2023-11-14T22:13:20.123456Z", 1_700_000_000),
            ("2023-11-15T06:13:20+08:00", 1_700_000_000),
            ("2023-11-14T17:13:20-05:00", 1_700_000_000),
            ("2099-12-31T23:59:59Z", 4_102_444_799),
        ];
        for (text, expected) in cases {
            assert_eq!(parse_moment("--since", text, NOW).expect(text), expected, "{text}");
        }
    }

    #[test]
    fn test_parse_moment_reads_unix_seconds_and_durations() {
        assert_eq!(parse_moment("--since", "1700000000", NOW).expect("unix"), 1_700_000_000);
        assert_eq!(parse_moment("--since", "24h", NOW).expect("24h"), NOW - 86_400);
        assert_eq!(parse_moment("--since", "7d", NOW).expect("7d"), NOW - 7 * 86_400);
        assert_eq!(parse_moment("--since", "30m", NOW).expect("30m"), NOW - 1_800);
        assert_eq!(parse_moment("--since", "0s", NOW).expect("0s"), NOW);
    }

    #[test]
    fn test_parse_moment_refuses_anything_else() {
        for text in [
            "",
            "yesterday",
            "h",
            "-1h",
            "1.5h",
            "2023-02-30T00:00:00Z",
            "2023-11-14T25:00:00Z",
            "2023-11-14T22:13:20",
            "2023-11-14T22:13:20+0800",
            "2023-11-14",
            "1969-12-31T23:59:59Z",
            "99999999999999999999",
            "99999999999999999w",
        ] {
            let error = parse_moment("--since", text, NOW).expect_err(text);
            assert!(
                error
                    .to_string()
                    .starts_with("--since '"),
                "{text}: {error}"
            );
        }
    }

    #[test]
    fn test_parse_duration_reads_units_and_refuses_moments() {
        assert_eq!(parse_duration("--window", "90s").expect("90s"), 90);
        assert_eq!(parse_duration("--window", "7d").expect("7d"), 604_800);
        assert_eq!(parse_duration("--window", "2w").expect("2w"), 1_209_600);
        for text in ["0h", "1700000000", "2023-11-14T22:13:20Z", "d", "7 d"] {
            let error = parse_duration("--window", text).expect_err(text);
            assert!(
                error
                    .to_string()
                    .contains("is not a duration"),
                "{text}: {error}"
            );
        }
    }

    #[test]
    fn test_parse_moment_flattens_control_characters_in_errors() {
        let error = parse_moment("--until", "\u{1b}[31mred", NOW).expect_err("escape");
        assert!(
            !error
                .to_string()
                .contains('\u{1b}'),
            "{error}"
        );
    }
}
