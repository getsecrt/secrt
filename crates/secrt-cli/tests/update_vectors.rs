//! Validates the CLI's semver and tag-filter behavior against
//! `spec/v1/update.vectors.json`. The vectors file is the normative
//! contract for the update-check policy across implementations; this
//! harness ensures the Rust implementation conforms.
//!
//! The `banner_suppression` section is descriptive scenarios covered by
//! `tests/cli_update_check.rs` and is not exercised here.

use std::cmp::Ordering;
use std::fs;
use std::path::PathBuf;

use secrt_cli::update::{is_valid_version_for_channel, Channel};
use secrt_cli::update_check;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    semver_compare: SemverCompare,
    release_tag_filter: ReleaseTagFilter,
    channel_resolution: ChannelResolution,
    prerelease_ordering: PrereleaseOrdering,
}

#[derive(Deserialize)]
struct SemverCompare {
    valid: Vec<SemverCase>,
    invalid: Vec<SemverInvalidCase>,
}

#[derive(Deserialize)]
struct SemverCase {
    current: String,
    latest: String,
    should_update: bool,
    description: String,
}

#[derive(Deserialize)]
struct SemverInvalidCase {
    input: String,
    reason: String,
}

#[derive(Deserialize)]
struct ReleaseTagFilter {
    valid: Vec<TagCase>,
}

#[derive(Deserialize)]
struct TagCase {
    tag: String,
    is_prerelease: bool,
    is_draft: bool,
    accepted: bool,
    #[serde(default)]
    extracted_semver: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct ChannelResolution {
    vectors: Vec<ChannelVersionCase>,
}

#[derive(Deserialize)]
struct ChannelVersionCase {
    channel: String,
    version: String,
    valid: bool,
    #[serde(default, rename = "_why")]
    _why: Option<String>,
}

#[derive(Deserialize)]
struct PrereleaseOrdering {
    cases: Vec<PrereleaseOrderCase>,
}

#[derive(Deserialize)]
struct PrereleaseOrderCase {
    a: String,
    b: String,
    expected: String,
}

fn vectors_path() -> PathBuf {
    // The CLI crate manifest is two levels deep from the workspace root,
    // so spec/v1/ is at `../../spec/v1/`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("spec")
        .join("v1")
        .join("update.vectors.json")
}

fn load_vectors() -> Vectors {
    let bytes = fs::read(vectors_path()).expect("read update.vectors.json");
    serde_json::from_slice(&bytes).expect("parse update.vectors.json")
}

#[test]
fn semver_compare_valid_cases() {
    let v = load_vectors();
    for case in &v.semver_compare.valid {
        // The vectors include prerelease inputs (e.g. `0.15.0-rc.1`)
        // which our strict parser rejects — those collapse to Equal,
        // and the case directives encode that expectation. We therefore
        // test the policy: `should_update == (compare(current, latest) == Less)`.
        let ordering = update_check::compare_semver(&case.current, &case.latest);
        let actual_should_update = ordering == Ordering::Less;
        assert_eq!(
            actual_should_update, case.should_update,
            "case {:?}: compare({:?}, {:?}) -> {:?}, expected should_update={}",
            case.description, case.current, case.latest, ordering, case.should_update
        );
    }
}

#[test]
fn semver_compare_invalid_cases_collapse_to_equal() {
    // The spec says invalid inputs MUST be rejected. Our `compare_semver`
    // collapses unparseable inputs to `Ordering::Equal` so we never
    // falsely advertise an upgrade. Verify that here.
    let v = load_vectors();
    for case in &v.semver_compare.invalid {
        // Compare against a known-good semver so any non-Equal result
        // would mean we accepted the invalid input as a valid number.
        let ord = update_check::compare_semver(&case.input, "0.15.0");
        assert_eq!(
            ord,
            Ordering::Equal,
            "invalid input {:?} ({}) should not parse, got {:?}",
            case.input,
            case.reason,
            ord,
        );
    }
}

#[test]
fn release_tag_filter_matches_spec() {
    use secrt_cli::update_check::compare_semver;

    // We re-implement the policy locally using only the public API of
    // `update_check` (semver compare for ordering) and the tag predicate
    // shape from the spec. Direct access to `secrt_server::release_poller`
    // would be cleaner, but the CLI crate doesn't depend on the server.
    fn parse_cli_tag_strict(tag: &str) -> Option<(u64, u64, u64)> {
        let rest = tag.strip_prefix("cli/v")?;
        let mut parts = rest.split('.');
        let a = parts.next()?.parse::<u64>().ok()?;
        let b = parts.next()?.parse::<u64>().ok()?;
        let c = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        if !c.chars().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        Some((a, b, c.parse::<u64>().ok()?))
    }
    fn would_accept(tag: &str, is_draft: bool, is_prerelease: bool) -> Option<String> {
        if is_draft || is_prerelease {
            return None;
        }
        parse_cli_tag_strict(tag).map(|(maj, min, pat)| format!("{maj}.{min}.{pat}"))
    }

    let v = load_vectors();
    for case in &v.release_tag_filter.valid {
        let actual = would_accept(&case.tag, case.is_draft, case.is_prerelease);
        let actually_accepted = actual.is_some();
        assert_eq!(
            actually_accepted,
            case.accepted,
            "tag {:?} (draft={}, prerelease={}): expected accepted={}, got={} (reason={:?})",
            case.tag,
            case.is_draft,
            case.is_prerelease,
            case.accepted,
            actually_accepted,
            case.reason
        );
        if let Some(expected) = &case.extracted_semver {
            assert_eq!(
                actual.as_deref(),
                Some(expected.as_str()),
                "tag {:?}: extracted_semver mismatch",
                case.tag
            );
            // Sanity check: the extracted semver round-trips through
            // compare_semver against itself as Equal.
            assert_eq!(compare_semver(expected, expected), Ordering::Equal);
        }
    }
}

#[test]
fn channel_resolution_version_validity() {
    let v = load_vectors();
    for case in &v.channel_resolution.vectors {
        let channel = match case.channel.as_str() {
            "stable" => Channel::Stable,
            "prerelease" => Channel::Prerelease,
            other => panic!("unknown channel in vectors: {:?}", other),
        };
        let actual = is_valid_version_for_channel(&case.version, channel);
        assert_eq!(
            actual, case.valid,
            "channel={:?} version={:?}: expected valid={}, got {}",
            case.channel, case.version, case.valid, actual
        );
    }
}

#[test]
fn prerelease_ordering_matches_spec() {
    let v = load_vectors();
    for case in &v.prerelease_ordering.cases {
        let expected = match case.expected.as_str() {
            "Less" => Ordering::Less,
            "Equal" => Ordering::Equal,
            "Greater" => Ordering::Greater,
            other => panic!("unknown ordering in vectors: {:?}", other),
        };
        let actual = update_check::compare_semver(&case.a, &case.b);
        assert_eq!(
            actual, expected,
            "compare_semver({:?}, {:?}) = {:?}, expected {:?}",
            case.a, case.b, actual, expected
        );
    }
}
