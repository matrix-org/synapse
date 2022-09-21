use anyhow::bail;
use anyhow::Context;
use anyhow::Error;
use lazy_static::lazy_static;
use regex;
use regex::Regex;
use regex::RegexBuilder;

lazy_static! {
    /// Matches runs of "glob" style wild cards
    static ref WILDCARD_RUN: Regex = Regex::new(r"([^\?\*]*)([\?\*]*)").expect("valid regex");
}

/// Extract the localpart from a Matrix style ID
pub(crate) fn get_localpart_from_id(id: &str) -> Result<&str, Error> {
    let (localpart, _) = id
        .split_once(':')
        .with_context(|| format!("ID does not contain colon: {id}"))?;

    // We need to strip off the first character, which is the ID type.
    if localpart.is_empty() {
        bail!("Invalid ID {id}");
    }

    Ok(&localpart[1..])
}

/// Used by `glob_to_regex` to specify what to match the regex against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobMatchType {
    /// The generated regex will match against the entire input.
    Whole,
    /// The generated regex will match against words.
    Word,
}

/// Convert a "glob" style expression to a regex, anchoring either to the entire
/// input or to individual words.
pub fn glob_to_regex(glob: &str, match_type: GlobMatchType) -> Result<Regex, Error> {
    let mut chunks = Vec::new();

    // Patterns with wildcards must be simplified to avoid performance cliffs
    // - The glob `?**?**?` is equivalent to the glob `???*`
    // - The glob `???*` is equivalent to the regex `.{3,}`
    for captures in WILDCARD_RUN.captures_iter(glob) {
        if let Some(chunk) = captures.get(1) {
            chunks.push(regex::escape(chunk.as_str()));
        }

        if let Some(wildcards) = captures.get(2) {
            if wildcards.as_str() == "" {
                continue;
            }

            let question_marks = wildcards.as_str().chars().filter(|c| *c == '?').count();

            if wildcards.as_str().contains('*') {
                chunks.push(format!(".{{{question_marks},}}"));
            } else {
                chunks.push(format!(".{{{question_marks}}}"));
            }
        }
    }

    let joined = chunks.join("");

    let regex_str = match match_type {
        GlobMatchType::Whole => format!(r"\A{joined}\z"),

        // `^|\W` and `\W|$` handle the case where `pattern` starts or ends with a non-word
        // character.
        GlobMatchType::Word => format!(r"(?:^|\W|\b){joined}(?:\b|\W|$)"),
    };

    Ok(RegexBuilder::new(&regex_str)
        .case_insensitive(true)
        .build()?)
}

#[test]
fn test_get_domain_from_id() {
    get_localpart_from_id("").unwrap_err();
    get_localpart_from_id(":").unwrap_err();
    get_localpart_from_id(":asd").unwrap_err();
    get_localpart_from_id("::as::asad").unwrap_err();

    assert_eq!(get_localpart_from_id("@test:foo").unwrap(), "test");
    assert_eq!(get_localpart_from_id("@:").unwrap(), "");
    assert_eq!(get_localpart_from_id("@test:foo:907").unwrap(), "test");
}

#[test]
fn tset_glob() -> Result<(), Error> {
    assert_eq!(
        glob_to_regex("simple", GlobMatchType::Whole)?.as_str(),
        r"\Asimple\z"
    );
    assert_eq!(
        glob_to_regex("simple*", GlobMatchType::Whole)?.as_str(),
        r"\Asimple.{0,}\z"
    );
    assert_eq!(
        glob_to_regex("simple?", GlobMatchType::Whole)?.as_str(),
        r"\Asimple.{1}\z"
    );
    assert_eq!(
        glob_to_regex("simple?*?*", GlobMatchType::Whole)?.as_str(),
        r"\Asimple.{2,}\z"
    );
    assert_eq!(
        glob_to_regex("simple???", GlobMatchType::Whole)?.as_str(),
        r"\Asimple.{3}\z"
    );

    assert_eq!(
        glob_to_regex("escape.", GlobMatchType::Whole)?.as_str(),
        r"\Aescape\.\z"
    );

    assert_eq!(
        glob_to_regex("simple", GlobMatchType::Word)?.as_str(),
        r"(?:^|\W|\b)simple(?:\b|\W|$)"
    );

    assert!(glob_to_regex("simple", GlobMatchType::Word)?.is_match("some simple."));
    assert!(glob_to_regex("simple", GlobMatchType::Word)?.is_match("simple"));

    Ok(())
}
