// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::bail;
use anyhow::Context;
use anyhow::Error;
use lazy_static::lazy_static;
use regex;
use regex::Regex;
use regex::RegexBuilder;

lazy_static! {
    /// Matches runs of non-wildcard characters followed by wildcard characters.
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
        GlobMatchType::Word => format!(r"(?:^|\b|\W){joined}(?:\b|\W|$)"),
    };

    Ok(RegexBuilder::new(&regex_str)
        .case_insensitive(true)
        .build()?)
}

/// Compiles the glob into a `Matcher`.
pub fn get_glob_matcher(glob: &str, match_type: GlobMatchType) -> Result<Matcher, Error> {
    // There are a number of shortcuts we can make if the glob doesn't contain a
    // wild card.
    let matcher = if glob.contains(['*', '?']) {
        let regex = glob_to_regex(glob, match_type)?;
        Matcher::Regex(regex)
    } else if match_type == GlobMatchType::Whole {
        // If there aren't any wildcards and we're matching the whole thing,
        // then we simply can do a case-insensitive string match.
        Matcher::Whole(glob.to_lowercase())
    } else {
        // Otherwise, if we're matching against words then can first check
        // if the haystack contains the glob at all.
        Matcher::Word {
            word: glob.to_lowercase(),
            regex: None,
        }
    };

    Ok(matcher)
}

/// Matches against a glob
pub enum Matcher {
    /// Plain regex matching.
    Regex(Regex),

    /// Case-insensitive equality.
    Whole(String),

    /// Word matching. `regex` is a cache of calling [`glob_to_regex`] on word.
    Word { word: String, regex: Option<Regex> },
}

impl Matcher {
    /// Checks if the glob matches the given haystack.
    pub fn is_match(&mut self, haystack: &str) -> Result<bool, Error> {
        // We want to to do case-insensitive matching, so we convert to
        // lowercase first.
        let haystack = haystack.to_lowercase();

        match self {
            Matcher::Regex(regex) => Ok(regex.is_match(&haystack)),
            Matcher::Whole(whole) => Ok(whole == &haystack),
            Matcher::Word { word, regex } => {
                // If we're looking for a literal word, then we first check if
                // the haystack contains the word as a substring.
                if !haystack.contains(&*word) {
                    return Ok(false);
                }

                // If it does contain the word as a substring, then we need to
                // check if it is an actual word by testing it against the regex.
                let regex = if let Some(regex) = regex {
                    regex
                } else {
                    let compiled_regex = glob_to_regex(word, GlobMatchType::Word)?;
                    regex.insert(compiled_regex)
                };

                Ok(regex.is_match(&haystack))
            }
        }
    }
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

    assert!(glob_to_regex("simple", GlobMatchType::Whole)?.is_match("simple"));
    assert!(!glob_to_regex("simple", GlobMatchType::Whole)?.is_match("simples"));
    assert!(glob_to_regex("simple*", GlobMatchType::Whole)?.is_match("simples"));
    assert!(glob_to_regex("simple?", GlobMatchType::Whole)?.is_match("simples"));
    assert!(glob_to_regex("simple*", GlobMatchType::Whole)?.is_match("simple"));

    assert!(glob_to_regex("simple", GlobMatchType::Word)?.is_match("some simple."));
    assert!(glob_to_regex("simple", GlobMatchType::Word)?.is_match("simple"));
    assert!(!glob_to_regex("simple", GlobMatchType::Word)?.is_match("simples"));

    assert!(glob_to_regex("@user:foo", GlobMatchType::Word)?.is_match("Some @user:foo test"));
    assert!(glob_to_regex("@user:foo", GlobMatchType::Word)?.is_match("@user:foo"));

    Ok(())
}
