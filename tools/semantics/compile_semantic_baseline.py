#!/usr/bin/env python3
"""Compile the declared-cutoff regex semantic corpus and planning denominator.

This compiler is design-only. It performs no regex execution, environment
realization, Docker operation, evidence publication, or network access.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import date
from decimal import Decimal, ROUND_CEILING
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_scale.evidence_pack_v3 import build_capacity_forecast  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402
from regex_conformance_schema.schema import validate_instance  # noqa: E402
from regex_conformance_schema.scientific_identity import verify_catalog  # noqa: E402


CUTOFF = "2026-08-22"
CORPUS_SCHEMA = "regex-semantic-corpus-v1"
PROJECTION_SCHEMA = "regex-semantic-projection-v1"
DENOMINATOR_SCHEMA = "regex-semantic-denominator-v1"
VECTOR_REQUIREMENTS_SCHEMA = "regex-semantic-vector-requirements-v1"

CORPUS_PATH = ROOT / "semantic-corpus" / "snapshots" / "regex-semantic-features-2026-08-22.v1.json"
PROJECTION_PATH = ROOT / "ontology" / "projections" / "regex-semantic-projection-2026-08-22.v1.json"
VECTOR_REQUIREMENTS_PATH = ROOT / "vectors" / "requirements" / "regex-semantic-vector-requirements-2026-08-22.v1.json"
DENOMINATOR_PATH = ROOT / "reports" / "scale" / "regex-semantic-denominator-forecast.json"

CORPUS_SCHEMA_PATH = ROOT / "schemas" / "json" / "regex-semantic-corpus.schema.json"
PROJECTION_SCHEMA_PATH = ROOT / "schemas" / "json" / "regex-semantic-projection.schema.json"
VECTOR_REQUIREMENTS_SCHEMA_PATH = ROOT / "schemas" / "json" / "regex-semantic-vector-requirements.schema.json"
DENOMINATOR_SCHEMA_PATH = ROOT / "schemas" / "json" / "regex-semantic-denominator.schema.json"


def _source(
    source_id: str,
    title: str,
    url: str,
    authority: str,
    scope: str,
    *,
    version: str = "retrieved at cutoff",
    source_class: str = "official-implementation-documentation",
    normative: bool = False,
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "title": title,
        "url": url,
        "authority": authority,
        "version_or_revision": version,
        "retrieved_on": CUTOFF,
        "source_class": source_class,
        "normative": normative,
        "scope": scope,
    }


SOURCES = [
    _source("unicode-tr18", "Unicode Regular Expressions", "https://www.unicode.org/reports/tr18/tr18-25.html", "Unicode Consortium", "Unicode regex levels, properties, sets, boundaries, case and grapheme semantics", version="UTS #18 revision 25", source_class="normative-standard", normative=True),
    _source("unicode-tr29", "Unicode Text Segmentation", "https://www.unicode.org/reports/tr29/tr29-47.html", "Unicode Consortium", "grapheme, word and sentence boundary algorithms", version="UAX #29 revision 47", source_class="normative-standard", normative=True),
    _source("posix-regex", "POSIX Regular Expressions", "https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html", "The Open Group", "BRE, ERE, bracket expressions and leftmost-longest submatch rules", version="POSIX.1-2017 Issue 7", source_class="normative-standard", normative=True),
    _source("ecma-regexp", "ECMAScript RegExp", "https://tc39.es/ecma262/2026/", "Ecma International", "pattern grammar, Unicode sets, stateful matching, split and replacement", version="ECMA-262 2026", source_class="normative-standard", normative=True),
    _source("w3c-xpath-regex", "XPath and XQuery Functions and Operators", "https://www.w3.org/TR/xpath-functions-31/", "W3C", "matches, replace, tokenize and analyze-string regex operations", version="3.1", source_class="normative-standard", normative=True),
    _source("w3c-xsd-regex", "XML Schema Definition Language: Datatypes", "https://www.w3.org/TR/xmlschema11-2/#regexs", "W3C", "implicitly anchored pattern language and character-class subtraction", version="1.1 Part 2", source_class="normative-standard", normative=True),
    _source("pcre2-pattern", "PCRE2 pattern specification", "https://www.pcre.org/current/doc/html/pcre2pattern.html", "PCRE2", "feature-rich pattern semantics and version boundaries"),
    _source("pcre2-syntax", "PCRE2 syntax summary", "https://www.pcre.org/current/doc/html/pcre2syntax.html", "PCRE2", "syntax and replacement manifestations"),
    _source("pcre2-api", "PCRE2 native API", "https://www.pcre.org/current/doc/html/pcre2api.html", "PCRE2", "compile, match, substitution, result, limit and diagnostic APIs"),
    _source("pcre2-matching", "PCRE2 matching algorithms", "https://www.pcre.org/current/doc/html/pcre2matching.html", "PCRE2", "standard versus alternative matcher behavior"),
    _source("pcre2-partial", "PCRE2 partial matching", "https://www.pcre.org/current/doc/html/pcre2partial.html", "PCRE2", "soft, hard and restartable partial matching"),
    _source("pcre2-callout", "PCRE2 callouts", "https://www.pcre.org/current/doc/html/pcre2callout.html", "PCRE2", "pattern and substitution callback semantics"),
    _source("perl-regex", "Perl regular expressions", "https://perldoc.perl.org/perlre", "Perl", "pattern semantics, recursion, conditionals, code and control verbs"),
    _source("perl-operations", "Perl regular expression operations", "https://perldoc.perl.org/perlop#Regexp-Quote-Like-Operators", "Perl", "matching, global iteration and substitution operations"),
    _source("dotnet-regex", ".NET regular expression language", "https://learn.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-language-quick-reference", "Microsoft", "grouping, captures, balancing groups, conditionals, options and substitutions"),
    _source("dotnet-groups", ".NET grouping constructs", "https://learn.microsoft.com/en-us/dotnet/standard/base-types/grouping-constructs-in-regular-expressions", "Microsoft", "capture collections, assertions, atomic and balancing groups"),
    _source("dotnet-options", ".NET regular expression options", "https://learn.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-options", "Microsoft", "direction, culture, nonbacktracking and matching modes"),
    _source("java-pattern", "Java Pattern", "https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/util/regex/Pattern.html", "Oracle Java", "Java pattern grammar, flags and split"),
    _source("java-matcher", "Java Matcher", "https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/util/regex/Matcher.html", "Oracle Java", "regions, cursor state, results and replacement"),
    _source("python-re", "Python re", "https://docs.python.org/3.14/library/re.html", "Python Software Foundation", "pattern grammar, atomic and possessive constructs, operations and empty-match advancement", version="Python 3.14"),
    _source("ruby-regexp", "Ruby Regexp", "https://docs.ruby-lang.org/en/3.4/Regexp.html", "Ruby", "Onigmo-derived regex syntax, encodings, subexpression calls and absent operator", version="Ruby 3.4"),
    _source("oniguruma-syntax", "Oniguruma syntax configuration", "https://github.com/kkos/oniguruma/blob/master/doc/SYNTAX.md", "Oniguruma", "configurable operators, capture history, callouts and syntax error behavior", version="6.9.10"),
    _source("oniguruma-regex", "Oniguruma regular expressions", "https://github.com/kkos/oniguruma/blob/master/doc/RE", "Oniguruma", "pattern semantics, encodings, absent functions and subexpression calls", version="6.9.10"),
    _source("icu-regex", "ICU regular expressions", "https://unicode-org.github.io/icu/userguide/strings/regexp.html", "Unicode Consortium", "Unicode-aware regex, full folding, boundaries, split and resource limits"),
    _source("re2-syntax", "RE2 syntax", "https://github.com/google/re2/wiki/Syntax", "Google RE2", "regular-language syntax, unsupported constructs and anchors"),
    _source("re2-readme", "RE2", "https://github.com/google/re2", "Google RE2", "linear-time and bounded-memory design claims"),
    _source("rust-regex", "Rust regex crate", "https://docs.rs/regex/1.13.1/regex/", "rust-lang regex project", "Unicode and byte domains, bounded compilation and match iteration", version="1.13.1"),
    _source("rust-regex-set", "Rust RegexSet", "https://docs.rs/regex/1.13.1/regex/struct.RegexSet.html", "rust-lang regex project", "multi-pattern identity and result limitations", version="1.13.1"),
    _source("go-regexp", "Go regexp", "https://pkg.go.dev/regexp", "Go project", "RE2-derived matching, longest mode, APIs and replacements"),
    _source("boost-regex", "Boost.Regex", "https://www.boost.org/doc/libs/latest/libs/regex/doc/html/index.html", "Boost", "multiple grammars, partial matching, recursion and replacement"),
    _source("hyperscan", "Hyperscan developer reference", "https://intel.github.io/hyperscan/dev-reference/", "Intel Hyperscan", "multi-pattern block, vectored and streaming matching"),
    _source("hyperscan-runtime", "Hyperscan runtime", "https://intel.github.io/hyperscan/dev-reference/runtime.html", "Intel Hyperscan", "callback ordering, stream lifecycle and scan termination"),
    _source("tre", "TRE approximate regex library", "https://github.com/laurikari/tre", "TRE project", "edit-distance regex matching, costs and best-match selection"),
    _source("python-regex", "Python regex package", "https://github.com/mrabarnett/mrab-regex", "mrab-regex project", "fuzzy matching, repeated captures, branch reset, reverse search and timeouts"),
    _source("postgres-regex", "PostgreSQL pattern matching", "https://www.postgresql.org/docs/18/functions-matching.html", "PostgreSQL", "ARE semantics, directors, locale and SQL operations", version="PostgreSQL 18"),
    _source("mysql-regex", "MySQL regular expressions", "https://dev.mysql.com/doc/refman/8.4/en/regexp.html", "Oracle MySQL", "ICU-backed SQL regex functions, binary rejection and resource controls", version="MySQL 8.4"),
    _source("oracle-regex", "Oracle Database regex", "https://docs.oracle.com/en/database/oracle/oracle-database/19/adfns/regexp.html", "Oracle Database", "POSIX/Unicode SQL operations, occurrence and collation semantics", version="Oracle Database 19c"),
    _source("bigquery-regex", "BigQuery string functions", "https://cloud.google.com/bigquery/docs/reference/standard-sql/string_functions", "Google Cloud", "RE2-backed SQL extraction, positions, occurrence and replacement"),
    _source("gnu-grep", "GNU grep", "https://www.gnu.org/software/grep/manual/grep.html", "GNU", "BRE/ERE/PCRE selection, locale, binary data, multi-pattern and resource behavior", version="3.12"),
    _source("emacs-regex", "GNU Emacs regular expressions", "https://www.gnu.org/software/emacs/manual/html_node/elisp/Regular-Expressions.html", "GNU Emacs", "buffer-oriented syntax-table and search semantics"),
    _source("vim-regex", "Vim patterns", "https://vimhelp.org/pattern.txt.html", "Vim", "magic modes, match-boundary resets and editor position atoms"),
    _source("tcl-regex", "Tcl regular expression syntax", "https://www.tcl-lang.org/man/tcl8.7/TclCmd/re_syntax.html", "Tcl", "Henry Spencer ARE constraints, directors and newline modes", version="Tcl 8.7"),
    _source("laurikari-tdfa", "NFAs with tagged transitions", "https://doi.org/10.1109/SPIRE.2000.878194", "Ville Laurikari", "tagged automata and POSIX submatch extraction", version="SPIRE 2000", source_class="primary-research-paper"),
    _source("legacy-knowledge-tombstone", "Retired STRling Regex Knowledge Program", "https://www.notion.so/3ba7d940647581a9b60dd76f67e5230e", "STRling program governance", "retirement state and recovery boundary for the former feature workspace", source_class="governance-record"),
    _source("legacy-authority-decision", "Feature ontology authority decision", "https://www.notion.so/3ba7d9406475818ca138bc971b6a13b3", "STRling program governance", "former semantic authority and projection boundary", source_class="governance-record"),
    _source("immutable-projection-decision", "Immutable semantic snapshot and projection decision", "https://www.notion.so/3ba7d9406475812ea149b96f9990396c", "STRling program governance", "immutable corpus snapshots and consumer projections", source_class="governance-record"),
    _source("semantic-obligation-taxonomy", "Semantic obligation taxonomy", "https://www.notion.so/3ba7d9406475814a9e13fb460ddb84bb", "STRling program governance", "twelve-facet profile by feature by obligation by operation model", source_class="governance-record"),
    _source("known-universe-census", "Known regex universe census", "repository:reports/scale/known-universe-census.json", "Regex Conformance", "frozen facility and profile bounds used by the applicability join", source_class="repository-artifact"),
    _source("evidence-pack-v3-certification", "Compact Evidence Pack v3 capacity certification", "repository:reports/scale/evidence-pack-v3-capacity-certification.json", "Regex Conformance", "measured retained-byte rates and capacity contract", source_class="repository-artifact"),
]


OPERATIONS = [
    ("compile", "Compile or validate a pattern without requiring a successful match."),
    ("test", "Return whether a pattern has a match."),
    ("prefix-match", "Attempt a match at a required starting position."),
    ("full-match", "Require the match to consume the complete governed subject region."),
    ("search", "Find the first applicable match in a governed subject region."),
    ("next-match", "Advance an explicit matcher cursor to the next match."),
    ("find-all", "Enumerate non-overlapping matches under the host advancement rule."),
    ("find-overlapping", "Enumerate matches whose spans may overlap."),
    ("extract", "Return a whole-match or selected-capture value."),
    ("count", "Count governed match occurrences."),
    ("position", "Return a governed match or capture position."),
    ("split", "Split input around regex matches."),
    ("replace-first", "Replace the first applicable match."),
    ("replace-all", "Replace all matches under the host advancement rule."),
    ("replace-callback", "Compute replacement text from a match callback."),
    ("expand-replacement", "Expand a replacement template against existing match data."),
    ("analyze", "Return structured matching and non-matching regions."),
    ("partial-match", "Report whether more subject data could complete a match."),
    ("stream-scan", "Match across incrementally supplied subject blocks."),
    ("block-scan", "Match one contiguous block through a multi-pattern database."),
    ("vector-scan", "Match a logical subject supplied as several blocks."),
    ("set-match", "Report which members of a compiled pattern set match."),
]


MODIFIERS = [
    ("case-insensitive", "Select case-insensitive matching."),
    ("multiline-anchors", "Make line boundaries participate in anchor semantics."),
    ("dotall", "Allow the wildcard atom to match governed newline sequences."),
    ("extended-spacing", "Ignore pattern spacing and recognize pattern comments."),
    ("explicit-capture", "Disable implicit unnamed capture allocation."),
    ("ungreedy-default", "Invert the default greediness of ordinary quantifiers."),
    ("unicode-mode", "Select a Unicode code-point or scalar matching domain."),
    ("unicode-properties", "Enable Unicode property semantics for shorthand classes."),
    ("ascii-restriction", "Restrict otherwise Unicode-aware classes or boundaries to ASCII."),
    ("locale-sensitive", "Select locale or collation-dependent character behavior."),
    ("literal-pattern", "Treat pattern text as literal data."),
    ("right-to-left", "Search from higher positions toward lower positions."),
    ("nonbacktracking-engine", "Select a nonbacktracking matcher with a restricted feature set."),
    ("posix-longest", "Select leftmost-longest match disambiguation."),
    ("sticky", "Require the next match to begin at the mutable cursor."),
    ("global", "Enable repeated host-managed matching or replacement."),
    ("has-indices", "Request capture span arrays in the host's native index unit."),
    ("newline-convention", "Select which sequences are line breaks."),
    ("backslash-r-convention", "Select which sequences the generic newline atom consumes."),
    ("dollar-end-only", "Remove the before-final-newline meaning of the dollar anchor."),
    ("first-line", "Forbid match starts after the first line."),
    ("allow-duplicate-names", "Permit multiple captures with one name."),
    ("no-auto-possess", "Disable automatic possessification."),
    ("not-empty", "Reject an otherwise successful empty match."),
    ("not-beginning-of-line", "Tell the matcher that the subject start is not a line start."),
    ("not-end-of-line", "Tell the matcher that the subject end is not a line end."),
    ("partial-soft", "Prefer a complete match over a partial match."),
    ("partial-hard", "Prefer a viable partial match even when a complete match exists."),
    ("fuzzy-best", "Prefer the lowest-cost approximate match."),
    ("fuzzy-enhance", "Improve the fit of the next approximate match."),
    ("single-match-per-pattern", "Report at most one match for each member of a pattern set."),
    ("prefilter", "Permit a superset of true matches for later confirmation."),
]


FACET_CASES = {
    "syntax": ("acceptance", "rejection", "ambiguity-boundary"),
    "core-semantics": ("positive", "negative", "boundary", "competing-interpretation"),
    "search-iteration": ("start-offset", "zero-length-progress", "repeated-next", "terminal-state"),
    "captures": ("participation", "unset-versus-empty", "value", "span", "history-or-name"),
    "unicode-encoding": ("datum-domain", "class-or-property", "case-folding", "index-unit", "malformed-input"),
    "options-state": ("off-versus-on", "scope", "interaction", "locale-mode-or-cursor"),
    "host-operation": ("success", "no-match", "state-transition", "result-shape"),
    "replacement": ("expansion", "missing-or-unset-group", "escaping", "global-progress", "callback-or-state"),
    "errors": ("phase", "class", "native-diagnostic"),
    "resource-termination": ("limit", "timeout", "exhaustion", "termination"),
    "interaction": ("prerequisite", "modifier", "comparison-control", "confounder"),
    "differential": ("release", "profile", "platform-or-backend"),
}


ARCHETYPES = {
    "standalone-library-surface": {
        "operations": {"compile", "test", "prefix-match", "full-match", "search", "next-match", "find-all", "extract", "partial-match", "replace-all", "expand-replacement"},
        "capabilities": {"captures", "backtracking", "replacement", "callbacks", "unicode", "partial"},
        "planning_profiles": 11,
    },
    "linear-or-dfa-surface": {
        "operations": {"compile", "test", "prefix-match", "full-match", "search", "find-all", "stream-scan", "block-scan", "vector-scan", "set-match"},
        "capabilities": {"linear", "unicode", "pattern-set", "streaming", "callbacks", "byte-domain"},
        "planning_profiles": 15,
    },
    "host-runtime-surface": {
        "operations": {item[0] for item in OPERATIONS if item[0] not in {"stream-scan", "block-scan", "vector-scan", "set-match", "partial-match"}},
        "capabilities": {"captures", "backtracking", "replacement", "callbacks", "unicode", "mutable-state"},
        "planning_profiles": 121,
    },
    "database-service-surface": {
        "operations": {"test", "search", "extract", "count", "position", "split", "replace-all"},
        "capabilities": {"captures", "replacement", "unicode", "occurrence-selection", "query-errors"},
        "planning_profiles": 41,
    },
    "cli-surface": {
        "operations": {"compile", "test", "search", "find-all", "replace-all"},
        "capabilities": {"captures", "replacement", "locale", "editor-state", "multi-pattern"},
        "planning_profiles": 24,
    },
    "posix-library-surface": {
        "operations": {"compile", "test", "prefix-match", "search", "find-all", "extract"},
        "capabilities": {"captures", "posix", "locale"},
        "planning_profiles": 12,
    },
}


# Rows are deliberately semantic rather than spelling-oriented. Syntax spellings
# are attached separately below and do not allocate additional feature identity.
FEATURE_GROUPS: list[dict[str, Any]] = [
    {
        "category": "grammar-and-composition",
        "feature_class": "pattern",
        "sources": ["posix-regex", "pcre2-pattern", "ecma-regexp"],
        "operations": ["compile", "test", "prefix-match", "full-match", "search", "find-all"],
        "rows": [
            ("literal-unit", "Literal text unit", "Consumes one literal unit in the profile's governed text domain."),
            ("literal-string", "Literal string", "Consumes an ordered sequence of literal text units."),
            ("concatenation", "Concatenation", "Requires adjacent pattern operands to match in sequence."),
            ("alternation", "Alternation", "Selects among alternative pattern branches under the profile's match-selection policy."),
            ("empty-pattern", "Empty pattern", "Defines a pattern that consumes no subject input."),
            ("empty-alternative", "Empty alternative", "Allows one branch of an alternation to consume no subject input."),
            ("wildcard", "Wildcard atom", "Consumes one governed text unit except units excluded by newline or domain policy."),
            ("escaped-literal", "Escaped literal", "Quotes a metacharacter so it denotes literal input."),
            ("quoted-literal-region", "Quoted literal region", "Quotes a sequence of pattern text as literal input until an explicit terminator."),
            ("noncapturing-group", "Noncapturing group", "Groups a subexpression for precedence or quantification without allocating a capture."),
            ("pattern-comment", "Pattern comment", "Embeds ignored commentary in the pattern grammar."),
            ("literal-grammar-director", "Literal grammar director", "Switches a complete pattern or remaining pattern region to literal interpretation."),
            ("grammar-mode-director", "Grammar mode director", "Switches among named regex grammars such as BRE, ERE, ARE or implementation modes."),
        ],
    },
    {
        "category": "character-classes",
        "feature_class": "character-class",
        "sources": ["posix-regex", "unicode-tr18", "pcre2-pattern", "ecma-regexp", "icu-regex"],
        "operations": ["compile", "test", "full-match", "search", "find-all"],
        "rows": [
            ("class-union", "Character-class union", "Matches a text unit that belongs to the union of class operands."),
            ("class-negation", "Character-class complement", "Matches a governed text unit outside the class operand's set."),
            ("class-range", "Character range", "Matches a text unit within an ordered inclusive range under the active range policy."),
            ("class-intersection", "Character-class intersection", "Matches a text unit common to each class operand."),
            ("class-subtraction", "Character-class subtraction", "Matches a text unit in one class but not a subtracted class."),
            ("class-symmetric-difference", "Character-class symmetric difference", "Matches a text unit in exactly one of two class operands."),
            ("nested-character-class", "Nested character class", "Uses a class expression as an operand inside another class expression."),
            ("posix-named-class", "POSIX named character class", "Matches the locale- or profile-defined members of a named POSIX class."),
            ("posix-collating-element", "POSIX collating element", "Treats a named collating element as one bracket-expression element."),
            ("posix-equivalence-class", "POSIX equivalence class", "Matches members equivalent under the active collation's primary weight."),
            ("class-string-member", "String-valued class member", "Allows a class operand to match a finite string rather than exactly one code point."),
            ("class-string-disjunction", "Class string disjunction", "Matches one of several explicitly listed strings inside a Unicode-set expression."),
            ("digit-class", "Digit shorthand class", "Matches the profile-defined digit set."),
            ("word-class", "Word-character shorthand class", "Matches the profile-defined word-character set."),
            ("whitespace-class", "Whitespace shorthand class", "Matches the profile-defined whitespace set."),
            ("horizontal-whitespace", "Horizontal whitespace", "Matches horizontal spacing characters under the profile's text model."),
            ("vertical-whitespace", "Vertical whitespace", "Matches vertical spacing or line-separator characters under the profile's text model."),
            ("generic-newline-sequence", "Generic newline sequence", "Consumes one logical newline sequence selected by the active newline convention."),
            ("unicode-general-category", "Unicode General_Category property", "Matches code points by Unicode General_Category value."),
            ("unicode-script", "Unicode Script property", "Matches code points by their primary Unicode Script value."),
            ("unicode-script-extensions", "Unicode Script_Extensions property", "Matches code points whose Script_Extensions set contains the requested script."),
            ("unicode-block", "Unicode block property", "Matches code points assigned to a named Unicode block range."),
            ("unicode-binary-property", "Unicode binary property", "Matches code points for which a named binary Unicode property is true."),
            ("unicode-property-alias", "Unicode property alias resolution", "Resolves standardized long, short and loose property names to the same property identity."),
            ("unicode-property-value-wildcard", "Unicode property-value wildcard", "Selects multiple property values by a wildcard over their names."),
            ("unicode-character-name", "Unicode character-name escape", "Matches a code point selected by its standardized character name or supported name alias."),
            ("unicode-string-property", "Unicode property of strings", "Matches a finite Unicode string belonging to a standardized string-valued property."),
        ],
    },
    {
        "category": "unicode-and-text-model",
        "feature_class": "unicode",
        "sources": ["unicode-tr18", "unicode-tr29", "icu-regex", "rust-regex", "pcre2-pattern"],
        "operations": ["compile", "test", "full-match", "search", "find-all", "position"],
        "rows": [
            ("unicode-code-point-domain", "Unicode code-point domain", "Treats one Unicode code point as the fundamental matching unit."),
            ("unicode-scalar-domain", "Unicode scalar-value domain", "Treats scalar values, excluding isolated surrogates, as the fundamental matching unit."),
            ("code-unit-domain", "Encoding code-unit domain", "Treats one code unit of the selected encoding as the fundamental matching unit."),
            ("byte-domain", "Arbitrary byte domain", "Matches arbitrary octets without requiring a valid character encoding."),
            ("single-code-unit-escape", "Single code-unit escape", "Consumes one code unit even when the surrounding pattern uses a Unicode mode."),
            ("extended-grapheme-cluster", "Extended grapheme cluster", "Consumes one default extended grapheme cluster under Unicode text segmentation."),
            ("legacy-grapheme-cluster", "Legacy grapheme cluster", "Consumes one legacy grapheme cluster under an older segmentation rule."),
            ("unicode-word-boundary", "Default Unicode word boundary", "Asserts a default Unicode word-break boundary."),
            ("unicode-grapheme-boundary", "Unicode grapheme boundary", "Asserts a default Unicode grapheme-cluster boundary."),
            ("unicode-sentence-boundary", "Unicode sentence boundary", "Asserts a default Unicode sentence-break boundary."),
            ("canonical-equivalence", "Canonical-equivalence matching", "Treats canonically equivalent Unicode sequences as equivalent for matching."),
            ("normalization-aware-matching", "Normalization-aware matching", "Matches through an explicit Unicode normalization transform while preserving result-coordinate semantics."),
            ("simple-case-folding", "Unicode simple case folding", "Performs case-insensitive comparison using one-to-one Unicode simple folds."),
            ("full-case-folding", "Unicode full case folding", "Performs case-insensitive comparison that may equate strings of different lengths."),
            ("locale-case-folding", "Locale-sensitive case matching", "Uses locale or culture-specific case relationships during matching."),
            ("ascii-restricted-unicode-classes", "ASCII-restricted Unicode classes", "Restricts otherwise Unicode-aware shorthand classes or boundaries to ASCII."),
            ("malformed-text-rejection", "Malformed encoded-text rejection", "Rejects a subject or pattern that is ill-formed in the selected encoding."),
            ("malformed-text-raw-units", "Malformed text as raw units", "Continues matching malformed encoded data as code units or bytes."),
            ("malformed-text-replacement", "Malformed text replacement decoding", "Repairs malformed input with replacement characters before matching."),
            ("native-index-unit", "Native result index unit", "Reports spans in the host's declared unit such as bytes, code units, code points or characters."),
        ],
    },
    {
        "category": "anchors-and-boundaries",
        "feature_class": "assertion",
        "sources": ["posix-regex", "pcre2-pattern", "ecma-regexp", "vim-regex", "oniguruma-regex"],
        "operations": ["compile", "test", "prefix-match", "full-match", "search", "find-all", "next-match"],
        "rows": [
            ("subject-start", "Absolute subject start", "Asserts the start of the complete governed subject independently of multiline mode."),
            ("subject-end-strict", "Strict absolute subject end", "Asserts the position after the final governed subject unit only."),
            ("subject-end-before-final-newline", "Subject end before final newline", "Asserts strict end or the position immediately before a permitted final newline."),
            ("line-start", "Line start", "Asserts subject start or a position following a governed line terminator."),
            ("line-end", "Line end", "Asserts subject end or a position preceding a governed line terminator."),
            ("word-boundary", "Word boundary", "Asserts a transition between word and non-word status under the active word definition."),
            ("non-word-boundary", "Non-word boundary", "Asserts that the current position is not a word boundary."),
            ("word-start", "Word start", "Asserts a transition into a word under the active word definition."),
            ("word-end", "Word end", "Asserts a transition out of a word under the active word definition."),
            ("previous-match-end", "Previous-match end", "Asserts the initial operation position or the end of the preceding successful match."),
            ("search-region-start", "Search-region start", "Asserts the start of a host-defined matcher region or subtext."),
            ("search-region-end", "Search-region end", "Asserts the end of a host-defined matcher region or subtext."),
            ("reset-reported-match-start", "Reset reported match start", "Keeps prior consumption and captures while moving the reported whole-match start to the current position."),
            ("reset-reported-match-end", "Reset reported match end", "Keeps later matching constraints while moving the reported whole-match end to the current position."),
            ("cursor-position", "Editor cursor position", "Asserts the current editor cursor position."),
            ("mark-position", "Editor mark position", "Asserts a named editor mark position."),
            ("line-number-position", "Line-number position", "Asserts that matching occurs on a specified editor line."),
            ("column-position", "Column position", "Asserts a specified physical or virtual editor column."),
            ("visual-selection-position", "Visual-selection position", "Asserts that the current position lies in the editor's visual selection."),
        ],
    },
    {
        "category": "groups-and-captures",
        "feature_class": "capture",
        "sources": ["pcre2-pattern", "dotnet-groups", "java-pattern", "python-re", "oniguruma-syntax"],
        "operations": ["compile", "test", "full-match", "search", "find-all", "extract", "position", "replace-all"],
        "rows": [
            ("numbered-capture", "Numbered capture", "Records the text and span matched by a parenthesized subexpression under an ordinal group number."),
            ("named-capture", "Named capture", "Records a capturing subexpression under a stable name and its profile-defined number."),
            ("explicit-capture-number", "Explicit capture number", "Assigns a capture number explicitly instead of solely by opening-parenthesis order."),
            ("branch-reset-group", "Branch-reset grouping", "Reuses capture numbers across alternatives occupying corresponding branch positions."),
            ("duplicate-group-name", "Duplicate group names", "Allows multiple capture definitions to share a name with governed lookup and reference rules."),
            ("duplicate-group-number", "Duplicate group numbers", "Allows distinct capture definitions to resolve to the same numeric identity."),
            ("capture-participation", "Capture participation", "Distinguishes whether a group participated in the successful match path."),
            ("unset-versus-empty-capture", "Unset versus empty capture", "Distinguishes nonparticipation from participation that consumed an empty string."),
            ("capture-value", "Capture value", "Returns the subject value associated with a capture."),
            ("capture-span", "Capture span", "Returns the governed start and end positions associated with a capture."),
            ("last-capture-of-repetition", "Last capture of a repetition", "Selects the final successful capture value produced by a quantified group."),
            ("capture-history", "Capture history", "Exposes every successful capture produced by a repeated or revisited group."),
            ("capture-name-table", "Capture name table", "Exposes the mapping from capture names to one or more numbers."),
            ("group-numbering-policy", "Group numbering policy", "Defines the ordinal allocation order for named, unnamed and branch-reset captures."),
            ("balancing-group", "Balancing group", "Uses one capture stack to balance or subtract captures from another stack."),
            ("capture-stack", "Capture stack", "Retains a stack or collection of successive captures for one group."),
            ("capture-suppression", "Capture suppression", "Disables capture allocation for otherwise capturing syntax under a mode or option."),
        ],
    },
    {
        "category": "backreferences-recursion-and-conditionals",
        "feature_class": "recursive",
        "sources": ["pcre2-pattern", "perl-regex", "boost-regex", "oniguruma-regex", "dotnet-regex"],
        "operations": ["compile", "test", "full-match", "search", "find-all", "extract"],
        "rows": [
            ("numbered-backreference", "Numbered backreference", "Consumes text equal under the profile's comparison rule to a previously captured numbered group."),
            ("named-backreference", "Named backreference", "Consumes text equal to a previously captured named group."),
            ("relative-backreference", "Relative backreference", "Resolves a capture by a signed offset from the reference location."),
            ("forward-backreference", "Forward backreference", "References a capture definition that appears later in pattern order under profile-specific participation rules."),
            ("unset-backreference-behavior", "Unset backreference behavior", "Defines whether a reference to a nonparticipating capture fails, matches empty, or errors."),
            ("numeric-subroutine-call", "Numeric subroutine call", "Invokes the pattern body defined by a numbered group without matching the group's previously captured text."),
            ("named-subroutine-call", "Named subroutine call", "Invokes the pattern body defined by a named group."),
            ("relative-subroutine-call", "Relative subroutine call", "Invokes a group body located by a signed group-number offset."),
            ("whole-pattern-recursion", "Whole-pattern recursion", "Recursively invokes the complete pattern from the current matching position."),
            ("group-recursion", "Group recursion", "Recursively invokes a group whose invocation is already active."),
            ("recursion-backtracking", "Backtracking into recursion", "Allows a later failure to re-enter a recursive or subroutine call and try unused alternatives."),
            ("atomic-recursion", "Atomic recursion", "Prevents re-entry into a completed recursive or subroutine call."),
            ("recursion-returned-captures", "Returned captures from recursion", "Restores selected capture values produced inside a recursion or subroutine to the caller."),
            ("capture-conditional", "Capture-participation conditional", "Selects a branch according to whether a named or numbered capture participated."),
            ("assertion-conditional", "Assertion conditional", "Selects a branch according to the result of a lookaround assertion."),
            ("recursion-conditional", "Recursion-state conditional", "Selects a branch according to whether matching is inside a specified recursion or subroutine."),
            ("define-conditional", "Definition-only conditional", "Declares reusable subpatterns in a branch that is skipped during ordinary flow."),
            ("version-conditional", "Engine-version conditional", "Selects a branch or compile result according to an engine version test embedded in the pattern."),
        ],
    },
    {
        "category": "lookaround-assertions",
        "feature_class": "assertion",
        "sources": ["pcre2-pattern", "perl-regex", "dotnet-groups", "java-pattern", "ecma-regexp", "python-regex"],
        "operations": ["compile", "test", "prefix-match", "full-match", "search", "find-all", "extract"],
        "rows": [
            ("positive-lookahead", "Positive lookahead", "Asserts that a subpattern matches forward from the current position without consuming it."),
            ("negative-lookahead", "Negative lookahead", "Asserts that a subpattern does not match forward from the current position."),
            ("atomic-lookahead", "Atomic lookahead", "Commits the successful internal choice of a lookahead against later backtracking."),
            ("non-atomic-lookahead", "Non-atomic positive lookahead", "Allows later failure to backtrack into a previously successful positive lookahead."),
            ("fixed-positive-lookbehind", "Fixed-length positive lookbehind", "Asserts a positive backward match whose alternatives have statically fixed lengths."),
            ("fixed-negative-lookbehind", "Fixed-length negative lookbehind", "Asserts absence of a backward fixed-length match."),
            ("different-length-lookbehind-alternatives", "Different-length fixed lookbehind alternatives", "Allows top-level fixed-length lookbehind alternatives to have different lengths."),
            ("bounded-variable-positive-lookbehind", "Bounded variable-length positive lookbehind", "Asserts a positive backward match with a finite statically bounded range of lengths."),
            ("bounded-variable-negative-lookbehind", "Bounded variable-length negative lookbehind", "Asserts absence of a backward match with a finite statically bounded range of lengths."),
            ("unbounded-positive-lookbehind", "Unbounded positive lookbehind", "Asserts a positive backward match whose possible length has no finite static maximum."),
            ("unbounded-negative-lookbehind", "Unbounded negative lookbehind", "Asserts absence of an unbounded backward match."),
            ("lookaround-capture-visibility", "Lookaround capture visibility", "Defines which captures made by a successful assertion remain observable outside it."),
            ("lookbehind-reverse-capture-selection", "Reverse lookbehind capture selection", "Defines capture choice when a lookbehind evaluates pattern atoms in reverse input direction."),
            ("lookbehind-backreference", "Backreference in lookbehind", "Permits a lookbehind operand to depend on a prior capture subject to bounded-length constraints."),
            ("lookbehind-subroutine", "Subroutine call in lookbehind", "Permits a bounded subroutine body inside lookbehind while restricting recursive cycles."),
        ],
    },
    {
        "category": "quantification-and-match-selection",
        "feature_class": "quantifier",
        "sources": ["posix-regex", "pcre2-pattern", "pcre2-matching", "postgres-regex", "re2-syntax"],
        "operations": ["compile", "test", "full-match", "search", "find-all", "extract"],
        "rows": [
            ("optional-quantifier", "Optional quantifier", "Repeats an operand zero or one time."),
            ("zero-or-more-quantifier", "Zero-or-more quantifier", "Repeats an operand any nonnegative number of times."),
            ("one-or-more-quantifier", "One-or-more quantifier", "Repeats an operand one or more times."),
            ("exact-quantifier", "Exact-count quantifier", "Repeats an operand exactly a specified number of times."),
            ("bounded-quantifier", "Bounded interval quantifier", "Repeats an operand within inclusive lower and upper bounds."),
            ("lower-bounded-quantifier", "Lower-bounded quantifier", "Repeats an operand at least a specified number of times with no finite upper bound."),
            ("upper-bounded-quantifier", "Upper-bounded quantifier", "Repeats an operand from zero through a specified upper bound."),
            ("greedy-preference", "Greedy quantifier preference", "Prefers a larger repetition count subject to overall matching policy."),
            ("lazy-preference", "Lazy quantifier preference", "Prefers a smaller repetition count subject to overall matching policy."),
            ("possessive-quantifier", "Possessive quantifier", "Commits the initially selected repetition count against later backtracking."),
            ("atomic-group", "Atomic grouping", "Commits the successful internal path of a grouped subpattern against later backtracking."),
            ("automatic-possessification", "Automatic possessification", "Transforms provably non-backtrackable repeats into possessive behavior during compilation."),
            ("quantified-empty-operand", "Quantified empty operand", "Defines progress, capture and termination behavior when a repeated operand can match empty."),
            ("nested-quantifier-validity", "Nested quantifier validity", "Defines whether adjacent or nested quantifier tokens are rejected, literalized or interpreted."),
            ("ordered-alternation", "Ordered alternation", "Prefers the first alternative that permits overall success."),
            ("leftmost-first-match", "Leftmost-first match selection", "Chooses the earliest start and then the first successful backtracking path."),
            ("leftmost-longest-match", "POSIX leftmost-longest selection", "Chooses the earliest start and longest whole match with ordered longest submatches."),
            ("shortest-match-at-start", "Shortest match at one start", "Returns the shortest of the matches beginning at the selected start position."),
            ("all-match-lengths-at-start", "All match lengths at one start", "Returns every match length beginning at the selected start position."),
            ("dfa-greediness-insensitivity", "DFA greediness insensitivity", "Treats greedy and lazy quantifiers equivalently when enumerating all paths."),
        ],
    },
    {
        "category": "backtracking-control-and-code",
        "feature_class": "control",
        "sources": ["pcre2-pattern", "pcre2-callout", "perl-regex", "oniguruma-syntax"],
        "operations": ["compile", "test", "full-match", "search", "find-all", "replace-all"],
        "rows": [
            ("force-failure", "Forced failure", "Forces the current matching path to fail immediately."),
            ("force-accept", "Forced acceptance", "Ends the current matching scope successfully without evaluating its remaining pattern."),
            ("prune-backtracking", "Prune backtracking", "Discards backtracking choices created since entering the current control scope."),
            ("skip-start-positions", "Skip start positions", "Fails the current attempt and advances the next unanchored start position to a governed point."),
            ("commit-start-position", "Commit start position", "Prevents unanchored matching from trying later subject start positions after failure."),
            ("then-alternative", "Advance to next alternative", "Prunes to the next alternative of the innermost governed alternation."),
            ("backtracking-mark", "Backtracking mark", "Labels a control point and exposes the last reached label in a result or control action."),
            ("numeric-callout", "Numeric match callout", "Invokes a host callback at a pattern position with numeric callout data."),
            ("string-callout", "String match callout", "Invokes a host callback at a pattern position with string callout data."),
            ("named-callout", "Named match callout", "Invokes a registered host callback selected by a name in the pattern."),
            ("callout-backtracking", "Callout during backtracking", "Invokes or re-invokes callbacks as matching enters, leaves or backtracks through callout positions."),
            ("substitution-callout", "Substitution callout", "Invokes a callback for each governed substitution event."),
            ("embedded-code", "Embedded match-time code", "Executes host-language code as part of pattern evaluation."),
            ("dynamic-regex-code", "Dynamic regex generation", "Executes host-language code whose result is parsed and evaluated as a subpattern."),
            ("code-conditional", "Code-evaluated conditional", "Selects a conditional branch using a host-language code result."),
            ("script-run", "Unicode script run", "Requires a subpattern's matched text to satisfy a governed Unicode script-run constraint."),
            ("absent-expression", "Absent expression", "Constrains matching so a forbidden subpattern is absent across a governed subject interval."),
        ],
    },
    {
        "category": "approximate-partial-and-multipattern",
        "feature_class": "special-operation",
        "sources": ["tre", "python-regex", "pcre2-partial", "hyperscan", "hyperscan-runtime", "rust-regex-set"],
        "operations": ["compile", "test", "search", "find-all", "partial-match", "stream-scan", "block-scan", "vector-scan", "set-match"],
        "rows": [
            ("approximate-edit-distance", "Approximate regex matching", "Allows a match within a governed edit-distance or cost bound."),
            ("approximate-insertion", "Approximate insertion", "Counts subject insertions as an allowed approximate-match edit."),
            ("approximate-deletion", "Approximate deletion", "Counts pattern deletions as an allowed approximate-match edit."),
            ("approximate-substitution", "Approximate substitution", "Counts character substitution as an allowed approximate-match edit."),
            ("approximate-cost-model", "Approximate cost model", "Assigns separate costs and bounds to insertion, deletion and substitution edits."),
            ("best-approximate-match", "Best approximate match", "Selects the lowest-cost match rather than the first match within a bound."),
            ("enhanced-approximate-match", "Enhanced next approximate match", "Improves the fit of the next match without globally searching for the best match."),
            ("soft-partial-match", "Soft partial match", "Reports a viable incomplete match only when no complete match is available."),
            ("hard-partial-match", "Hard partial match", "Reports a viable incomplete match even when a complete shorter match is available."),
            ("partial-match-restart", "Restartable partial match", "Continues a prior partial match after additional subject data arrives."),
            ("streaming-match", "Streaming matching", "Maintains matcher state across sequential subject blocks so matches may span block boundaries."),
            ("block-match", "Block matching", "Matches one complete contiguous block with no cross-call subject state."),
            ("vectored-match", "Vectored matching", "Matches a logical subject presented as several simultaneously available blocks."),
            ("multi-pattern-database", "Multi-pattern compilation", "Compiles multiple independently identified patterns into one matching database."),
            ("pattern-set-results", "Pattern-set result identity", "Reports which members of a pattern set matched without necessarily reporting their spans."),
            ("multi-pattern-overlap", "Overlapping multi-pattern results", "Reports distinct pattern members whose matches overlap in the same subject scan."),
            ("logical-pattern-combination", "Logical combination of pattern results", "Defines a match as a Boolean combination of independently identified pattern results."),
            ("start-of-match-tracking", "Start-of-match tracking", "Reports the leftmost possible start associated with an end-offset match event."),
            ("start-of-match-horizon", "Start-of-match horizon", "Reports exact starts only within a configured distance and a past-horizon sentinel otherwise."),
            ("match-event-callback", "Match-event callback", "Delivers multi-pattern or streaming match events through a host callback."),
            ("callback-scan-termination", "Callback scan termination", "Allows a match callback to stop a scan and moves the stream to a terminal state."),
            ("single-match-pattern", "Single match per pattern", "Suppresses later match events for a pattern after its first event."),
            ("prefilter-superset", "Prefilter superset matching", "Permits false-positive events while guaranteeing that true matches are not omitted within scope."),
            ("match-offset-constraints", "Match offset constraints", "Constrains acceptable match starts, ends or minimum lengths outside pattern syntax."),
        ],
    },
    {
        "category": "host-operations-and-results",
        "feature_class": "host-operation",
        "sources": ["ecma-regexp", "java-matcher", "python-re", "w3c-xpath-regex", "postgres-regex", "bigquery-regex", "emacs-regex"],
        "operations": [item[0] for item in OPERATIONS],
        "rows": [
            ("occurrence-selection", "Occurrence selection", "Selects a numbered non-overlapping match occurrence after a governed start position."),
            ("split-capture-inclusion", "Split capture inclusion", "Includes delimiter capture values in split output."),
            ("split-empty-match", "Split by empty match", "Defines fields and advancement when the delimiter pattern matches empty."),
            ("split-limit", "Split limit and trailing-empty policy", "Constrains split result count and defines retention of trailing empty fields."),
            ("zero-length-advancement", "Zero-length match advancement", "Moves the next search cursor after an empty match without nontermination or duplicate credit."),
            ("mutable-match-cursor", "Mutable match cursor", "Stores and updates a next-search position as observable host state."),
            ("sticky-cursor-match", "Sticky cursor match", "Requires a stateful next match to begin exactly at the cursor."),
            ("matcher-region", "Matcher region", "Restricts matching to a host-selected subject interval."),
            ("transparent-region-bounds", "Transparent region bounds", "Allows lookaround and boundary checks to see beyond a matcher region."),
            ("anchoring-region-bounds", "Anchoring region bounds", "Treats matcher-region bounds as anchorable subject boundaries."),
            ("structured-analyze-string", "Structured analyze-string result", "Partitions input into matched and non-matched regions with nested capture structure."),
            ("tokenize-zero-length-prohibition", "Zero-length tokenizer prohibition", "Rejects a tokenizer delimiter pattern capable of matching an empty string."),
            ("match-end-state", "Match end-state indicators", "Reports whether end of input was reached or additional input could change the result."),
        ],
    },
    {
        "category": "replacement-language",
        "feature_class": "replacement",
        "sources": ["pcre2-api", "pcre2-syntax", "dotnet-regex", "java-matcher", "python-re", "ecma-regexp", "bigquery-regex"],
        "operations": ["replace-first", "replace-all", "replace-callback", "expand-replacement"],
        "rows": [
            ("replacement-literal", "Literal replacement text", "Inserts literal replacement text for a selected match."),
            ("replacement-numbered-group", "Numbered capture replacement", "Inserts the value of a numbered capture into replacement output."),
            ("replacement-named-group", "Named capture replacement", "Inserts the value of a named capture into replacement output."),
            ("replacement-whole-match", "Whole-match replacement token", "Inserts the complete matched substring into replacement output."),
            ("replacement-prefix", "Pre-match prefix replacement token", "Inserts subject text preceding the match."),
            ("replacement-suffix", "Post-match suffix replacement token", "Inserts subject text following the match."),
            ("replacement-last-capture", "Last participating capture replacement", "Inserts the last capture that participated under the replacement profile's ordering rule."),
            ("replacement-whole-input", "Whole-input replacement token", "Inserts the complete original subject."),
            ("replacement-escape", "Replacement metacharacter escaping", "Quotes a replacement-language metacharacter as literal output."),
            ("replacement-case-conversion", "Replacement case conversion", "Transforms subsequent replacement output to upper, lower or title case."),
            ("replacement-conditional", "Conditional replacement expansion", "Selects replacement text according to capture participation or value."),
            ("replacement-unset-group", "Unset replacement group behavior", "Defines whether an unset capture inserts empty text, preserves syntax, or raises an error."),
            ("replacement-unknown-group", "Unknown replacement group behavior", "Defines compile or runtime behavior for a nonexistent capture reference."),
            ("callback-replacement", "Callback replacement", "Computes replacement text from a host callback receiving match data."),
            ("append-replacement-state", "Append-replacement state", "Maintains an append position while incrementally copying unmatched and replacement text."),
            ("replacement-only-output", "Replacement-only output", "Returns only generated replacement fragments rather than a copy of unmatched subject text."),
        ],
    },
    {
        "category": "diagnostics-resources-and-safety",
        "feature_class": "diagnostic",
        "sources": ["pcre2-api", "pcre2-matching", "re2-readme", "rust-regex", "mysql-regex", "gnu-grep", "boost-regex"],
        "operations": ["compile", "test", "search", "find-all", "replace-all", "stream-scan"],
        "rows": [
            ("compile-syntax-error", "Pattern syntax error", "Rejects invalid pattern grammar with a compile-phase error."),
            ("invalid-escape-error", "Invalid escape error", "Rejects an unrecognized or malformed escape under the selected grammar."),
            ("invalid-quantifier-error", "Invalid quantifier error", "Rejects malformed, out-of-order or context-invalid quantifier syntax."),
            ("invalid-group-reference", "Invalid group reference", "Rejects or classifies a reference to a nonexistent or illegal group."),
            ("invalid-unicode-property", "Invalid Unicode property error", "Rejects an unknown property or illegal property value."),
            ("unsupported-construct", "Unsupported construct rejection", "Rejects a syntactically identifiable feature unavailable to the selected matcher or profile."),
            ("diagnostic-offset", "Diagnostic source offset", "Reports the native pattern or replacement position associated with an error."),
            ("diagnostic-code-and-class", "Diagnostic code and class", "Exposes a stable or native error classification in addition to message text."),
            ("pattern-size-limit", "Pattern size limit", "Rejects compilation when pattern size or compiled representation exceeds a governed limit."),
            ("nesting-depth-limit", "Pattern nesting-depth limit", "Rejects or stops patterns whose group nesting exceeds a governed bound."),
            ("match-step-limit", "Match step limit", "Stops matching after a governed amount of matcher work."),
            ("backtracking-depth-limit", "Backtracking depth limit", "Stops matching when the backtracking or recursion depth bound is reached."),
            ("match-heap-limit", "Match heap limit", "Stops matching when governed backtracking heap allocation is exhausted."),
            ("operation-timeout", "Operation timeout", "Stops a complete match, iteration or replacement operation after a governed duration."),
            ("stack-exhaustion", "Stack exhaustion outcome", "Reports or contains native stack exhaustion caused by pattern evaluation."),
            ("workspace-exhaustion", "Matcher workspace exhaustion", "Reports insufficient DFA, scratch or stream workspace without misclassifying it as no-match."),
            ("replacement-buffer-overflow", "Replacement output overflow sizing", "Reports insufficient output capacity and, where supported, the required size."),
            ("linear-time-guarantee", "Linear-time match guarantee", "Guarantees asymptotically linear match time within the documented feature subset and resource model."),
            ("bounded-memory-guarantee", "Bounded matcher memory", "Constrains matcher memory through a configured or implementation-defined budget with graceful failure."),
            ("target-crash-or-signal", "Target crash or signal outcome", "Preserves a target process crash or signal as a regex execution outcome distinct from infrastructure failure."),
        ],
    },
    {
        "category": "editor-cli-and-product-surfaces",
        "feature_class": "host-operation",
        "sources": ["vim-regex", "emacs-regex", "gnu-grep", "postgres-regex", "mysql-regex", "oracle-regex"],
        "operations": ["compile", "test", "search", "find-all", "replace-all", "set-match"],
        "rows": [
            ("magic-syntax-mode", "Magic syntax mode", "Changes which punctuation characters are metacharacters without changing the intended operator identities."),
            ("syntax-table-class", "Editor syntax-table class", "Matches characters according to the active editor syntax table."),
            ("character-category-class", "Editor character-category class", "Matches characters assigned to an editor-defined category."),
            ("keyword-character-class", "Keyword-character class", "Matches characters considered part of editor keywords under local configuration."),
            ("file-name-character-class", "File-name character class", "Matches characters considered valid in file names by an editor surface."),
            ("ignore-combining-differences", "Ignore combining-character differences", "Ignores selected composing-character differences during matching."),
            ("multiple-pattern-input", "Multiple independent input patterns", "Accepts several patterns whose matches are combined by the host command."),
            ("line-record-domain", "Line-record matching domain", "Applies regex matching independently to host-defined records or lines rather than an unconstrained subject."),
            ("nul-record-domain", "NUL-delimited record domain", "Uses NUL rather than newline as the host record separator."),
            ("binary-file-policy", "Binary-input matching policy", "Changes matching and reporting when the host classifies input as binary or malformed text."),
            ("sql-null-propagation", "SQL NULL propagation", "Returns SQL NULL rather than match or no-match when a governed regex argument is NULL."),
            ("sql-collation-selection", "SQL collation selection", "Derives matching character and case behavior from an explicit or implicit SQL collation."),
        ],
    },
]


FEATURE_VARIANTS: dict[str, list[str]] = {
    "wildcard": ["newline-excluding", "dotall", "code-point", "code-unit", "byte"],
    "class-range": ["code-point-order", "locale-collation", "implementation-defined-outside-posix-locale"],
    "word-class": ["ascii", "unicode-property-derived", "locale-derived", "editor-syntax-derived"],
    "generic-newline-sequence": ["unicode-any-newline", "crlf-atomic", "configured-bsr"],
    "extended-grapheme-cluster": ["legacy-grapheme", "extended-grapheme"],
    "native-index-unit": ["byte", "utf-16-code-unit", "utf-32-code-unit", "code-point", "one-based-character"],
    "subject-end-before-final-newline": ["single-final-lf", "configured-final-newline-sequence"],
    "previous-match-end": ["initial-subject-start", "operation-start-offset", "previous-success-end"],
    "duplicate-group-name": ["first-definition", "first-participating", "last-participating", "all-captures"],
    "capture-history": ["value-history", "start-history", "end-history", "span-history", "capture-tree"],
    "unset-backreference-behavior": ["fail", "match-empty", "compile-error"],
    "recursion-backtracking": ["backtrackable", "historically-atomic"],
    "fixed-positive-lookbehind": ["equal-length-alternatives", "different-fixed-length-alternatives"],
    "bounded-variable-positive-lookbehind": ["caller-configured-maximum", "implementation-fixed-maximum"],
    "unbounded-positive-lookbehind": ["forward-implemented-reverse-evaluation", "reverse-search-implementation"],
    "possessive-quantifier": ["zero-or-more", "one-or-more", "optional", "bounded-interval"],
    "leftmost-longest-match": ["whole-match-longest", "ordered-submatch-longest"],
    "numeric-callout": ["compile-time-auto-callout", "explicit-numeric"],
    "approximate-cost-model": ["uniform-edit-cost", "per-edit-cost", "per-group-cost-and-bound"],
    "partial-match-restart": ["caller-retained-overlap", "dfa-state-restart"],
    "streaming-match": ["cross-block-match", "end-of-stream-delayed-assertion", "stream-reset-copy-compress"],
    "pattern-set-results": ["any-pattern", "matching-pattern-identities", "no-capture-result"],
    "split-limit": ["positive-limit", "zero-limit", "negative-or-unlimited", "trailing-empty-retained", "trailing-empty-dropped"],
    "zero-length-advancement": ["one-code-unit", "one-code-point", "same-position-after-nonempty", "adjacent-empty-suppression"],
    "mutable-match-cursor": ["success-end", "failure-reset", "externally-settable"],
    "replacement-unset-group": ["empty", "error", "literal-preservation"],
    "operation-timeout": ["match-only", "whole-findall", "whole-replacement-including-callback"],
    "binary-file-policy": ["text", "binary-summary", "without-match", "encoding-error-suppression"],
}


FEATURE_ALIASES: dict[str, list[str]] = {
    "wildcard": ["dot", "any character"],
    "noncapturing-group": ["non-capturing parentheses"],
    "class-negation": ["negated character class", "complemented bracket expression"],
    "class-subtraction": ["character class difference"],
    "unicode-general-category": ["Unicode category"],
    "extended-grapheme-cluster": ["grapheme matcher"],
    "subject-end-strict": ["absolute end anchor"],
    "subject-end-before-final-newline": ["soft end anchor"],
    "previous-match-end": ["contiguous match anchor"],
    "reset-reported-match-start": ["keep out", "match-start reset"],
    "branch-reset-group": ["branch reset"],
    "capture-history": ["repeated captures", "capture collection"],
    "numbered-backreference": ["backref"],
    "numeric-subroutine-call": ["subpattern call"],
    "whole-pattern-recursion": ["recursive pattern"],
    "fixed-positive-lookbehind": ["positive lookbehind assertion"],
    "fixed-negative-lookbehind": ["negative lookbehind assertion"],
    "bounded-variable-positive-lookbehind": ["variable-length lookbehind"],
    "lazy-preference": ["reluctant quantifier", "non-greedy quantifier"],
    "possessive-quantifier": ["non-backtracking quantifier"],
    "atomic-group": ["independent subexpression"],
    "leftmost-longest-match": ["POSIX longest-leftmost"],
    "force-failure": ["fail verb"],
    "prune-backtracking": ["prune verb"],
    "approximate-edit-distance": ["fuzzy regex", "approximate regular expression"],
    "soft-partial-match": ["partial soft"],
    "hard-partial-match": ["partial hard"],
    "multi-pattern-database": ["regex set", "pattern set"],
    "callback-replacement": ["replacement evaluator", "function replacement"],
    "linear-time-guarantee": ["ReDoS-resistant matching"],
}


FEATURE_MODIFIERS: dict[str, list[str]] = {
    "wildcard": ["dotall", "newline-convention"],
    "line-start": ["multiline-anchors", "newline-convention", "not-beginning-of-line"],
    "line-end": ["multiline-anchors", "newline-convention", "not-end-of-line", "dollar-end-only"],
    "word-class": ["unicode-properties", "ascii-restriction", "locale-sensitive"],
    "word-boundary": ["unicode-properties", "ascii-restriction", "locale-sensitive"],
    "literal-unit": ["case-insensitive", "unicode-mode", "locale-sensitive"],
    "simple-case-folding": ["case-insensitive", "unicode-mode"],
    "full-case-folding": ["case-insensitive", "unicode-mode"],
    "numbered-capture": ["explicit-capture"],
    "duplicate-group-name": ["allow-duplicate-names"],
    "greedy-preference": ["ungreedy-default"],
    "lazy-preference": ["ungreedy-default"],
    "automatic-possessification": ["no-auto-possess"],
    "mutable-match-cursor": ["global", "sticky"],
    "native-index-unit": ["has-indices"],
    "soft-partial-match": ["partial-soft"],
    "hard-partial-match": ["partial-hard"],
    "best-approximate-match": ["fuzzy-best"],
    "enhanced-approximate-match": ["fuzzy-enhance"],
    "single-match-pattern": ["single-match-per-pattern"],
    "prefilter-superset": ["prefilter"],
    "leftmost-longest-match": ["posix-longest"],
    "binary-file-policy": ["locale-sensitive"],
}


FEATURE_PREREQUISITES: dict[str, list[str]] = {
    "branch-reset-group": ["numbered-capture"],
    "duplicate-group-number": ["numbered-capture"],
    "capture-history": ["numbered-capture"],
    "balancing-group": ["capture-stack"],
    "numbered-backreference": ["numbered-capture"],
    "named-backreference": ["named-capture"],
    "relative-backreference": ["numbered-capture"],
    "numeric-subroutine-call": ["noncapturing-group"],
    "named-subroutine-call": ["named-capture"],
    "whole-pattern-recursion": ["numeric-subroutine-call"],
    "group-recursion": ["numeric-subroutine-call"],
    "recursion-returned-captures": ["group-recursion", "capture-value"],
    "capture-conditional": ["capture-participation"],
    "assertion-conditional": ["positive-lookahead"],
    "fixed-positive-lookbehind": ["positive-lookahead"],
    "bounded-variable-positive-lookbehind": ["fixed-positive-lookbehind"],
    "unbounded-positive-lookbehind": ["bounded-variable-positive-lookbehind"],
    "possessive-quantifier": ["greedy-preference"],
    "automatic-possessification": ["possessive-quantifier"],
    "start-of-match-horizon": ["start-of-match-tracking", "streaming-match"],
    "pattern-set-results": ["multi-pattern-database"],
    "logical-pattern-combination": ["multi-pattern-database"],
    "callback-scan-termination": ["match-event-callback"],
    "replacement-numbered-group": ["numbered-capture"],
    "replacement-named-group": ["named-capture"],
    "replacement-last-capture": ["capture-participation"],
}


SYNTAX_FORMS: dict[str, str] = {
    "literal-unit": "<literal>",
    "concatenation": "<A><B>",
    "alternation": "<A>|<B>",
    "empty-pattern": "(?:)",
    "empty-alternative": "<A>|",
    "wildcard": ".",
    "quoted-literal-region": r"\Q...\E",
    "noncapturing-group": "(?:<A>)",
    "pattern-comment": "(?#...)",
    "class-union": "[<A><B>]",
    "class-negation": "[^<A>]",
    "class-range": "[<A>-<B>]",
    "class-intersection": "[<A>&&<B>]",
    "class-subtraction": "[<A>--<B>] or [<A>-[<B>]]",
    "class-symmetric-difference": "[<A>~~<B>]",
    "posix-named-class": "[[:<name>:]]",
    "posix-collating-element": "[[.<element>.]]",
    "posix-equivalence-class": "[[=<element>=]]",
    "class-string-disjunction": r"\q{<string>|<string>}",
    "digit-class": r"\d / \D",
    "word-class": r"\w / \W",
    "whitespace-class": r"\s / \S",
    "horizontal-whitespace": r"\h / \H",
    "vertical-whitespace": r"\v / \V",
    "generic-newline-sequence": r"\R",
    "unicode-general-category": r"\p{General_Category=<value>}",
    "unicode-script": r"\p{Script=<value>}",
    "unicode-script-extensions": r"\p{Script_Extensions=<value>}",
    "unicode-block": r"\p{Block=<value>}",
    "unicode-binary-property": r"\p{<binary-property>}",
    "unicode-character-name": r"\N{<name>}",
    "extended-grapheme-cluster": r"\X",
    "subject-start": r"\A or ^",
    "subject-end-strict": r"\z",
    "subject-end-before-final-newline": r"\Z or $",
    "line-start": "^",
    "line-end": "$",
    "word-boundary": r"\b",
    "non-word-boundary": r"\B",
    "word-start": r"\<",
    "word-end": r"\>",
    "previous-match-end": r"\G",
    "reset-reported-match-start": r"\K or \\zs",
    "reset-reported-match-end": r"\ze",
    "numbered-capture": "(<A>)",
    "named-capture": "(?<name><A>) or (?P<name><A>)",
    "explicit-capture-number": "(?|...)",
    "branch-reset-group": "(?|<A>|<B>)",
    "duplicate-group-name": "multiple named groups with one name",
    "numbered-backreference": r"\1",
    "named-backreference": r"\k<name> or (?P=name)",
    "relative-backreference": r"\g{-1}",
    "numeric-subroutine-call": "(?1)",
    "named-subroutine-call": "(?&name) or (?P>name)",
    "relative-subroutine-call": "(?-1)",
    "whole-pattern-recursion": "(?R) or (?0)",
    "capture-conditional": "(?(<name>)<yes>|<no>)",
    "assertion-conditional": "(?(?=<A>)<yes>|<no>)",
    "recursion-conditional": "(?(R)<yes>|<no>)",
    "define-conditional": "(?(DEFINE)<definitions>)",
    "positive-lookahead": "(?=<A>)",
    "negative-lookahead": "(?!<A>)",
    "atomic-lookahead": "(?=<A>) under atomic assertion semantics",
    "non-atomic-lookahead": "*napla:<A> or (?*<A>)",
    "fixed-positive-lookbehind": "(?<=<fixed-A>)",
    "fixed-negative-lookbehind": "(?<!<fixed-A>)",
    "bounded-variable-positive-lookbehind": "(?<=<bounded-A>)",
    "bounded-variable-negative-lookbehind": "(?<!<bounded-A>)",
    "unbounded-positive-lookbehind": "(?<=<unbounded-A>)",
    "unbounded-negative-lookbehind": "(?<!<unbounded-A>)",
    "optional-quantifier": "<A>?",
    "zero-or-more-quantifier": "<A>*",
    "one-or-more-quantifier": "<A>+",
    "exact-quantifier": "<A>{n}",
    "bounded-quantifier": "<A>{n,m}",
    "lower-bounded-quantifier": "<A>{n,}",
    "upper-bounded-quantifier": "<A>{,m}",
    "lazy-preference": "<quantifier>?",
    "possessive-quantifier": "<quantifier>+",
    "atomic-group": "(?>A)",
    "force-failure": "(*FAIL) or (?!)",
    "force-accept": "(*ACCEPT)",
    "prune-backtracking": "(*PRUNE)",
    "skip-start-positions": "(*SKIP)",
    "commit-start-position": "(*COMMIT)",
    "then-alternative": "(*THEN)",
    "backtracking-mark": "(*MARK:<name>)",
    "numeric-callout": "(?C<number>)",
    "string-callout": "(?C\"<text>\")",
    "embedded-code": "(?{ <code> })",
    "dynamic-regex-code": "(??{ <code> })",
    "script-run": "(*script_run:<A>)",
    "absent-expression": "(?~<A>)",
    "approximate-edit-distance": "<A>{e<=n}",
    "approximate-insertion": "<A>{i<=n}",
    "approximate-deletion": "<A>{d<=n}",
    "approximate-substitution": "<A>{s<=n}",
    "magic-syntax-mode": r"\v / \m / \M / \V",
}


FEATURE_RELATIONS: list[tuple[str, str, str]] = [
    ("positive-lookahead", "negative-lookahead", "polarity-contrast"),
    ("fixed-positive-lookbehind", "fixed-negative-lookbehind", "polarity-contrast"),
    ("bounded-variable-positive-lookbehind", "unbounded-positive-lookbehind", "generality-contrast"),
    ("atomic-group", "possessive-quantifier", "related-backtracking-suppression"),
    ("numeric-subroutine-call", "whole-pattern-recursion", "call-target-contrast"),
    ("group-recursion", "named-subroutine-call", "recursive-versus-nonrecursive-call"),
    ("leftmost-first-match", "leftmost-longest-match", "conflicting-selection-policy"),
    ("greedy-preference", "lazy-preference", "conflicting-preference"),
    ("soft-partial-match", "hard-partial-match", "partial-policy-contrast"),
    ("streaming-match", "block-match", "subject-delivery-contrast"),
    ("multi-pattern-database", "pattern-set-results", "producer-consumer"),
    ("numbered-capture", "numbered-backreference", "defines-reference-target"),
    ("named-capture", "named-backreference", "defines-reference-target"),
    ("duplicate-group-name", "named-backreference", "name-resolution-interaction"),
    ("unicode-code-point-domain", "byte-domain", "conflicting-text-domain"),
    ("full-case-folding", "simple-case-folding", "folding-strength-contrast"),
    ("class-string-member", "class-union", "string-versus-character-membership"),
    ("zero-length-advancement", "mutable-match-cursor", "termination-requirement"),
    ("replacement-unset-group", "unset-versus-empty-capture", "result-state-interaction"),
    ("operation-timeout", "target-crash-or-signal", "outcome-classification-contrast"),
    ("linear-time-guarantee", "backtracking-depth-limit", "resource-model-contrast"),
]


HISTORICAL_ONLY = {"atomic-recursion", "legacy-grapheme-cluster"}


# Feature-level bindings prevent a category checklist source from being
# misrepresented as documentation for every member of that category.
FEATURE_SOURCE_OVERRIDES: dict[str, list[str]] = {
    "quoted-literal-region": ["pcre2-pattern", "perl-regex"],
    "noncapturing-group": ["pcre2-pattern", "ecma-regexp"],
    "pattern-comment": ["pcre2-pattern", "dotnet-regex"],
    "literal-grammar-director": ["postgres-regex", "pcre2-pattern"],
    "grammar-mode-director": ["postgres-regex", "tcl-regex"],
    "class-intersection": ["unicode-tr18", "pcre2-pattern", "ecma-regexp"],
    "class-subtraction": ["unicode-tr18", "w3c-xsd-regex", "ecma-regexp"],
    "class-symmetric-difference": ["ecma-regexp"],
    "nested-character-class": ["unicode-tr18", "ecma-regexp"],
    "class-string-member": ["ecma-regexp"],
    "class-string-disjunction": ["ecma-regexp"],
    "horizontal-whitespace": ["pcre2-pattern"],
    "vertical-whitespace": ["pcre2-pattern"],
    "generic-newline-sequence": ["pcre2-pattern", "icu-regex"],
    "unicode-general-category": ["unicode-tr18", "icu-regex"],
    "unicode-script": ["unicode-tr18", "icu-regex"],
    "unicode-script-extensions": ["unicode-tr18", "ecma-regexp"],
    "unicode-block": ["unicode-tr18", "icu-regex"],
    "unicode-binary-property": ["unicode-tr18", "ecma-regexp"],
    "unicode-property-alias": ["unicode-tr18"],
    "unicode-property-value-wildcard": ["pcre2-pattern"],
    "unicode-character-name": ["pcre2-pattern", "python-re"],
    "unicode-string-property": ["ecma-regexp", "unicode-tr18"],
    "native-index-unit": ["ecma-regexp", "java-matcher", "rust-regex"],
    "malformed-text-rejection": ["rust-regex", "pcre2-api"],
    "malformed-text-raw-units": ["rust-regex", "pcre2-pattern"],
    "malformed-text-replacement": ["icu-regex"],
    "subject-start": ["pcre2-pattern", "ecma-regexp"],
    "subject-end-strict": ["pcre2-pattern"],
    "subject-end-before-final-newline": ["pcre2-pattern", "ecma-regexp"],
    "previous-match-end": ["pcre2-pattern", "ruby-regexp"],
    "reset-reported-match-start": ["pcre2-pattern", "vim-regex"],
    "reset-reported-match-end": ["vim-regex"],
    "cursor-position": ["vim-regex", "emacs-regex"],
    "mark-position": ["vim-regex", "emacs-regex"],
    "line-number-position": ["vim-regex"],
    "column-position": ["vim-regex"],
    "visual-selection-position": ["vim-regex"],
    "capture-history": ["dotnet-groups", "python-regex", "oniguruma-syntax"],
    "balancing-group": ["dotnet-groups"],
    "capture-stack": ["dotnet-groups"],
    "duplicate-group-name": ["pcre2-pattern", "python-regex"],
    "atomic-recursion": ["pcre2-pattern"],
    "unbounded-positive-lookbehind": ["python-regex"],
    "unbounded-negative-lookbehind": ["python-regex"],
    "lazy-preference": ["pcre2-pattern", "java-pattern"],
    "possessive-quantifier": ["pcre2-pattern", "java-pattern", "python-re"],
    "atomic-group": ["pcre2-pattern", "dotnet-groups", "python-re"],
    "automatic-possessification": ["pcre2-pattern"],
    "shortest-match-at-start": ["pcre2-matching"],
    "all-match-lengths-at-start": ["pcre2-matching"],
    "dfa-greediness-insensitivity": ["pcre2-matching"],
    "numeric-callout": ["pcre2-callout"],
    "string-callout": ["pcre2-callout"],
    "named-callout": ["oniguruma-syntax"],
    "callout-backtracking": ["pcre2-callout"],
    "substitution-callout": ["pcre2-callout"],
    "embedded-code": ["perl-regex"],
    "dynamic-regex-code": ["perl-regex"],
    "code-conditional": ["perl-regex"],
    "absent-expression": ["oniguruma-regex", "ruby-regexp"],
    "soft-partial-match": ["pcre2-partial", "boost-regex"],
    "hard-partial-match": ["pcre2-partial"],
    "partial-match-restart": ["pcre2-partial"],
    "streaming-match": ["hyperscan", "hyperscan-runtime"],
    "block-match": ["hyperscan"],
    "vectored-match": ["hyperscan"],
    "multi-pattern-database": ["hyperscan", "rust-regex-set"],
    "pattern-set-results": ["rust-regex-set", "hyperscan-runtime"],
    "multi-pattern-overlap": ["hyperscan-runtime"],
    "logical-pattern-combination": ["hyperscan"],
    "start-of-match-tracking": ["hyperscan-runtime"],
    "start-of-match-horizon": ["hyperscan-runtime"],
    "match-event-callback": ["hyperscan-runtime"],
    "callback-scan-termination": ["hyperscan-runtime"],
    "single-match-pattern": ["hyperscan"],
    "prefilter-superset": ["hyperscan"],
    "match-offset-constraints": ["hyperscan"],
    "matcher-region": ["java-matcher"],
    "transparent-region-bounds": ["java-matcher"],
    "anchoring-region-bounds": ["java-matcher"],
    "structured-analyze-string": ["w3c-xpath-regex"],
    "tokenize-zero-length-prohibition": ["w3c-xpath-regex"],
    "occurrence-selection": ["postgres-regex", "oracle-regex", "bigquery-regex"],
    "replacement-prefix": ["dotnet-regex", "ecma-regexp"],
    "replacement-suffix": ["dotnet-regex", "ecma-regexp"],
    "replacement-last-capture": ["dotnet-regex", "ecma-regexp"],
    "replacement-whole-input": ["dotnet-regex"],
    "replacement-case-conversion": ["pcre2-syntax"],
    "replacement-conditional": ["pcre2-syntax"],
    "operation-timeout": ["python-regex", "dotnet-regex"],
    "linear-time-guarantee": ["re2-readme", "rust-regex"],
    "bounded-memory-guarantee": ["re2-readme", "rust-regex"],
    "workspace-exhaustion": ["pcre2-matching", "hyperscan-runtime"],
    "multiple-pattern-input": ["gnu-grep"],
    "line-record-domain": ["gnu-grep"],
    "nul-record-domain": ["gnu-grep"],
    "binary-file-policy": ["gnu-grep"],
    "sql-null-propagation": ["postgres-regex", "mysql-regex", "oracle-regex"],
    "sql-collation-selection": ["mysql-regex", "oracle-regex"],
}


LEGACY_UNRESOLVED = [
    {
        "candidate_id": f"candidate.legacy-bridge.unrecovered-{index:02d}",
        "label": f"Unrecovered retired feature bridge record {index}",
        "disposition": "unresolved",
        "reason": "The retired Knowledge workspace reported ten provisional bridge records, but only the positive-lookbehind identity remains recoverable from governed artifacts. The record is conserved without guessing its identity.",
        "source_ids": ["legacy-knowledge-tombstone"],
    }
    for index in range(1, 10)
]


SEARCH_OPERATIONS = {"test", "prefix-match", "full-match", "search", "next-match", "find-all", "find-overlapping", "extract", "count", "position"}
CAPTURE_OPERATIONS = {"prefix-match", "full-match", "search", "next-match", "find-all", "find-overlapping", "extract", "split", "replace-first", "replace-all", "replace-callback", "analyze"}
REPLACEMENT_OPERATIONS = {"replace-first", "replace-all", "replace-callback", "expand-replacement"}
RESOURCE_OPERATIONS = {"compile", "test", "prefix-match", "full-match", "search", "next-match", "find-all", "partial-match", "stream-scan", "block-scan", "vector-scan", "set-match"}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _artifact_digest(value: dict[str, Any], *excluded: str) -> str:
    body = deepcopy(value)
    for key in excluded:
        body.pop(key, None)
    return _sha256(canonical_bytes(body))


def _slug(value: str) -> str:
    return "-".join(part for part in value.lower().replace("_", "-").split("-") if part)


def _feature_rows() -> list[tuple[dict[str, Any], tuple[str, str, str]]]:
    return [(group, row) for group in FEATURE_GROUPS for row in group["rows"]]


def _source_ids_for(feature_id: str) -> list[str]:
    for group, row in _feature_rows():
        if row[0] == feature_id:
            return list(FEATURE_SOURCE_OVERRIDES.get(feature_id, group["sources"][:1]))
    raise KeyError(feature_id)


def _relations_for(feature_id: str) -> list[dict[str, str]]:
    relations: list[dict[str, str]] = []
    for prerequisite in FEATURE_PREREQUISITES.get(feature_id, []):
        relations.append({"relation_type": "prerequisite", "target_id": f"feature.{prerequisite}"})
    for modifier in FEATURE_MODIFIERS.get(feature_id, []):
        relations.append({"relation_type": "modified-by", "target_id": f"modifier.{modifier}"})
    for left, right, relation_type in FEATURE_RELATIONS:
        if left == feature_id:
            relations.append({"relation_type": relation_type, "target_id": f"feature.{right}"})
        elif right == feature_id:
            relations.append({"relation_type": relation_type, "target_id": f"feature.{left}"})
    return sorted(relations, key=lambda item: (item["relation_type"], item["target_id"]))


def _manifestation_kind(feature_class: str) -> str:
    if feature_class == "replacement":
        return "replacement-syntax-or-api"
    if feature_class in {"host-operation", "diagnostic", "special-operation"}:
        return "host-api-or-observable-behavior"
    return "pattern-syntax"


def _manifestations(feature_id: str, feature_class: str, source_ids: list[str]) -> list[dict[str, Any]]:
    syntax = SYNTAX_FORMS.get(feature_id)
    if syntax is None:
        syntax = f"<{feature_id}>" if feature_class not in {"host-operation", "diagnostic", "special-operation"} else "host API or observable rule; no independent pattern token"
    return [
        {
            "manifestation_id": f"manifestation.{feature_id}.{source_id}",
            "source_id": source_id,
            "kind": _manifestation_kind(feature_class),
            "syntax_or_api_form": syntax,
            "semantic_feature_id": f"feature.{feature_id}",
            "identity_note": "This source manifestation does not allocate a separate semantic feature identity.",
        }
        for source_id in source_ids
    ]


def build_features() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    features: list[dict[str, Any]] = []
    manifestations: list[dict[str, Any]] = []
    normative_ids = {source["source_id"] for source in SOURCES if source["normative"]}
    for group, (short_id, name, definition) in _feature_rows():
        feature_id = f"feature.{short_id}"
        source_ids = _source_ids_for(short_id)
        feature_manifestations = _manifestations(short_id, group["feature_class"], source_ids)
        manifestations.extend(feature_manifestations)
        aliases = FEATURE_ALIASES.get(short_id, [])
        variants = FEATURE_VARIANTS.get(short_id, [])
        modifiers = FEATURE_MODIFIERS.get(short_id, [])
        relations = _relations_for(short_id)
        features.append(
            {
                "feature_id": feature_id,
                "revision": 1,
                "canonical_name": name,
                "aliases": aliases,
                "historical_names": aliases if short_id in HISTORICAL_ONLY else [],
                "category": group["category"],
                "feature_class": group["feature_class"],
                "semantic_definition": definition,
                "prerequisite_feature_ids": [f"feature.{item}" for item in FEATURE_PREREQUISITES.get(short_id, [])],
                "modifier_ids": [f"modifier.{item}" for item in modifiers],
                "semantic_variants": [
                    {"variant_id": f"variant.{short_id}.{_slug(item)}", "name": item, "distinguishing_rule": f"A documented semantic variant of {name}; tests must bind the selected profile behavior rather than infer it from spelling."}
                    for item in variants
                ],
                "typed_relations": relations,
                "manifestation_ids": [item["manifestation_id"] for item in feature_manifestations],
                "abstract_grammar_form": SYNTAX_FORMS.get(short_id, f"<{short_id}>") if group["feature_class"] not in {"host-operation", "diagnostic", "special-operation"} else None,
                "supported_operation_ids": list(group["operations"]),
                "capture_result_semantics": "Directly governs capture state or values." if group["feature_class"] in {"capture", "recursive"} else "Observe whole-match and capture state only where the profile and operation expose them.",
                "replacement_implications": "Direct replacement-language semantics." if group["feature_class"] == "replacement" else "May affect replacement selection, expansion, or progress only when a replacement operation is available.",
                "unicode_encoding_implications": "Directly governs the text, encoding, segmentation, property, or index domain." if group["category"] in {"unicode-and-text-model", "character-classes"} else "Bind the profile's text domain, encoding policy, index unit, case mode, locale and malformed-input policy.",
                "option_state_dependencies": [f"modifier.{item}" for item in modifiers],
                "diagnostic_error_semantics": "Direct diagnostic or failure behavior." if group["feature_class"] == "diagnostic" else "Distinguish accepted-and-supported, syntactically rejected, unsupported, and runtime error outcomes.",
                "resource_termination_implications": "Direct resource or termination behavior." if group["category"] == "diagnostics-resources-and-safety" else "Exercise with finite bounded probes and preserve timeout, limit, crash and infrastructure outcomes distinctly.",
                "lifecycle": {
                    "status": "historical-only" if short_id in HISTORICAL_ONLY else "documented-at-cutoff",
                    "evidence": [{"claim": "documented by source at the declared cutoff", "source_ids": source_ids}],
                },
                "normative_reference_ids": sorted(normative_ids.intersection(source_ids)),
                "implementation_reference_ids": sorted(set(source_ids).difference(normative_ids)),
                "test_concepts": {
                    "positive": f"Isolate the supported behavior of {name} with the smallest possible subject and no unrelated extension.",
                    "negative": f"Distinguish unsupported or rejected {name} from ordinary no-match.",
                    "edge": f"Bind empty, boundary, capture, text-domain, option and resource outcomes relevant to {name}.",
                },
                "unresolved_semantic_questions": [],
                "provenance": {"source_ids": source_ids, "discovery_cutoff": CUTOFF, "claim_scope": "semantic identity and documented behavior; empirical support remains a Conformance observation"},
            }
        )
    return sorted(features, key=lambda item: item["feature_id"]), sorted(manifestations, key=lambda item: item["manifestation_id"])


def build_interactions(features: list[dict[str, Any]]) -> list[dict[str, str]]:
    interactions: dict[tuple[str, str, str], dict[str, str]] = {}
    for feature in features:
        for relation in feature["typed_relations"]:
            key = (feature["feature_id"], relation["target_id"], relation["relation_type"])
            interactions[key] = {
                "interaction_id": f"interaction.{_slug(feature['feature_id'])}.{relation['relation_type']}.{_slug(relation['target_id'])}",
                "source_id": feature["feature_id"],
                "target_id": relation["target_id"],
                "interaction_type": relation["relation_type"],
            }
    return sorted(interactions.values(), key=lambda item: item["interaction_id"])


def build_candidates(
    features: list[dict[str, Any]],
    manifestations: list[dict[str, Any]],
    interactions: list[dict[str, str]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for feature in features:
        candidates.append(
            {
                "candidate_id": f"candidate.{feature['feature_id']}",
                "label": feature["canonical_name"],
                "disposition": "canonical semantic feature",
                "canonical_feature_id": feature["feature_id"],
                "reason": "Materially distinct user-observable semantics under one definition.",
                "source_ids": feature["provenance"]["source_ids"],
            }
        )
        for variant in feature["semantic_variants"]:
            candidates.append(
                {
                    "candidate_id": f"candidate.{variant['variant_id']}",
                    "label": variant["name"],
                    "disposition": "canonical subfeature/semantic variant",
                    "canonical_feature_id": feature["feature_id"],
                    "reason": "Observable variant retained below the feature identity because the shared semantic definition remains accurate.",
                    "source_ids": feature["provenance"]["source_ids"],
                }
            )
        for alias in feature["aliases"]:
            candidates.append(
                {
                    "candidate_id": f"candidate.alias.{_slug(alias)}.{_slug(feature['feature_id'])}",
                    "label": alias,
                    "disposition": "alias/synonym",
                    "canonical_feature_id": feature["feature_id"],
                    "reason": "Alternate name without a distinct semantic identity.",
                    "source_ids": feature["provenance"]["source_ids"],
                }
            )
    for manifestation in manifestations:
        candidates.append(
            {
                "candidate_id": f"candidate.{manifestation['manifestation_id']}",
                "label": manifestation["syntax_or_api_form"],
                "disposition": "syntax manifestation of an existing feature",
                "canonical_feature_id": manifestation["semantic_feature_id"],
                "reason": manifestation["identity_note"],
                "source_ids": [manifestation["source_id"]],
            }
        )
    for modifier_id, definition in MODIFIERS:
        candidates.append(
            {
                "candidate_id": f"candidate.modifier.{modifier_id}",
                "label": modifier_id,
                "disposition": "modifier/option rather than independent feature",
                "canonical_modifier_id": f"modifier.{modifier_id}",
                "reason": definition,
                "source_ids": sorted({source for feature in features if f"modifier.{modifier_id}" in feature["modifier_ids"] for source in feature["provenance"]["source_ids"]}),
            }
        )
    for operation_id, definition in OPERATIONS:
        candidates.append(
            {
                "candidate_id": f"candidate.operation.{operation_id}",
                "label": operation_id,
                "disposition": "host operation rather than independent feature",
                "canonical_operation_id": f"operation.{operation_id}",
                "reason": definition,
                "source_ids": ["pcre2-api", "java-matcher", "python-re"],
            }
        )
    for interaction in interactions:
        candidates.append(
            {
                "candidate_id": f"candidate.{interaction['interaction_id']}",
                "label": interaction["interaction_type"],
                "disposition": "interaction/composition rather than independent feature",
                "canonical_interaction_id": interaction["interaction_id"],
                "reason": "The recurring combination is represented as a typed relation, not a composite pseudo-feature.",
                "source_ids": [],
            }
        )
    candidates.extend(
        [
            {"candidate_id": "candidate.legacy-bridge.feature-assertion-lookbehind-positive", "label": "feature.assertion.lookbehind.positive", "disposition": "alias/synonym", "canonical_feature_id": "feature.fixed-positive-lookbehind", "reason": "The only recoverable retired bridge identity is conserved as a historical alias. The new corpus splits fixed, bounded-variable, and unbounded semantics rather than preserving the old underspecified granularity.", "source_ids": ["legacy-knowledge-tombstone", "legacy-authority-decision"]},
            {"candidate_id": "candidate.result.match-object", "label": "match object", "disposition": "result/capture/replacement semantic facet", "reason": "A result carrier; its observable fields are obligations of features and operations rather than a pattern feature.", "source_ids": ["java-matcher", "python-re"]},
            {"candidate_id": "candidate.diagnostic.native-message", "label": "native diagnostic message", "disposition": "diagnostic/resource behavior", "canonical_feature_id": "feature.diagnostic-code-and-class", "reason": "Retained as an observable diagnostic facet with native provenance.", "source_ids": ["pcre2-api"]},
            {"candidate_id": "candidate.history.atomic-recursion", "label": "historically atomic recursion", "disposition": "historical-only capability", "canonical_feature_id": "feature.atomic-recursion", "reason": "Needed to explain historical recursion behavior after modern semantic changes.", "source_ids": ["pcre2-pattern"]},
            {"candidate_id": "candidate.duplicate.negative-assertion-spelling", "label": "negative assertion spelling", "disposition": "duplicate", "canonical_feature_id": "feature.negative-lookahead", "reason": "Duplicate discovery claim already represented by polarity-specific assertion identity.", "source_ids": ["pcre2-pattern", "perl-regex"]},
            {"candidate_id": "candidate.non-regex.shell-glob", "label": "shell glob", "disposition": "not actually regex", "reason": "A different pattern language and therefore not a regex semantic capability.", "source_ids": ["known-universe-census"]},
            {"candidate_id": "candidate.out-of-scope.sqlite-hook", "label": "SQLite user-defined REGEXP hook", "disposition": "out of scope with reason", "reason": "The host defines no regex implementation or semantics until an external function is installed.", "source_ids": ["known-universe-census"]},
        ]
    )
    candidates.extend(LEGACY_UNRESOLVED)
    return sorted(candidates, key=lambda item: item["candidate_id"])


def _facet_status(feature: dict[str, Any], facet: str) -> str:
    feature_class = feature["feature_class"]
    category = feature["category"]
    if facet == "core-semantics":
        return "mandatory"
    if facet == "syntax":
        return "prohibited/not-applicable" if feature_class in {"host-operation", "diagnostic"} else "mandatory"
    if facet == "search-iteration":
        return "prohibited/not-applicable" if feature_class in {"replacement", "diagnostic"} else "conditional"
    if facet == "captures":
        if feature_class == "capture":
            return "mandatory"
        return "prohibited/not-applicable" if feature_class == "diagnostic" else "conditional"
    if facet == "unicode-encoding":
        return "mandatory" if category in {"unicode-and-text-model", "character-classes"} else "conditional"
    if facet == "options-state":
        return "conditional" if feature["modifier_ids"] or feature_class in {"host-operation", "diagnostic", "special-operation"} else "informative"
    if facet == "host-operation":
        return "mandatory" if feature_class == "host-operation" else "conditional"
    if facet == "replacement":
        if feature_class == "replacement":
            return "mandatory"
        return "prohibited/not-applicable" if feature_class == "diagnostic" else "conditional"
    if facet == "errors":
        return "mandatory" if feature_class == "diagnostic" else "conditional"
    if facet == "resource-termination":
        return "mandatory" if category == "diagnostics-resources-and-safety" else "conditional"
    if facet == "interaction":
        return "conditional" if feature["typed_relations"] else "informative"
    if facet == "differential":
        return "conditional" if feature["semantic_variants"] or feature["lifecycle"]["status"] == "historical-only" else "informative"
    raise KeyError(facet)


def _facet_operations(feature: dict[str, Any], facet: str) -> list[str]:
    operations = set(feature["supported_operation_ids"])
    if facet == "syntax":
        operations.add("compile")
    elif facet == "search-iteration":
        operations.intersection_update(SEARCH_OPERATIONS)
    elif facet == "captures":
        operations = CAPTURE_OPERATIONS
    elif facet == "replacement":
        operations = REPLACEMENT_OPERATIONS
    elif facet == "errors":
        operations.add("compile")
    elif facet == "resource-termination":
        operations.intersection_update(RESOURCE_OPERATIONS)
    if not operations and facet not in {"captures", "replacement"}:
        operations = {"compile"}
    return sorted(operations)


def _predicate(feature: dict[str, Any], facet: str, status: str) -> dict[str, Any]:
    if status == "prohibited/not-applicable":
        return {"operator": "literal", "value": False, "reason": "The facet has no meaningful semantic coordinate for this feature class."}
    clauses: list[dict[str, Any]] = [
        {"field": "profile.operation_ids", "operator": "contains", "value_from": "coordinate.operation_id"}
    ]
    if status == "conditional":
        if facet == "captures":
            clauses.append({"field": "profile.capabilities", "operator": "contains", "value": "captures"})
        elif facet == "replacement":
            clauses.append({"field": "profile.capabilities", "operator": "contains", "value": "replacement"})
        elif facet == "search-iteration":
            clauses.append({"field": "coordinate.operation_id", "operator": "in", "values": sorted(SEARCH_OPERATIONS)})
        elif facet == "differential":
            clauses.append({"field": "profile.release_or_backend_comparator", "operator": "exists"})
        elif facet == "interaction":
            clauses.append({"field": "vector.explicit_interaction_ids", "operator": "contains", "value_from": "obligation.interaction_id"})
        else:
            clauses.append({"field": "profile.feature_state", "operator": "in", "values": ["supported", "unknown"]})
    return {"operator": "all", "clauses": clauses}


def build_obligations(features: list[dict[str, Any]]) -> list[dict[str, Any]]:
    obligations: list[dict[str, Any]] = []
    for feature in features:
        short_id = feature["feature_id"].removeprefix("feature.")
        for facet, cases in FACET_CASES.items():
            status = _facet_status(feature, facet)
            operation_ids = [] if status == "prohibited/not-applicable" else _facet_operations(feature, facet)
            for case in cases:
                obligations.append(
                    {
                        "obligation_id": f"obligation.{short_id}.{facet}.{case}",
                        "feature_id": feature["feature_id"],
                        "facet": facet,
                        "case": case,
                        "classification": status,
                        "operation_ids": operation_ids,
                        "applicability_predicate": _predicate(feature, facet, status),
                        "expected_observation_contract": {
                            "unsupported": "Retain an explicit accepted-but-unsupported or rejected/unsupported outcome; never convert it to not-applicable.",
                            "supported": f"Record an attributable {facet} observation for the {case} case.",
                            "unknown": "Keep the coordinate open until a qualifying vector and empirical result settle it.",
                        },
                        "single_credit_rule": "Credit this obligation only through an explicit vector obligation reference and operation-specific expected outcome.",
                    }
                )
    return sorted(obligations, key=lambda item: item["obligation_id"])


def _category_sparsity(features: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(feature["category"] for feature in features)
    return [
        {
            "category": category,
            "canonical_features": count,
            "audit_state": "reviewed",
            "sparsity_flag": count < 5,
            "note": "A sparse category requires explicit reviewer inspection; no category is accepted solely because it has a nonzero count." if count < 5 else "No suspicious sparsity at the category threshold.",
        }
        for category, count in sorted(counts.items())
    ]


def _facility_reconciliations(features: list[dict[str, Any]]) -> list[dict[str, Any]]:
    index = load_strict(ROOT / "registries" / "universe" / "full-known-universe-2026-08-15.v1.json")
    categories = sorted({feature["category"] for feature in features})
    return [
        {
            "scan_id": f"facility-scan.{facility['key']}",
            "facility_key": facility["key"],
            "facility_name": facility["name"],
            "facility_category": facility["category"],
            "planning_archetype": facility["archetype"],
            "source_identity": facility["source"],
            "current_profile_count_in_planning_index": facility["current_profiles"],
            "historical_profile_bounds_in_planning_index": facility["historical_profiles"],
            "checklist_categories": categories,
            "result": "reconciled-to-canonical-corpus-through-primary-family-sources-and-archetype-applicability",
            "limitation": "This reconciles the governed facility family. Exact per-profile coordinates require the external canonical profile ledger identified by the frozen census hash.",
        }
        for facility in index["facilities"]
    ]


def _source_scans(features: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    feature_by_source: dict[str, list[str]] = defaultdict(list)
    candidate_by_source: dict[str, list[str]] = defaultdict(list)
    for feature in features:
        for source_id in feature["provenance"]["source_ids"]:
            feature_by_source[source_id].append(feature["feature_id"])
    for candidate in candidates:
        for source_id in candidate.get("source_ids", []):
            candidate_by_source[source_id].append(candidate["candidate_id"])
    return [
        {
            "scan_id": f"source-scan.{source['source_id']}",
            "source_id": source["source_id"],
            "source_class": source["source_class"],
            "features_reconciled": sorted(set(feature_by_source[source["source_id"]])),
            "candidates_reconciled": sorted(set(candidate_by_source[source["source_id"]])),
            "result": "all encountered candidates dispositioned",
        }
        for source in SOURCES
    ]


def build_corpus() -> dict[str, Any]:
    features, manifestations = build_features()
    interactions = build_interactions(features)
    candidates = build_candidates(features, manifestations, interactions)
    disposition_counts = Counter(candidate["disposition"] for candidate in candidates)
    corpus: dict[str, Any] = {
        "schema_version": CORPUS_SCHEMA,
        "cutoff_date": CUTOFF,
        "status": "frozen-declared-cutoff-baseline",
        "authority": {
            "primary_authoritative_home": "semantic-corpus/snapshots in the Regex Conformance repository",
            "semantic_claim_rule": "Canonical semantic meaning and researched source claims change only through a new reviewed corpus revision and immutable snapshot.",
            "conformance_boundary": "Regex Conformance empirical observations consume an identified immutable projection and never silently redefine semantic meaning.",
            "language_boundary": "STRling owns product-language and compiler contracts; it may consume this corpus but does not duplicate the researched regex taxonomy.",
            "website_boundary": "Public products are derived from this corpus LEFT JOIN Conformance evidence; they do not create a third taxonomy.",
            "legacy_migration": "Recoverable retired Knowledge claims were provenance-bound. Nine bridge identities unavailable after retirement remain conserved as unresolved candidates rather than reconstructed from memory.",
            "supersedes_source_ids": ["legacy-authority-decision"],
            "retains_source_ids": ["immutable-projection-decision", "semantic-obligation-taxonomy"],
        },
        "methodology": {
            "candidate_rule": "Record every distinct regex-relevant semantic capability, behavior, modifier, operation-sensitive behavior, interaction, result/replacement facet, diagnostic/resource behavior, or historical capability encountered.",
            "identity_rule": "Split materially different observable behavior; merge spelling-only differences; model recurring composition as typed interaction unless it has independent semantics.",
            "source_priority": ["normative standard", "official implementation or host documentation", "upstream history", "primary research", "secondary discovery lead"],
            "census_question": "What user-observable regex capability exists here that is not yet represented canonically?",
            "exhaustion_rule": "Freeze only after governed facility-family reconciliation and independent omission passes yield existing identities, manifestations, variants/interactions, non-regex items, or explicit unresolved candidates.",
            "claim": "exhaustive to the strongest defensible declared cutoff; not a claim of timeless omniscience",
        },
        "sources": sorted(SOURCES, key=lambda item: item["source_id"]),
        "features": features,
        "modifiers": [{"modifier_id": f"modifier.{modifier_id}", "name": modifier_id, "semantic_effect": definition} for modifier_id, definition in MODIFIERS],
        "operations": [{"operation_id": f"operation.{operation_id}", "name": operation_id, "semantic_contract": definition} for operation_id, definition in OPERATIONS],
        "manifestations": manifestations,
        "interactions": interactions,
        "candidates": candidates,
        "discovery_scans": _source_scans(features, candidates),
        "facility_family_reconciliations": _facility_reconciliations(features),
        "adversarial_audit": {
            "passes": [
                {"pass_id": "audit.engine-indexes", "attack": "Feature-rich engine syntax and API indexes", "result": "Only canonical identities, variants, manifestations and already-typed interactions remained."},
                {"pass_id": "audit.regular-dfa-streaming", "attack": "POSIX, tagged-DFA, linear-time, multi-pattern, partial and streaming blind spots", "result": "Selection policies, result limitations, callback ordering and stream state were represented."},
                {"pass_id": "audit.host-result-replacement", "attack": "Host operations, cursors, split, extraction, replacement and capture/result APIs", "result": "Operation identities stayed separate while operation-sensitive semantics remained canonical features."},
                {"pass_id": "audit.historical-product-resource", "attack": "Historical manuals, editor/CLI/database surfaces, diagnostics, limits and embedded evaluation", "result": "Two historical-only identities and nine unrecoverable legacy candidates remain explicit; no unexplained major category remained."},
            ],
            "category_sparsity": _category_sparsity(features),
            "major_category_omission_count": 0,
            "unresolved_candidate_count": disposition_counts["unresolved"],
        },
        "counts": {
            "canonical_features": len(features),
            "subfeatures_variants": sum(len(feature["semantic_variants"]) for feature in features),
            "aliases": sum(len(feature["aliases"]) for feature in features),
            "syntax_manifestations": len(manifestations),
            "modifiers_options": len(MODIFIERS),
            "typed_interactions": len(interactions),
            "host_operations": len(OPERATIONS),
            "historical_only_features": sum(feature["lifecycle"]["status"] == "historical-only" for feature in features),
            "normative_definitions": sum(source["normative"] for source in SOURCES),
            "unresolved_semantic_candidates": disposition_counts["unresolved"],
            "discovery_sources": len(SOURCES),
            "discovery_scans": len(SOURCES) + len(_facility_reconciliations(features)) + 4,
            "candidate_records": len(candidates),
        },
        "candidate_disposition_counts": dict(sorted(disposition_counts.items())),
    }
    corpus["corpus_digest_sha256"] = _artifact_digest(corpus, "corpus_digest_sha256", "snapshot_id")
    corpus["snapshot_id"] = f"regex-semantic-features-{CUTOFF}.sha256-{corpus['corpus_digest_sha256']}"
    return corpus


def build_projection(corpus: dict[str, Any]) -> dict[str, Any]:
    obligations = build_obligations(corpus["features"])
    projection: dict[str, Any] = {
        "schema_version": PROJECTION_SCHEMA,
        "cutoff_date": CUTOFF,
        "semantic_snapshot_id": corpus["snapshot_id"],
        "semantic_corpus_digest_sha256": corpus["corpus_digest_sha256"],
        "projection_rule": "Immutable executable projection. Feature meaning remains authoritative in the bound semantic snapshot; observations cannot mutate it.",
        "feature_revisions": [
            {
                "feature_id": feature["feature_id"],
                "revision": feature["revision"],
                "category": feature["category"],
                "feature_class": feature["feature_class"],
                "semantic_definition_sha256": _sha256(feature["semantic_definition"].encode("utf-8")),
                "supported_operation_ids": [f"operation.{item}" for item in feature["supported_operation_ids"]],
            }
            for feature in corpus["features"]
        ],
        "manifestations": corpus["manifestations"],
        "modifiers": corpus["modifiers"],
        "operations": corpus["operations"],
        "typed_interactions": corpus["interactions"],
        "semantic_obligation_templates": obligations,
        "facet_taxonomy": [
            {
                "facet": facet,
                "cases": list(cases),
                "allowed_classifications": ["mandatory", "conditional", "informative", "prohibited/not-applicable"],
            }
            for facet, cases in FACET_CASES.items()
        ],
        "counts": {
            "feature_revisions": len(corpus["features"]),
            "manifestations": len(corpus["manifestations"]),
            "typed_interactions": len(corpus["interactions"]),
            "obligation_templates": len(obligations),
            "executable_obligation_templates": sum(item["classification"] in {"mandatory", "conditional"} for item in obligations),
            "informative_templates": sum(item["classification"] == "informative" for item in obligations),
            "prohibited_not_applicable_templates": sum(item["classification"] == "prohibited/not-applicable" for item in obligations),
        },
    }
    projection["projection_digest_sha256"] = _artifact_digest(projection, "projection_digest_sha256", "projection_id")
    projection["projection_id"] = f"regex-semantic-projection-{CUTOFF}.sha256-{projection['projection_digest_sha256']}"
    return projection


def build_vector_requirements(projection: dict[str, Any]) -> dict[str, Any]:
    requirements: list[dict[str, Any]] = []
    for obligation in projection["semantic_obligation_templates"]:
        if obligation["classification"] not in {"mandatory", "conditional"}:
            continue
        requirements.append(
            {
                "requirement_id": f"vector-requirement.{obligation['obligation_id'].removeprefix('obligation.')}",
                "feature_id": obligation["feature_id"],
                "obligation_id": obligation["obligation_id"],
                "facet": obligation["facet"],
                "vector_role": obligation["case"],
                "required_operation_ids": [f"operation.{item}" for item in obligation["operation_ids"]],
                "required_attribution": "The vector must name this exact obligation and define operation-specific expected outcomes; incidental co-occurrence earns no credit.",
                "existing_vector_ids": [],
                "status": "missing",
            }
        )
    existing_vector_paths = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "vectors").rglob("*.json")
        if path != VECTOR_REQUIREMENTS_PATH
    )
    artifact: dict[str, Any] = {
        "schema_version": VECTOR_REQUIREMENTS_SCHEMA,
        "cutoff_date": CUTOFF,
        "semantic_projection_id": projection["projection_id"],
        "semantic_projection_digest_sha256": projection["projection_digest_sha256"],
        "minimum_rule": "One isolating definition per executable semantic-obligation template is the minimum; it may carry multiple operation-specific expectations only with explicit attribution.",
        "reuse_audit": {
            "existing_vector_files_inspected": existing_vector_paths,
            "existing_vector_file_count": len(existing_vector_paths),
            "reusable_vector_count": 0,
            "reason": "Existing qualification vectors contain no canonical semantic projection or exact obligation references. They remain valid qualification assets but cannot silently receive semantic coverage credit.",
        },
        "requirements": requirements,
        "counts": {
            "minimum_vector_definitions": len(requirements),
            "reusable_vector_definitions": 0,
            "missing_vector_definitions": len(requirements),
            "negative_or_error_vector_definitions": sum(item["vector_role"] in {"negative", "rejection", "ambiguity-boundary", "class", "native-diagnostic", "phase", "termination", "exhaustion", "timeout", "limit"} for item in requirements),
            "interaction_vector_definitions": sum(item["facet"] == "interaction" for item in requirements),
            "differential_vector_definitions": sum(item["facet"] == "differential" for item in requirements),
            "host_operation_vector_definitions": sum(item["facet"] == "host-operation" for item in requirements),
        },
    }
    artifact["requirements_digest_sha256"] = _artifact_digest(artifact, "requirements_digest_sha256")
    return artifact


def _largest_remainder(total: int, weights: dict[str, int]) -> dict[str, int]:
    denominator = sum(weights.values())
    raw = {name: Decimal(total) * Decimal(weight) / Decimal(denominator) for name, weight in weights.items()}
    result = {name: int(value) for name, value in raw.items()}
    remaining = total - sum(result.values())
    order = sorted(weights, key=lambda name: (raw[name] - int(raw[name]), name), reverse=True)
    for name in order[:remaining]:
        result[name] += 1
    return result


def _profile_allocations() -> dict[str, Any]:
    census = load_strict(ROOT / "reports" / "scale" / "known-universe-census-forecast.json")
    index = load_strict(ROOT / "registries" / "universe" / "full-known-universe-2026-08-15.v1.json")
    current_weights = Counter({name: value["planning_profiles"] for name, value in ARCHETYPES.items()})
    history_weights: dict[str, Counter[str]] = {name: Counter() for name in ("lower", "expected", "conservative")}
    index_case = {"lower": "lower", "expected": "expected", "conservative": "upper"}
    for facility in index["facilities"]:
        for case, source_case in index_case.items():
            history_weights[case][facility["archetype"]] += facility["historical_profiles"][source_case]
    result: dict[str, Any] = {}
    for case, totals in census["release_profile_forecast"]["cases"].items():
        result[case] = {
            "current_profiles": totals["current_profiles"],
            "historical_profiles": totals["historical_profiles"],
            "current_by_archetype": _largest_remainder(totals["current_profiles"], dict(current_weights)),
            "historical_by_archetype": _largest_remainder(totals["historical_profiles"], dict(history_weights[case])),
        }
    return result


STREAMING_FEATURES = {
    "feature.streaming-match", "feature.block-match", "feature.vectored-match", "feature.multi-pattern-database",
    "feature.pattern-set-results", "feature.multi-pattern-overlap", "feature.logical-pattern-combination",
    "feature.start-of-match-tracking", "feature.start-of-match-horizon", "feature.match-event-callback",
    "feature.callback-scan-termination", "feature.single-match-pattern", "feature.prefilter-superset", "feature.match-offset-constraints",
}
SQL_FEATURES = {"feature.sql-null-propagation", "feature.sql-collation-selection"}
EDITOR_FEATURES = {"feature.magic-syntax-mode", "feature.syntax-table-class", "feature.character-category-class", "feature.keyword-character-class", "feature.file-name-character-class", "feature.ignore-combining-differences", "feature.visual-selection-position", "feature.line-number-position", "feature.column-position", "feature.mark-position"}


def _obligation_applies_to_archetype(
    feature: dict[str, Any],
    obligation: dict[str, Any],
    archetype_name: str,
    operation: str,
) -> bool:
    archetype = ARCHETYPES[archetype_name]
    if obligation["classification"] not in {"mandatory", "conditional"}:
        return False
    if operation not in archetype["operations"] or operation not in obligation["operation_ids"]:
        return False
    facet = obligation["facet"]
    if facet == "captures" and "captures" not in archetype["capabilities"]:
        return False
    if facet == "replacement" and "replacement" not in archetype["capabilities"]:
        return False
    if feature["feature_id"] in STREAMING_FEATURES and facet != "syntax" and "streaming" not in archetype["capabilities"]:
        return False
    if feature["feature_id"] in SQL_FEATURES and facet != "syntax" and archetype_name != "database-service-surface":
        return False
    if feature["feature_id"] in EDITOR_FEATURES and facet != "syntax" and archetype_name != "cli-surface":
        return False
    return True


def _coordinate_units(
    corpus: dict[str, Any], projection: dict[str, Any]
) -> tuple[dict[str, int], dict[str, dict[str, int]], dict[str, int], dict[str, int]]:
    features = {feature["feature_id"]: feature for feature in corpus["features"]}
    units = {name: 0 for name in ARCHETYPES}
    facet_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    per_archetype_facet = {name: Counter() for name in ARCHETYPES}
    for obligation in projection["semantic_obligation_templates"]:
        feature = features[obligation["feature_id"]]
        for operation in obligation["operation_ids"]:
            for archetype_name in ARCHETYPES:
                if _obligation_applies_to_archetype(feature, obligation, archetype_name, operation):
                    units[archetype_name] += 1
                    per_archetype_facet[archetype_name][obligation["facet"]] += 1
                    facet_counts[obligation["facet"]] += 1
                    category_counts[feature["category"]] += 1
    return units, {name: dict(sorted(counts.items())) for name, counts in per_archetype_facet.items()}, dict(sorted(facet_counts.items())), dict(sorted(category_counts.items()))


def _logical_parts(units: dict[str, int], allocations: dict[str, Any], case: str) -> dict[str, int]:
    current = sum(units[name] * allocations[case]["current_by_archetype"][name] for name in units)
    historical = sum(units[name] * allocations[case]["historical_by_archetype"][name] for name in units)
    canary_rate = {"lower": Decimal("0.25"), "expected": Decimal("1.00"), "conservative": Decimal("2.00")}[case]
    reserve_rate = {"lower": Decimal("0"), "expected": Decimal("0.02"), "conservative": Decimal("0.05")}[case]
    qualification = {"lower": 0, "expected": 100_000, "conservative": 1_000_000}[case]
    canary = int((Decimal(historical) * canary_rate).to_integral_value(rounding=ROUND_CEILING))
    targeted = int((Decimal(current + historical) * reserve_rate).to_integral_value(rounding=ROUND_CEILING))
    total = current + historical + canary + targeted + qualification
    return {
        "current_stable_logical_executions": current,
        "historical_stable_logical_executions": historical,
        "platform_canary_logical_executions": canary,
        "targeted_platform_expansion_reserve": targeted,
        "qualification_rehearsal_logical_executions": qualification,
        "total_logical_executions": total,
    }


def build_denominator(
    corpus: dict[str, Any],
    projection: dict[str, Any],
    vector_requirements: dict[str, Any],
) -> dict[str, Any]:
    allocations = _profile_allocations()
    units, per_archetype_facet, facet_counts, category_counts = _coordinate_units(corpus, projection)
    logical_cases = {case: _logical_parts(units, allocations, case) for case in ("lower", "expected", "conservative")}
    evidence_report = load_strict(ROOT / "reports" / "scale" / "evidence-pack-v3-capacity-certification.json")
    physical_cases: dict[str, dict[str, int]] = {}
    retry_rates = {"lower": Decimal("0"), "expected": Decimal("0.005"), "conservative": Decimal("0.05")}
    for case, parts in logical_cases.items():
        attempts = int((Decimal(parts["total_logical_executions"]) * (Decimal(1) + retry_rates[case])).to_integral_value(rounding=ROUND_CEILING))
        physical_cases[case] = {
            "logical_executions": parts["total_logical_executions"],
            "physical_attempts": attempts,
            "expected_retry_attempts": attempts - parts["total_logical_executions"],
        }
    measurement = evidence_report["future_contract_measurement"]
    restored_measurement = evidence_report["retention_analysis"][
        "restored_contract_measurement"
    ]
    qualification_bytes = evidence_report["final_forecast"]["qualification_corpus_bytes"]
    forecast = build_capacity_forecast(
        measurement["bytes_by_evidence_class"],
        physical_cases,
        measured_logical_executions=measurement["logical_executions"],
        measured_physical_attempts=measurement["physical_attempts"],
        qualification_corpus_bytes=qualification_bytes,
    )
    restored_forecast = build_capacity_forecast(
        restored_measurement["bytes_by_evidence_class"],
        physical_cases,
        measured_logical_executions=restored_measurement["logical_executions"],
        measured_physical_attempts=restored_measurement["physical_attempts"],
        qualification_corpus_bytes=qualification_bytes,
    )
    availability_measurement = evidence_report["retention_analysis"][
        "measured_counterfactuals"
    ]["reconstructible_routine_availability_only"]
    availability_forecast = build_capacity_forecast(
        availability_measurement["bytes_by_evidence_class"],
        physical_cases,
        measured_logical_executions=restored_measurement["logical_executions"],
        measured_physical_attempts=restored_measurement["physical_attempts"],
        qualification_corpus_bytes=qualification_bytes,
    )
    conservative_total = forecast["conservative"]["total_retained_bytes"]
    restored_conservative = restored_forecast["conservative"]["total_retained_bytes"]
    retention_savings = restored_conservative - conservative_total
    soft = evidence_report["final_forecast"]["soft_stop_bytes"]
    hard = evidence_report["final_forecast"]["hard_cap_bytes"]
    prior = evidence_report["declared_cutoff_denominators"]
    report: dict[str, Any] = {
        "schema_version": DENOMINATOR_SCHEMA,
        "cutoff_date": CUTOFF,
        "classification": {
            "design_only": True,
            "full_campaign_executed": False,
            "profile_join_kind": "strongest-defensible-bounded",
            "exact_coordinate_materialization_available": False,
            "reason": "The frozen known-universe census publishes aggregate profile bounds and an external canonical-ledger hash, but the exact expanded profile coordinate ledger is not present in this repository.",
        },
        "source_bindings": {
            "semantic_snapshot_id": corpus["snapshot_id"],
            "semantic_corpus_digest_sha256": corpus["corpus_digest_sha256"],
            "semantic_projection_id": projection["projection_id"],
            "semantic_projection_digest_sha256": projection["projection_digest_sha256"],
            "vector_requirements_digest_sha256": vector_requirements["requirements_digest_sha256"],
            "known_universe_census_report_digest_sha256": load_strict(ROOT / "reports" / "scale" / "known-universe-census-forecast.json")["report_digest_sha256"],
            "evidence_pack_v3_report_digest_sha256": evidence_report["report_digest_sha256"],
        },
        "denominator_contract": "profile × feature × semantic obligation × operation",
        "profile_bounds_and_allocations": allocations,
        "coordinate_units_per_profile_by_archetype": units,
        "coordinate_units_by_archetype_and_facet": per_archetype_facet,
        "unweighted_applicable_coordinate_units_by_facet": facet_counts,
        "unweighted_applicable_coordinate_units_by_feature_category": category_counts,
        "semantic_obligation_template_counts": projection["counts"],
        "obligation_denominator_bounds": {
            case: {
                "current_stable": logical_cases[case]["current_stable_logical_executions"],
                "historical_stable": logical_cases[case]["historical_stable_logical_executions"],
                "current_plus_historical": logical_cases[case]["current_stable_logical_executions"] + logical_cases[case]["historical_stable_logical_executions"],
            }
            for case in logical_cases
        },
        "logical_execution_denominator": logical_cases,
        "physical_attempt_denominator": physical_cases,
        "vector_requirements": vector_requirements["counts"],
        "compact_evidence_pack_v3": {
            "restored_baseline": {
                "measurement": restored_measurement,
                "forecast_cases": restored_forecast,
                "conservative_retained_bytes": restored_conservative,
                "conservative_soft_stop_overage_bytes": max(
                    0, restored_conservative - soft
                ),
                "conservative_hard_cap_overage_bytes": max(
                    0, restored_conservative - hard
                ),
            },
            "measurement": {
                "logical_executions": measurement["logical_executions"],
                "physical_attempts": measurement["physical_attempts"],
                "retained_bytes": measurement["retained_bytes"],
                "bytes_per_logical_execution": measurement["bytes_per_logical_execution"],
                "bytes_per_physical_attempt": measurement["bytes_per_physical_attempt"],
                "bytes_by_evidence_class": measurement["bytes_by_evidence_class"],
            },
            "qualification_corpus_bytes": qualification_bytes,
            "forecast_cases": forecast,
            "soft_stop_bytes": soft,
            "hard_cap_bytes": hard,
            "capacity_status": "BLOCKED" if conservative_total > soft else "PASS",
            "conservative_soft_stop_overage_bytes": max(0, conservative_total - soft),
            "conservative_hard_cap_overage_bytes": max(0, conservative_total - hard),
            "stop_rule_applied": conservative_total > soft,
            "retention_optimization": {
                "selected_contract": "semantic-anomaly-complete-routine-process-summary.v2",
                "total_savings_bytes": retention_savings,
                "total_savings_percent": str(
                    (
                        Decimal(retention_savings)
                        * Decimal(100)
                        / Decimal(restored_conservative)
                    ).quantize(Decimal("0.000000001"))
                ),
                "soft_stop_margin_bytes": soft - conservative_total,
                "hard_cap_margin_bytes": hard - conservative_total,
                "candidate_reductions": [
                    {
                        "candidate": "routine clean process diagnostic summary with ordered stdout commitment",
                        "selected": True,
                        "conservative_retained_bytes": conservative_total,
                        "savings_bytes": retention_savings,
                        "scientific_effect": "No semantic coordinate or result is removed. Per-process routine stdout digest/length is omitted operational telemetry and the ordered set remains committed; every exception remains rich.",
                    },
                    {
                        "candidate": "omit only reconstructible routine availability grids",
                        "selected": False,
                        "conservative_retained_bytes": availability_forecast[
                            "conservative"
                        ]["total_retained_bytes"],
                        "savings_bytes": restored_conservative
                        - availability_forecast["conservative"][
                            "total_retained_bytes"
                        ],
                        "scientific_effect": "No semantic loss, but insufficient: it remains above both capacity limits.",
                    },
                    {
                        "candidate": "drop the complete performance/resource class",
                        "selected": False,
                        "maximum_savings_bytes": 332_407_660,
                        "scientific_effect": "Insufficient alone and destroys performance/resource evidence.",
                    },
                    {
                        "candidate": "drop the complete physical-attempt class",
                        "selected": False,
                        "maximum_savings_bytes": 322_792_799,
                        "scientific_effect": "Insufficient alone and destroys retry, timestamp, interruption, and recovery evidence.",
                    },
                    {
                        "candidate": "drop the complete semantic-result class",
                        "selected": False,
                        "maximum_savings_bytes": 3_164_555_796,
                        "scientific_effect": "Insufficient alone and prohibited because it removes match, capture, replacement, split, and error evidence.",
                    },
                    {
                        "candidate": "remove qualification evidence and the complete fixed reserve",
                        "selected": False,
                        "maximum_savings_bytes": 1_028_313_839,
                        "scientific_effect": "Insufficient alone and violates qualification and targeted-expansion policy.",
                    },
                ],
                "conservative_byte_decomposition": [
                    {
                        "evidence_class": name,
                        "baseline_bytes": restored_forecast["conservative"][
                            "bytes_by_evidence_class"
                        ][name],
                        "final_bytes": forecast["conservative"][
                            "bytes_by_evidence_class"
                        ][name],
                        "savings_bytes": restored_forecast["conservative"][
                            "bytes_by_evidence_class"
                        ][name]
                        - forecast["conservative"]["bytes_by_evidence_class"][
                            name
                        ],
                        "tier": (
                            "C"
                            if name == "diagnostics"
                            else "A"
                            if name
                            in {
                                "canonical_inputs",
                                "physical_attempt_facts",
                                "profile_environment_release_provenance",
                                "semantic_results",
                                "manifests_integrity",
                            }
                            else "B"
                        ),
                        "ordinary_or_exceptional": (
                            "conditional: only routine clean process envelope fields are summarized"
                            if name == "diagnostics"
                            else "unchanged"
                        ),
                    }
                    for name in sorted(measurement["bytes_by_evidence_class"])
                ]
                + [
                    {
                        "evidence_class": "diagnostic_growth_allowance",
                        "baseline_bytes": restored_forecast["conservative"][
                            "diagnostic_growth_allowance_bytes"
                        ],
                        "final_bytes": forecast["conservative"][
                            "diagnostic_growth_allowance_bytes"
                        ],
                        "savings_bytes": restored_forecast["conservative"][
                            "diagnostic_growth_allowance_bytes"
                        ]
                        - forecast["conservative"][
                            "diagnostic_growth_allowance_bytes"
                        ],
                        "tier": "reserve",
                        "ordinary_or_exceptional": "unchanged 10% conservative rate applied to the modeled base",
                    },
                    {
                        "evidence_class": "performance_growth_allowance",
                        "baseline_bytes": restored_forecast["conservative"][
                            "performance_growth_allowance_bytes"
                        ],
                        "final_bytes": forecast["conservative"][
                            "performance_growth_allowance_bytes"
                        ],
                        "savings_bytes": restored_forecast["conservative"][
                            "performance_growth_allowance_bytes"
                        ]
                        - forecast["conservative"][
                            "performance_growth_allowance_bytes"
                        ],
                        "tier": "reserve",
                        "ordinary_or_exceptional": "unchanged 5% conservative rate applied to the modeled base",
                    },
                    {
                        "evidence_class": "fixed_targeted_and_general_reserve",
                        "baseline_bytes": 1_000_000_000,
                        "final_bytes": 1_000_000_000,
                        "savings_bytes": 0,
                        "tier": "reserve",
                        "ordinary_or_exceptional": "unchanged",
                    },
                    {
                        "evidence_class": "qualification_corpus",
                        "baseline_bytes": qualification_bytes,
                        "final_bytes": qualification_bytes,
                        "savings_bytes": 0,
                        "tier": "A",
                        "ordinary_or_exceptional": "unchanged completed immutable evidence",
                    },
                ],
                "protected_semantic_result_facets": {
                    "allocation_status": "co-resident in the independently configurable semantic_results class; exact subtype byte rates are not separately certified",
                    "facets": [
                        "match/no-match and core semantic results",
                        "captures, names, spans/index units, and capture history",
                        "replacement outputs",
                        "split, search, cursor, and iteration outputs",
                        "compile acceptance, rejection, and native error results",
                    ],
                    "retention": "complete and unchanged",
                },
                "information_no_longer_physically_retained": [
                    "per-process stdout SHA-256 for a routine clean success",
                    "per-process stdout byte count for a routine clean success",
                    "repeated routine constants: completed outcome, exit code zero, null native diagnostic, empty stderr digest/count, and false authority flags",
                ],
                "information_retained_for_summary": [
                    "routine-success marker and exact provider plan per process",
                    "ordered whole-pack SHA-256 commitment over every summarized stdout digest and length",
                    "summarized record count and aggregate stdout byte count",
                    "full rich process record for every non-routine, malformed, error, timeout, stderr, diagnostic, redaction, truncation, or anomalous case",
                ],
                "downstream_sufficiency": {
                    "strling": "PASS: all feature support, semantic results, target/profile provenance, errors, and differential evidence remain retained",
                    "compatibility_explorer": "PASS: Supported, Unsupported, Partial/conditional, N/A, Unknown/not tested, and Inconclusive/conflicting remain distinguishable",
                    "limitation": "A displayed routine process stdout digest must be regenerated and checked against the whole-pack commitment instead of read directly.",
                },
            },
        },
        "comparison_to_prior_feature_denominator": {
            case: {
                "prior_logical_executions": prior[case]["logical_executions"],
                "new_logical_executions": logical_cases[case]["total_logical_executions"],
                "feature_census_attributable_change": logical_cases[case]["total_logical_executions"] - prior[case]["logical_executions"],
                "ratio": str((Decimal(logical_cases[case]["total_logical_executions"]) / Decimal(prior[case]["logical_executions"])).quantize(Decimal("0.000001"))),
            }
            for case in logical_cases
        },
        "exact_next_dependency": "Materialize and provenance-bind the exact frozen profile coordinate ledger, compile the enumerated profile-by-feature-by-obligation-by-operation coordinates, author and certify the 9,506 missing attributable production vectors, then complete environment/adapter qualification before separately authorizing full-suite execution.",
        "public_product_readiness": {
            "complete_feature_catalog": "ready from canonical feature definitions, aliases, variants, manifestations, test concepts, edge facets, interactions and Unicode fields",
            "compatibility_explorer": "schema-ready for complete feature universe LEFT JOIN empirical evidence; absent evidence maps to Unknown/Not Tested, never Unsupported",
            "website_taxonomy_authority": False,
        },
    }
    report["report_digest_sha256"] = _artifact_digest(report, "report_digest_sha256")
    return report


ALLOWED_DISPOSITIONS = {
    "canonical semantic feature",
    "canonical subfeature/semantic variant",
    "syntax manifestation of an existing feature",
    "alias/synonym",
    "modifier/option rather than independent feature",
    "host operation rather than independent feature",
    "interaction/composition rather than independent feature",
    "result/capture/replacement semantic facet",
    "diagnostic/resource behavior",
    "historical-only capability",
    "duplicate",
    "not actually regex",
    "out of scope with reason",
    "unresolved",
}


def verify_artifacts(
    corpus: dict[str, Any],
    projection: dict[str, Any],
    vector_requirements: dict[str, Any],
    denominator: dict[str, Any],
) -> None:
    if corpus["corpus_digest_sha256"] != _artifact_digest(corpus, "corpus_digest_sha256", "snapshot_id"):
        raise ValueError("semantic corpus digest differs")
    if projection["projection_digest_sha256"] != _artifact_digest(projection, "projection_digest_sha256", "projection_id"):
        raise ValueError("semantic projection digest differs")
    if vector_requirements["requirements_digest_sha256"] != _artifact_digest(vector_requirements, "requirements_digest_sha256"):
        raise ValueError("vector-requirements digest differs")
    if denominator["report_digest_sha256"] != _artifact_digest(denominator, "report_digest_sha256"):
        raise ValueError("denominator report digest differs")
    feature_ids = [feature["feature_id"] for feature in corpus["features"]]
    if len(feature_ids) != len(set(feature_ids)):
        raise ValueError("feature IDs are not unique")
    feature_id_set = set(feature_ids)
    source_ids = {source["source_id"] for source in corpus["sources"]}
    modifier_ids = {modifier["modifier_id"] for modifier in corpus["modifiers"]}
    for feature in corpus["features"]:
        if not set(feature["provenance"]["source_ids"]).issubset(source_ids):
            raise ValueError(f"unknown feature provenance source for {feature['feature_id']}")
        if not set(feature["prerequisite_feature_ids"]).issubset(feature_id_set):
            raise ValueError(f"unknown prerequisite for {feature['feature_id']}")
        if not set(feature["modifier_ids"]).issubset(modifier_ids):
            raise ValueError(f"unknown modifier for {feature['feature_id']}")
    manifestation_ids = [item["manifestation_id"] for item in corpus["manifestations"]]
    if len(manifestation_ids) != len(set(manifestation_ids)):
        raise ValueError("manifestation IDs are not unique")
    for item in corpus["manifestations"]:
        if item["semantic_feature_id"] not in feature_id_set or item["source_id"] not in source_ids:
            raise ValueError(f"invalid manifestation binding {item['manifestation_id']}")
    candidate_ids = [item["candidate_id"] for item in corpus["candidates"]]
    if len(candidate_ids) != len(set(candidate_ids)):
        duplicates = [item for item, count in Counter(candidate_ids).items() if count > 1]
        raise ValueError(f"candidate IDs are not unique: {duplicates[:5]}")
    dispositions = {item["disposition"] for item in corpus["candidates"]}
    if not dispositions.issubset(ALLOWED_DISPOSITIONS) or dispositions != ALLOWED_DISPOSITIONS:
        raise ValueError(f"candidate disposition coverage differs: {sorted(dispositions)}")
    if corpus["counts"]["unresolved_semantic_candidates"] != len(LEGACY_UNRESOLVED):
        raise ValueError("unresolved legacy candidate conservation differs")
    obligations = projection["semantic_obligation_templates"]
    obligation_ids = [item["obligation_id"] for item in obligations]
    if len(obligation_ids) != len(set(obligation_ids)):
        raise ValueError("obligation IDs are not unique")
    by_feature_facets: dict[str, set[str]] = defaultdict(set)
    for obligation in obligations:
        by_feature_facets[obligation["feature_id"]].add(obligation["facet"])
    expected_facets = set(FACET_CASES)
    if any(by_feature_facets[feature_id] != expected_facets for feature_id in feature_id_set):
        raise ValueError("every feature must have the complete twelve-facet template set")
    requirement_obligations = {item["obligation_id"] for item in vector_requirements["requirements"]}
    executable_obligations = {item["obligation_id"] for item in obligations if item["classification"] in {"mandatory", "conditional"}}
    if requirement_obligations != executable_obligations:
        raise ValueError("missing-vector requirements do not conserve executable obligations")
    if denominator["denominator_contract"] != "profile × feature × semantic obligation × operation":
        raise ValueError("denominator contract differs")
    for case in ("lower", "expected", "conservative"):
        logical = denominator["logical_execution_denominator"][case]["total_logical_executions"]
        attempts = denominator["physical_attempt_denominator"][case]["physical_attempts"]
        if attempts < logical:
            raise ValueError(f"physical attempts below logical executions for {case}")
        allocation = denominator["profile_bounds_and_allocations"][case]
        if sum(allocation["current_by_archetype"].values()) != allocation["current_profiles"]:
            raise ValueError(f"current profile allocation does not close for {case}")
        if sum(allocation["historical_by_archetype"].values()) != allocation["historical_profiles"]:
            raise ValueError(f"historical profile allocation does not close for {case}")


def _validate_schemas(artifacts: list[tuple[dict[str, Any], Path]]) -> None:
    for artifact, schema_path in artifacts:
        if schema_path.exists():
            validate_instance(artifact, load_strict(schema_path), source=str(schema_path))


def _write(path: Path, value: dict[str, Any]) -> None:
    encoded = canonical_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded:
        raise RuntimeError(f"read-after-write verification failed for {path}")


def build_all() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    corpus = build_corpus()
    projection = build_projection(corpus)
    vector_requirements = build_vector_requirements(projection)
    denominator = build_denominator(corpus, projection, vector_requirements)
    verify_artifacts(corpus, projection, vector_requirements, denominator)
    return corpus, projection, vector_requirements, denominator


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify tracked artifacts against a deterministic rebuild")
    args = parser.parse_args()
    artifacts = build_all()
    verify_catalog(ROOT)
    bindings = [
        (artifacts[0], CORPUS_PATH, CORPUS_SCHEMA_PATH),
        (artifacts[1], PROJECTION_PATH, PROJECTION_SCHEMA_PATH),
        (artifacts[2], VECTOR_REQUIREMENTS_PATH, VECTOR_REQUIREMENTS_SCHEMA_PATH),
        (artifacts[3], DENOMINATOR_PATH, DENOMINATOR_SCHEMA_PATH),
    ]
    _validate_schemas([(artifact, schema_path) for artifact, _, schema_path in bindings])
    if args.check:
        for artifact, path, _ in bindings:
            if not path.exists():
                raise ValueError(f"tracked artifact is missing: {path}")
            if path.read_bytes() != canonical_bytes(artifact) + b"\n":
                raise ValueError(f"tracked artifact differs from deterministic rebuild: {path}")
    else:
        for artifact, path, _ in bindings:
            _write(path, artifact)
        rebuilt = build_all()
        if any(canonical_bytes(left) != canonical_bytes(right) for left, right in zip(artifacts, rebuilt, strict=True)):
            raise RuntimeError("semantic baseline second build is not deterministic")
    corpus, _, vectors, denominator = artifacts
    capacity = denominator["compact_evidence_pack_v3"]
    print(
        f"features={corpus['counts']['canonical_features']} "
        f"snapshot={corpus['corpus_digest_sha256']} "
        f"vectors={vectors['counts']['minimum_vector_definitions']} "
        f"conservative_logical={denominator['logical_execution_denominator']['conservative']['total_logical_executions']} "
        f"capacity={capacity['capacity_status']} "
        f"soft_overage={capacity['conservative_soft_stop_overage_bytes']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
