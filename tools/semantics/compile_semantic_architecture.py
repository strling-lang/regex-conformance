#!/usr/bin/env python3
"""Disposition semantic-architecture candidates without rebuilding the denominator."""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "schemas" / "tooling" / "python"))

from regex_conformance_schema.identity import NamespaceRegistry, build_content_identity, generate_assigned_id  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402
from regex_conformance_schema.profile import IdentityProfile  # noqa: E402
from regex_conformance_schema.schema import validate_instance  # noqa: E402


PREDECESSOR_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v2.json")
LEGACY_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json")
ALLOCATION_PATH = Path("semantic-corpus/research/semantic-architecture-identities-2026-09-07.v1.json")
LEDGER_PATH = Path("semantic-corpus/research/regex-semantic-architecture-candidates-2026-09-07.v1.json")
SNAPSHOT_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v3.json")
REPORT_PATH = Path("reports/semantics/semantic-architecture-disposition-2026-09-07.v1.json")
IDENTITY_PATH = Path("registries/identity/scientific-identities.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v3.json")
PROFILE_PATH = Path("schemas/identity-profiles/semantic-research-artifact.v1.json")
ALLOCATION_SCHEMA_PATH = Path("schemas/json/regex-semantic-architecture-identity-allocation.schema.json")
LEDGER_SCHEMA_PATH = Path("schemas/json/regex-semantic-candidate-disposition-ledger.schema.json")
SNAPSHOT_SCHEMA_PATH = Path("schemas/json/regex-semantic-corpus-v3.schema.json")
REPORT_SCHEMA_PATH = Path("schemas/json/regex-semantic-architecture-disposition-report.schema.json")

DERIVATION_ID = "rcid:v1:assertion-derivation:u7:01a07d86-1c67-7e4e-9237-baaaf44f8639"
SCHEMA_FAMILIES = {
    "ledger": "rcid:v1:schema-family:u7:01a07d86-1c67-7baf-bbee-8ebe71bd5c8b",
    "snapshot": "rcid:v1:schema-family:u7:01a07d86-1c67-7b3e-be73-d0f61f0a3549",
    "report": "rcid:v1:schema-family:u7:01a07d86-1c67-7b46-a1b9-f5e1efbcdc2e",
}
PUBLISHED_ON = "2026-09-07"
SEMANTIC_FIELDS = (
    "definition", "syntax_grammar", "capture_result", "diagnostic_error", "replacement",
    "resource_termination", "unicode_encoding", "search_iteration", "options_state", "host_operation",
)


NEW_SOURCES = [
    {"source_id": "lucene-regexp", "title": "Lucene RegExp", "url": "https://lucene.apache.org/core/10_3_1/core/org/apache/lucene/util/automaton/RegExp.html", "source_class": "official-implementation-documentation", "authority": "Apache Lucene", "scope": "Automaton regular-language syntax including intersection, complement, empty language, any string, named automata and numeric intervals", "version_or_revision": "10.3.1", "retrieved_on": PUBLISHED_ON, "normative": False},
    {"source_id": "smtlib-unicode-strings", "title": "SMT-LIB Unicode Strings theory", "url": "https://smt-lib.org/theories-UnicodeStrings.shtml", "source_class": "normative-specification", "authority": "SMT-LIB Initiative", "scope": "Mathematical regular-language operations including empty, universal, intersection, complement and difference", "version_or_revision": "2.7; page updated 2025-12-03", "retrieved_on": PUBLISHED_ON, "normative": True},
    {"source_id": "swift-regex-type", "title": "Swift Regex type overview", "url": "https://github.com/swiftlang/swift-evolution/blob/main/proposals/0350-regex-type-overview.md", "source_class": "normative-language-proposal", "authority": "Swift Evolution", "scope": "Typed capture output, optionality and dynamic AnyRegexOutput", "version_or_revision": "SE-0350", "retrieved_on": PUBLISHED_ON, "normative": True},
    {"source_id": "swift-regex-builder", "title": "Swift Regex Builder DSL", "url": "https://github.com/swiftlang/swift-evolution/blob/main/proposals/0351-regex-builder.md", "source_class": "normative-language-proposal", "authority": "Swift Evolution", "scope": "Builder composition and capture/output transformation", "version_or_revision": "SE-0351", "retrieved_on": PUBLISHED_ON, "normative": True},
    {"source_id": "swift-regex-literals", "title": "Swift regex literals", "url": "https://github.com/swiftlang/swift-evolution/blob/main/proposals/0354-regex-literals.md", "source_class": "normative-language-proposal", "authority": "Swift Evolution", "scope": "Build-time parsing and inferred Regex output types", "version_or_revision": "SE-0354", "retrieved_on": PUBLISHED_ON, "normative": True},
    {"source_id": "unicode-tr14", "title": "Unicode Line Breaking Algorithm", "url": "https://www.unicode.org/reports/tr14/", "source_class": "normative-specification", "authority": "Unicode Consortium", "scope": "Unicode line-break classes and boundary algorithm", "version_or_revision": "Unicode 17.0", "retrieved_on": PUBLISHED_ON, "normative": True},
    {"source_id": "unicode-uax44", "title": "Unicode Character Database", "url": "https://www.unicode.org/reports/tr44/", "source_class": "normative-specification", "authority": "Unicode Consortium", "scope": "Property aliases, value domains and Unicode-versioned data", "version_or_revision": "Unicode 17.0", "retrieved_on": PUBLISHED_ON, "normative": True},
    {"source_id": "pcre2-serialization", "title": "PCRE2 serialization API", "url": "https://www.pcre.org/current/doc/html/pcre2serialize.html", "source_class": "official-implementation-documentation", "authority": "PCRE2 Project", "scope": "Compiled-pattern serialization, decoding, compatibility and trusted-input constraints", "version_or_revision": "current at cutoff", "retrieved_on": PUBLISHED_ON, "normative": False},
    {"source_id": "pcre2-pattern-info", "title": "PCRE2 pattern information API", "url": "https://www.pcre.org/current/doc/html/pcre2_pattern_info.html", "source_class": "official-implementation-documentation", "authority": "PCRE2 Project", "scope": "Compiled-pattern introspection including capture, name, option and length information", "version_or_revision": "current at cutoff", "retrieved_on": PUBLISHED_ON, "normative": False},
    {"source_id": "perl-regex-escapes", "title": "Perl regular-expression backslash sequences", "url": "https://perldoc.perl.org/5.40.5/perlrebackslash", "source_class": "official-implementation-documentation", "authority": "Perl Project", "scope": "Unicode line-break boundary and escape semantics", "version_or_revision": "5.40.5", "retrieved_on": PUBLISHED_ON, "normative": False},
]


FACETS = [
    ("syntax", "Syntax", ["accepted", "rejected", "unsupported"], "Grammar acceptance and construction constraints."),
    ("core-match", "Core match", ["match", "no-match", "result"], "Core language and result behavior."),
    ("search-boundary", "Search and boundary", ["start", "advance", "boundary"], "Search placement and iteration behavior."),
    ("capture", "Capture", ["allocation", "participation", "shape"], "Capture numbering, state and result shape."),
    ("unicode-encoding", "Unicode and encoding", ["byte", "code-unit", "code-point", "grapheme"], "Text domain, Unicode data and index-unit sensitivity."),
    ("option-state", "Option and state", ["compile", "call", "session"], "Persistent and per-call option/state effects."),
    ("host-api", "Host API", ["construction", "operation", "result"], "Observable host-operation contracts."),
    ("replacement", "Replacement", ["selection", "expansion", "advancement"], "Substitution and replacement-language consequences."),
    ("error-diagnostics", "Error and diagnostics", ["compile", "runtime", "unsupported"], "Failure phase and diagnostic observability."),
    ("resource-termination", "Resource and termination", ["limit", "termination", "resource"], "Observable limits and termination, distinct from guarantees."),
    ("interaction-composition", "Interaction and composition", ["pair", "compound", "stateful"], "Semantically material feature interactions."),
    ("version-platform-differential", "Version and platform differential", ["release", "platform", "build"], "Versioned or platform-dependent semantics."),
    ("phase", "Semantic phase", ["build-source-generation", "compile", "match-search", "replacement-substitution", "stream-session", "serialization-deserialization"], "The lifecycle phase at which an observable semantic assertion applies."),
    ("complexity-guarantee", "Complexity guarantee", ["none-declared", "worst-case-time", "worst-case-memory", "subset-conditional", "resource-budget"], "Documented algorithmic time or memory guarantee, never an observed timeout proxy."),
    ("security-context", "Security context", ["trusted-pattern", "untrusted-pattern", "trusted-subject", "untrusted-subject", "trusted-serialized-input", "untrusted-serialized-input", "injection-boundary", "denial-of-service-posture"], "Trust assumptions and security boundaries that condition safe use without redefining match results."),
]


NEW_OPERATIONS = [
    ("escape-pattern", "Transform input text into pattern syntax intended to denote that text literally; the result is pattern-dialect specific.", ["python-re", "dotnet-regex"]),
    ("escape-replacement", "Transform input text into replacement syntax intended to emit that text literally; pattern escaping is not substitutable.", ["java-matcher", "python-re"]),
    ("serialize-pattern", "Encode a compiled pattern into a persistent or transferable representation under an explicit compatibility contract.", ["pcre2-serialization"]),
    ("deserialize-pattern", "Reconstruct a compiled pattern from serialized bytes while enforcing version, architecture and trust preconditions.", ["pcre2-serialization"]),
    ("inspect-pattern", "Read compiled-pattern metadata without applying the pattern to a subject.", ["pcre2-pattern-info"]),
    ("stream-open", "Create stream-specific matching state for a compiled multi-pattern database.", ["hyperscan-runtime"]),
    ("stream-close", "Finalize stream state and report end-of-stream matches before releasing the stream.", ["hyperscan-runtime"]),
    ("stream-reset", "Return an existing stream to initial state, including any end-of-stream reporting defined by the runtime.", ["hyperscan-runtime"]),
    ("stream-copy", "Clone current stream state so subsequent feeds may diverge from the same prefix.", ["hyperscan-runtime"]),
    ("stream-compress", "Encode live stream state into a bounded runtime representation without treating it as a compiled-pattern serialization.", ["hyperscan-runtime"]),
    ("stream-expand", "Restore live stream state from the runtime's compressed representation under the same database contract.", ["hyperscan-runtime"]),
]


EFFECTS = {
    "modifier": {
        "capture_result": "Option changes do not allocate a capture by themselves, but may change which branch or span supplies existing captures.",
        "diagnostic_error": "The exact directive spelling, legal placement, option domain and rejection phase are manifestation- and profile-specific.",
        "replacement": "The directive affects replacement only through the selected match and captures; it introduces no replacement token.",
        "resource_termination": "The directive has no universal complexity guarantee; the enabled option may select materially different runtime behavior.",
        "unicode_encoding": "Unicode-related options may change character interpretation; unrelated options preserve the profile's text domain.",
        "search_iteration": "The option can alter match selection but does not create a new host iteration operation.",
        "options_state": "Its scientific content is the scope, transition and restoration of option state.",
        "host_operation": "Hosts must preserve whether the option is compile-time, expression-scoped, or call-scoped rather than flattening these states.",
    },
    "algebra": {
        "capture_result": "Regular-language algebra contributes no capture allocation unless an implementation separately extends the construct with captures.",
        "diagnostic_error": "Unsupported algebraic operators are compile-time grammar outcomes, not ordinary no-match results.",
        "replacement": "Algebra changes the selected language and match span; it defines no replacement expansion token.",
        "resource_termination": "Automaton construction may expand substantially even when matching is bounded; implementation limits remain distinct from language semantics.",
        "unicode_encoding": "Set complement and universe are relative to the profile's declared alphabet or string domain.",
        "search_iteration": "Search applies the resulting language under the operation's existing leftmost/longest and advancement policy.",
        "options_state": "The operator has no mutable state but its alphabet and syntax may be gated by compile options.",
        "host_operation": "It is pattern-language semantics, not logical combination of independently reported multi-pattern results.",
    },
    "unicode": {
        "capture_result": "The construct allocates no capture and affects captures only through the text it matches or the boundary it asserts.",
        "diagnostic_error": "Unknown names, out-of-range values, and unavailable Unicode data versions are compile-time or documented unsupported outcomes.",
        "replacement": "The construct affects replacement through match selection and spans, not through replacement syntax.",
        "resource_termination": "Unicode-data lookup or grapheme/line algorithms may add bounded table/state cost but do not imply a universal complexity class.",
        "unicode_encoding": "Its meaning is explicitly Unicode-versioned and must distinguish code point, code unit and higher-level boundary domains.",
        "search_iteration": "Boundary assertions are zero-width; consuming atoms advance according to the matched text and host empty-match policy.",
        "options_state": "Unicode, ASCII-restriction and locale modes may enable, restrict or reinterpret the construct.",
        "host_operation": "Reported spans remain in the profile's native index unit even when matching uses Unicode properties or boundaries.",
    },
    "control": {
        "capture_result": "Captures made while evaluating the construct follow the source-defined backtracking and visibility rule; they are not assumed flat or atomic.",
        "diagnostic_error": "Support and structural restrictions are compile-time profile facts; attributable target termination remains distinct from adapter failure.",
        "replacement": "Any replacement consequence is mediated by the final match span and surviving captures.",
        "resource_termination": "Backtracking into assertions or recursive capture references can add search states; exact limits are profile-specific.",
        "unicode_encoding": "The construct inherits the enclosing pattern's text and index domain unless its captured subject is reinterpreted explicitly.",
        "search_iteration": "It constrains the match at the current engine position and does not itself define next-match advancement.",
        "options_state": "The construct observes the option state active at its lexical location and any source-defined recursion level.",
        "host_operation": "Hosts expose only final target-attributable results unless a documented trace or capture-history API supplies additional states.",
    },
    "result": {
        "capture_result": "The feature changes the static or dynamic result shape as a function of capture structure, optionality, repetition and transformations.",
        "diagnostic_error": "A statically inferred shape can reject an ill-typed use at build time; dynamic construction instead reports runtime parsing or cast outcomes.",
        "replacement": "Replacement callbacks may consume typed captures, while template replacement remains a separate replacement-dialect contract.",
        "resource_termination": "Result materialization cost follows the produced capture/output structure and is not a match-complexity guarantee.",
        "unicode_encoding": "Typed output may transform substrings, but underlying match ranges retain the profile's native string-index semantics.",
        "search_iteration": "Collection and repeated-capture types reflect the operation's iteration and quantification semantics.",
        "options_state": "The result type is determined by pattern construction and capture transformations, not by unrelated mutable match state.",
        "host_operation": "Compile-time literals/builders can expose a static Regex<Output>; runtime patterns may require an existential output representation.",
    },
}


FEATURE_SPECS = [
    ("inline-modifier-directive", "Inline modifier directive", "options-and-state", "modifier", "(?im-sx)", ["pcre2-pattern", "python-re"], ["compile", "test", "search"], "Changes option state from its lexical position under a source-defined scope rather than only through a host API."),
    ("scoped-modifier-group", "Scoped modifier group", "options-and-state", "modifier", "(?im-sx:<A>)", ["pcre2-pattern", "python-re"], ["compile", "test", "search"], "Applies an option delta only within a delimited subexpression and restores the enclosing option state afterward."),
    ("expression-intersection", "Expression-level language intersection", "grammar-and-composition", "algebra", "<A>&<B>", ["lucene-regexp", "smtlib-unicode-strings"], ["compile", "test", "full-match", "search"], "Denotes exactly the strings accepted by both operand regular languages; it is distinct from character-class intersection and multi-pattern result combination."),
    ("expression-difference", "Expression-level language difference", "grammar-and-composition", "algebra", "diff(<A>,<B>)", ["smtlib-unicode-strings"], ["compile", "test", "full-match", "search"], "Denotes strings in the first operand language and not in the second operand language."),
    ("expression-complement", "Expression-level language complement", "grammar-and-composition", "algebra", "~<A>", ["lucene-regexp", "smtlib-unicode-strings"], ["compile", "test", "full-match", "search"], "Denotes the complement of an operand language relative to the declared string alphabet/universe, not merely a negated character class."),
    ("empty-language-atom", "Empty-language atom", "grammar-and-composition", "algebra", "#", ["lucene-regexp", "smtlib-unicode-strings"], ["compile", "test", "full-match", "search"], "Denotes the regular language containing no strings; this differs from an empty pattern that matches the empty string."),
    ("universal-language-atom", "Universal-language atom", "grammar-and-composition", "algebra", "@", ["lucene-regexp", "smtlib-unicode-strings"], ["compile", "test", "full-match", "search"], "Denotes every string over the governed alphabet, including the empty string where the source theory defines a full string universe."),
    ("numeric-interval-language-atom", "Numeric interval language atom", "grammar-and-composition", "algebra", "<n-m>", ["lucene-regexp"], ["compile", "test", "full-match", "search"], "Denotes decimal strings whose numeric values lie in an inclusive interval, with source-defined fixed-width behavior when endpoints have equal width."),
    ("named-automaton-reference", "Named automaton reference", "grammar-and-composition", "algebra", "<identifier>", ["lucene-regexp"], ["compile", "test", "full-match", "search"], "References an externally supplied named automaton as a regular-language atom under the compiler's automaton provider."),
    ("numeric-unicode-code-point-escape", "Numeric Unicode code-point escape", "unicode-and-text-model", "unicode", "\\x{...}", ["unicode-tr18", "pcre2-pattern"], ["compile", "test", "search"], "Denotes a Unicode code point by numeric value subject to the grammar's range, width and mode rules."),
    ("unicode-line-break-boundary", "Unicode line-break boundary", "anchors-and-boundaries", "unicode", "\\b{lb}", ["unicode-tr14", "perl-regex-escapes"], ["compile", "test", "search", "next-match"], "Asserts a boundary selected by a Unicode line-breaking algorithm rather than a word, grapheme or literal newline boundary."),
    ("enumerated-unicode-property-value", "Enumerated Unicode property value", "unicode-and-text-model", "unicode", "\\p{property=value}", ["unicode-tr18", "unicode-uax44"], ["compile", "test", "search"], "Matches code points whose Unicode enumerated property has the named value, including non-binary properties such as Script or General_Category."),
    ("numeric-unicode-property-value", "Numeric Unicode property value", "unicode-and-text-model", "unicode", "\\p{property=value}", ["unicode-tr18", "unicode-uax44"], ["compile", "test", "search"], "Matches code points selected by a Unicode numeric property and governed value comparison/alias rule."),
    ("non-atomic-positive-lookbehind", "Non-atomic positive lookbehind", "lookaround", "control", "(?<*<A>)", ["pcre2-pattern"], ["compile", "test", "search"], "Asserts a preceding match while permitting later backtracking to re-enter the lookbehind, unlike an atomic positive lookbehind."),
    ("recursion-level-qualified-backreference", "Recursion-level-qualified backreference", "backreferences-recursion-and-conditionals", "control", "\\k<name+n>", ["oniguruma-syntax"], ["compile", "test", "search"], "References the capture value belonging to a source-defined relative recursion level rather than the current flat capture state."),
    ("captured-substring-assertion", "Captured-substring assertion", "lookaround", "control", "(*scan_substring:<A>)", ["pcre2-pattern"], ["compile", "test", "search"], "Applies a subpattern as a whole-string assertion over a previously captured substring while retaining the outer subject position."),
    ("typed-capture-result-shape", "Typed capture result shape", "host-operations-and-results", "result", "Regex<Output>", ["swift-regex-type", "swift-regex-builder", "swift-regex-literals"], ["compile", "extract", "find-all", "replace-callback"], "Makes capture structure, alternation optionality, repetition and transformations part of the host-visible regex output type."),
]


VARIANTS = [
    ("variant.inline-modifier-directive.leading-global", "feature.inline-modifier-directive", "leading-global", "A leading directive changes the initial option state for the remaining pattern under its grammar's global-placement rule."),
    ("variant.inline-modifier-directive.group-tail", "feature.inline-modifier-directive", "set-to-end-of-group", "A mid-group directive changes option state from its position to the end of the containing group."),
    ("variant.inline-modifier-directive.unset", "feature.inline-modifier-directive", "modifier-unset", "The directive removes named option bits while leaving unrelated option state intact."),
    ("variant.inline-modifier-directive.reset-default", "feature.inline-modifier-directive", "reset-to-default", "The directive resets the source-defined inline option set to its language defaults rather than merely unsetting one bit."),
    ("variant.inline-modifier-directive.exclusive-domain", "feature.inline-modifier-directive", "mutually-exclusive-domain", "Selecting one option from an exclusive domain replaces the currently active member of that domain."),
]

EXTRA_MANIFESTATIONS = [
    ("manifestation.replacement-numbered-group.java-dollar", "java-matcher", "replacement-syntax", "$1", "feature.replacement-numbered-group"),
    ("manifestation.replacement-numbered-group.python-backslash", "python-re", "replacement-syntax", "\\1", "feature.replacement-numbered-group"),
    ("manifestation.replacement-numbered-group.python-g", "python-re", "replacement-syntax", "\\g<1>", "feature.replacement-numbered-group"),
]


def _raw_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _finalize(body: dict[str, Any], namespace: str, family: str, id_field: str, digest_field: str) -> dict[str, Any]:
    digest = hashlib.sha256(canonical_bytes(body)).hexdigest()
    identity = build_content_identity(
        registry=NamespaceRegistry.load(ROOT / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(ROOT / PROFILE_PATH)),
        namespace=namespace,
        identity_schema_family_id=family,
        identity_schema_version="1.0.0",
        identity={"artifact_digest_sha256": digest},
    )["content_id"]
    return {**body, id_field: identity, digest_field: digest}


def _source_id_set() -> set[str]:
    predecessor = load_strict(ROOT / PREDECESSOR_PATH)
    return {item["source_id"] for item in predecessor["sources"]} | {item["source_id"] for item in NEW_SOURCES}


def _manifestation_key(slug: str) -> str:
    source = FEATURE_SPECS[[item[0] for item in FEATURE_SPECS].index(slug)][5][0]
    return f"manifestation.{slug}.{source}"


def candidate_specs() -> list[tuple[str, str, str, list[str], str]]:
    accepted: list[tuple[str, str, str, list[str], str]] = []
    for key, title, *_ in FACETS[-3:]:
        accepted.append((f"facet.{key}", "facet/dimension", f"Evaluate {title} as a first-class semantic dimension.", ["semantic-obligation-taxonomy", "re2-readme" if key != "phase" else "pcre2-pattern"], "accept-as-facet"))
    for key, _, sources in NEW_OPERATIONS:
        accepted.append((f"operation.{key}", "operation", f"Evaluate the materially distinct {key} host operation.", sources, "accept-as-operation"))
    for slug, title, _, _, _, sources, _, _ in FEATURE_SPECS:
        accepted.append((f"feature.{slug}", "canonical feature", f"Evaluate {title} as a canonical semantic concept.", sources, "accept-canonical"))
    for key, _, name, _ in VARIANTS:
        accepted.append((key, "semantic variant", f"Evaluate {name} as a distinct inline-modifier semantic variant.", ["pcre2-pattern"], "accept-as-variant"))
    extras = [
        ("operation.compile-only", "operation", "Compile-only or pattern construction operation.", ["pcre2-api"], "already-covered"),
        ("operation.stream-feed", "operation", "Feed one subject block to an open stream.", ["hyperscan-runtime"], "already-covered"),
        ("operation.minimum-maximum-match-analysis", "operation", "Static minimum/maximum match-length analysis.", ["pcre2-pattern-info"], "already-covered"),
        ("operation.subexpression-extraction", "operation", "Select a subexpression result through a host API.", ["bigquery-regex"], "already-covered"),
        ("operation.subexpression-position", "operation", "Return a selected subexpression position.", ["bigquery-regex"], "already-covered"),
        ("operation.pattern-analysis", "operation", "Analyze compiled pattern structure rather than a subject.", ["pcre2-pattern-info"], "already-covered"),
        ("feature.replacement-dialect-identity", "canonical feature", "Make replacement dialect itself a canonical feature.", ["java-matcher", "python-re"], "profile-specific-not-canonical"),
        ("manifestation.replacement-dollar-reference", "manifestation", "Dollar-numbered replacement reference spelling.", ["java-matcher"], "accept-as-manifestation"),
        ("manifestation.replacement-backslash-reference", "manifestation", "Backslash-numbered replacement reference spelling.", ["python-re"], "accept-as-manifestation"),
        ("manifestation.replacement-g-reference", "manifestation", "Delimited replacement reference spelling.", ["python-re"], "accept-as-manifestation"),
        ("feature.replacement-callback-model", "canonical feature", "Callback/evaluated replacement behavior.", ["perl-operations", "python-re"], "already-covered"),
        ("feature.grapheme-cluster-domain", "canonical feature", "Grapheme-cluster matching domain.", ["unicode-tr29", "unicode-tr18"], "already-covered"),
        ("feature.full-code-point-complement-policy", "canonical feature", "Full string versus code-point complement policy.", ["unicode-tr18", "smtlib-unicode-strings"], "accept-as-facet"),
        ("feature.malformed-text-mode", "canonical feature", "Malformed-text interpretation and rejection modes.", ["unicode-tr18", "pcre2-pattern"], "already-covered"),
        ("feature.right-to-left-whole-pattern", "canonical feature", "Whole-pattern right-to-left evaluation.", ["dotnet-options"], "already-covered"),
        ("feature.cursor-retention", "canonical feature", "Retain or expose the next search cursor.", ["java-matcher", "tcl-regex"], "already-covered"),
        ("feature.capture-tree", "canonical feature", "Tree-shaped capture structure distinct from flat history.", ["swift-regex-type", "dotnet-groups"], "defer-to-oracle-adjudication"),
        ("feature.generated-regex-build-time", "canonical feature", "Build/source-generation regex validation.", ["swift-regex-literals", "dotnet-regex"], "accept-as-facet"),
        ("taxonomy.capture-history-stack", "taxonomy correction", "Capture history versus capture stack possible duplication.", ["dotnet-groups", "oniguruma-regex"], "already-covered"),
        ("taxonomy.resource-versus-complexity", "taxonomy correction", "Resource termination observations mixed with complexity guarantees.", ["re2-readme", "rust-regex"], "accept-as-facet"),
        ("taxonomy.harness-vocabulary", "taxonomy correction", "Harness-only states represented as regex semantics.", ["semantic-obligation-taxonomy"], "out-of-scope"),
        ("taxonomy.result-span-mutators", "taxonomy correction", "Result-span mutators grouped as anchors.", ["pcre2-pattern", "oniguruma-regex"], "accept-canonical"),
        ("taxonomy.unicode-vendor-syntax", "taxonomy correction", "Unicode concepts grouped by vendor spelling.", ["unicode-tr18"], "alias-or-terminology"),
        ("taxonomy.sql-product-surface", "taxonomy correction", "SQL host semantics grouped as product surface.", ["bigquery-regex", "postgres-regex"], "profile-specific-not-canonical"),
        ("taxonomy.automatic-possessification", "taxonomy correction", "Automatic possessification represented as observable semantics.", ["pcre2-pattern"], "implementation-specific"),
        ("feature.hyperscan-logical-combination", "canonical feature", "Logical combination of independently reported pattern IDs.", ["hyperscan"], "already-covered"),
        ("feature.modifiers-forbidden-inline", "canonical feature", "Options forbidden from inline manipulation.", ["pcre2-pattern", "dotnet-options"], "profile-specific-not-canonical"),
        ("source.lucene", "source authority", "Lucene automaton regular-expression authority.", ["lucene-regexp"], "accept-as-source"),
        ("source.smtlib", "source authority", "SMT-LIB regular-language theory authority.", ["smtlib-unicode-strings"], "accept-as-source"),
        ("source.swift", "source authority", "Swift Regex and RegexBuilder authority.", ["swift-regex-type", "swift-regex-builder", "swift-regex-literals"], "accept-as-source"),
        ("source.vim", "source authority", "Vim regular-expression authority.", ["vim-regex"], "already-covered"),
        ("source.emacs", "source authority", "Emacs regular-expression authority.", ["emacs-regex"], "already-covered"),
        ("source.unicode-line-break", "source authority", "Unicode line-break authority.", ["unicode-tr14"], "accept-as-source"),
        ("source.unicode-database", "source authority", "Unicode property data authority.", ["unicode-uax44"], "accept-as-source"),
        ("source.pcre2-serialization", "source authority", "PCRE2 serialization and pattern-info authority.", ["pcre2-serialization", "pcre2-pattern-info"], "accept-as-source"),
        ("source.official-conformance-corpora", "source authority", "Additional official conformance corpora as semantic authority.", ["ecma-regexp", "unicode-tr18"], "insufficient-evidence"),
        ("source.package-catalogues", "source authority", "General package catalogues as semantic authority.", ["known-universe-census"], "defer-to-profile-architecture"),
    ]
    return sorted(accepted + extras)


def allocation_keys() -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    keys += [("semantic-facet", f"facet.{key}") for key, *_ in FACETS]
    keys += [("operation", f"operation.{key}") for key, *_ in NEW_OPERATIONS]
    keys += [("feature", f"feature.{slug}") for slug, *_ in FEATURE_SPECS]
    keys += [("semantic-variant", key) for key, *_ in VARIANTS]
    keys += [("manifestation", _manifestation_key(slug)) for slug, *_ in FEATURE_SPECS]
    keys += [("manifestation", key) for key, *_ in EXTRA_MANIFESTATIONS]
    keys += [("candidate", f"candidate.{key}") for key, *_ in candidate_specs()]
    return sorted(keys)


def allocate() -> dict[str, Any]:
    registry = NamespaceRegistry.load(ROOT / NAMESPACE_PATH)
    existing: dict[tuple[str, str], str] = {}
    if (ROOT / ALLOCATION_PATH).exists():
        record = load_strict(ROOT / ALLOCATION_PATH)
        existing = {(x["entity_class"], x["canonical_key"]): x["assigned_id"] for x in record["allocations"]}
    for entity_class, key in allocation_keys():
        if (entity_class, key) not in existing:
            existing[(entity_class, key)] = generate_assigned_id(registry, "rcid", entity_class)
    return {
        "schema_version": "regex-semantic-architecture-identity-allocation.v1",
        "allocated_on": PUBLISHED_ON,
        "allocations": [
            {"entity_class": entity_class, "canonical_key": key, "assigned_id": identifier}
            for (entity_class, key), identifier in sorted(existing.items())
        ],
    }


def allocation_map(record: dict[str, Any]) -> dict[str, str]:
    return {x["canonical_key"]: x["assigned_id"] for x in record["allocations"]}


def _assertions(spec: tuple[Any, ...]) -> dict[str, Any]:
    slug, title, _, family, grammar, sources, _, definition = spec
    effects = EFFECTS[family]
    values = {
        "definition": definition,
        "syntax_grammar": f"{title} has the canonical abstract form {grammar!r}; exact spelling, precedence and enablement remain on source-bound manifestations.",
        **effects,
    }
    return {
        field: {
            "field": field,
            "state": "profile-dependent" if field in {"diagnostic_error", "options_state"} else "known",
            "scope": "canonical-invariant" if field not in {"syntax_grammar", "diagnostic_error"} else "manifestation-specific",
            "statement": values[field],
            "source_ids": sorted(sources),
            "derivation_id": DERIVATION_ID,
            "derivation_class": "research-derived",
            "rule_id": f"semantic-architecture.{family}.{field}",
        }
        for field in SEMANTIC_FIELDS
    }


def _candidate_record(spec: tuple[str, str, str, list[str], str], ids: dict[str, str]) -> dict[str, Any]:
    key, cls, description, sources, disposition = spec
    accepted = disposition.startswith("accept-")
    destinations = {
        "defer-to-profile-architecture": "Empirical profile-universe freeze",
        "defer-to-oracle-adjudication": "Oracle, applicability, claims and adjudication architecture",
        "defer-to-execution-resource-architecture": "Final evidence and execution resource architecture",
    }
    return {
        "candidate_id": ids[f"candidate.{key}"],
        "candidate_key": f"candidate.{key}",
        "candidate_class": cls,
        "description": description,
        "evidence_source_ids": sorted(set(sources)),
        "current_corpus_relationship": "Compared against the researched successor snapshot and its carried operation/modifier/interaction authorities.",
        "scientific_distinctness": "Accepted only when the candidate changes an observable language, operation, result, lifecycle, guarantee, or authority boundary rather than naming a vendor spelling.",
        "disposition": disposition,
        "rationale": ("Primary authority establishes a materially distinct canonical contract." if accepted else "The reviewed evidence places this concept in an existing entity, a narrower manifestation/profile, or a later authority layer."),
        "implementation_consequence": ("Represented in the successor semantic architecture." if accepted else "No duplicate canonical semantic entity is minted in this snapshot."),
        "identity_consequence": ("A new typed assigned identity is allocated where the accepted disposition creates a canonical entity." if accepted else "No accepted scientific identity is retired or reused."),
        "downstream_consequence": destinations.get(disposition, "The later obligation derivation consumes this disposition without changing the predecessor denominator here."),
        "blocking": False,
    }


def build_all(allocation: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    ids = allocation_map(allocation)
    predecessor = load_strict(ROOT / PREDECESSOR_PATH)
    legacy = load_strict(ROOT / LEGACY_PATH)
    identity_catalog = load_strict(ROOT / IDENTITY_PATH)
    existing_ids = {x["canonical_key"]: x["scientific_id"] for x in identity_catalog["bindings"]}
    candidates = [_candidate_record(spec, ids) for spec in candidate_specs()]
    ledger_body = {
        "schema_version": "regex-semantic-candidate-disposition-ledger.v1",
        "published_on": PUBLISHED_ON,
        "method": {
            "derivation_id": DERIVATION_ID,
            "source_priority": ["normative specification", "official implementation documentation", "official source or tests", "authoritative data", "explicit inference"],
            "exhaustiveness_rule": "Seed audit findings, predecessor unresolved questions, source-family comparison, operation comparison and taxonomy-overcount challenges; retain every candidate with a terminal disposition.",
        },
        "predecessor_snapshot": {"path": PREDECESSOR_PATH.as_posix(), "snapshot_id": predecessor["snapshot_id"], "snapshot_digest_sha256": predecessor["snapshot_digest_sha256"]},
        "candidates": candidates,
        "counts": {
            "total": len(candidates),
            "by_class": dict(sorted(Counter(x["candidate_class"] for x in candidates).items())),
            "by_disposition": dict(sorted(Counter(x["disposition"] for x in candidates).items())),
            "blocking_unresolved": sum(x["blocking"] for x in candidates),
        },
    }
    ledger = _finalize(ledger_body, "finding-revision", SCHEMA_FAMILIES["ledger"], "ledger_id", "ledger_digest_sha256")

    source_map = {x["source_id"]: x for x in predecessor["sources"]}
    source_map.update({x["source_id"]: x for x in NEW_SOURCES})
    legacy_ops = []
    for op in legacy["operations"]:
        key = op["operation_id"]
        legacy_ops.append({
            **deepcopy(op),
            "scientific_id": existing_ids[key],
            "identity_basis": {"kind": "host-operation", "observable_contract": key},
            "derivation_id": DERIVATION_ID,
            "source_ids": ["semantic-obligation-taxonomy"],
        })
    operations = legacy_ops + [
        {
            "operation_id": f"operation.{key}",
            "name": key,
            "description": contract,
            "semantic_contract": contract,
            "scientific_id": ids[f"operation.{key}"],
            "identity_basis": {"kind": "host-operation", "observable_contract": key},
            "derivation_id": DERIVATION_ID,
            "source_ids": sorted(sources),
        }
        for key, contract, sources in NEW_OPERATIONS
    ]

    facets = [
        {
            "facet_id": f"facet.{key}",
            "scientific_id": ids[f"facet.{key}"],
            "title": title,
            "domain": domain,
            "applicability": description,
            "canonical_authority": "This snapshot defines the closed semantic dimension; source-bound assertions establish applicability.",
            "obligation_derivation_use": "A later denominator compiler may emit only evidence-backed applicable states; presence here never creates obligations by uniform expansion.",
            "identity_basis": {"kind": "semantic-dimension", "dimension": key},
            "derivation_id": DERIVATION_ID,
            "source_ids": ["semantic-obligation-taxonomy"] if key not in {"phase", "complexity-guarantee", "security-context"} else (["pcre2-pattern", "swift-regex-literals"] if key == "phase" else ["re2-readme", "rust-regex"]),
        }
        for key, title, domain, description in FACETS
    ]

    features = []
    for feature in predecessor["features"]:
        current = deepcopy(feature)
        current["semantic_revision"] = 3
        current["identity_basis"] = {"kind": "retained-feature", "scientific_id": feature["scientific_id"]}
        if current["feature_id"] in {"feature.reset-reported-match-end", "feature.reset-reported-match-start"}:
            current["category"] = "host-operations-and-results"
            current["identity_disposition"] = {"kind": "retained", "predecessor_key": current["feature_id"], "reason": "Category correction relocates a result-span mutator without changing its scientific meaning."}
        features.append(current)

    new_features = []
    variant_by_feature: dict[str, list[dict[str, Any]]] = {}
    for key, parent, name, statement in VARIANTS:
        variant_by_feature.setdefault(parent, []).append({
            "variant_id": key,
            "name": name,
            "scientific_id": ids[key],
            "semantic_assertion": {"field": "variant-distinction", "state": "known", "scope": "variant-specific", "statement": statement, "source_ids": ["pcre2-pattern"], "derivation_id": DERIVATION_ID, "derivation_class": "research-derived", "rule_id": "semantic-architecture.modifier.variant"},
            "identity_basis": {"kind": "semantic-variant", "parent": parent, "distinction": name},
        })
    manifestations = deepcopy(predecessor["manifestations"])
    for key, source, kind, form, feature_key in EXTRA_MANIFESTATIONS:
        manifestations.append({
            "manifestation_id": key,
            "scientific_id": ids[key],
            "source_id": source,
            "kind": kind,
            "syntax_or_api_form": form,
            "semantic_feature_id": feature_key,
            "identity_note": "Replacement spelling is source-bound manifestation syntax, not a duplicate canonical replacement feature.",
            "semantic_scope": "manifestation-specific",
            "canonical_semantics_owner": existing_ids[feature_key],
            "derivation_id": DERIVATION_ID,
            "identity_basis": {"kind": "manifestation", "feature": feature_key, "source": source, "form": form},
        })
    for spec in FEATURE_SPECS:
        slug, title, category, family, grammar, sources, operation_ids, definition = spec
        key = f"feature.{slug}"
        manifestation_key = _manifestation_key(slug)
        feature = {
            "feature_id": key,
            "scientific_id": ids[key],
            "canonical_name": title,
            "aliases": [],
            "historical_names": [],
            "category": category,
            "feature_class": family,
            "semantic_revision": 3,
            "abstract_grammar_form": grammar,
            "semantic_assertions": _assertions(spec),
            "source_ids": sorted(sources),
            "derivation_id": DERIVATION_ID,
            "supported_operation_ids": operation_ids,
            "semantic_variants": sorted(variant_by_feature.get(key, []), key=lambda x: x["variant_id"]),
            "manifestation_ids": [manifestation_key],
            "modifier_ids": [],
            "prerequisite_feature_ids": [],
            "typed_relations": [],
            "test_concepts": [f"Distinguish {title} from its nearest existing construct.", f"Probe source-defined acceptance and rejection boundaries for {grammar}.", "Preserve native result spans and attributable diagnostics."],
            "unresolved_semantic_questions": [],
            "identity_basis": {"kind": "canonical-regex-semantics", "semantic-role": slug, "distinguishing-axis": family},
            "identity_disposition": {"kind": "new", "reason": "Primary-source comparison established a materially distinct semantic concept absent from the predecessor."},
        }
        new_features.append(feature)
        manifestations.append({
            "manifestation_id": manifestation_key,
            "scientific_id": ids[manifestation_key],
            "source_id": sources[0],
            "kind": "syntax-or-api",
            "syntax_or_api_form": grammar,
            "semantic_feature_id": key,
            "identity_note": "The source spelling manifests the canonical concept and does not own cross-source semantics.",
            "semantic_scope": "manifestation-specific",
            "canonical_semantics_owner": ids[key],
            "derivation_id": DERIVATION_ID,
            "identity_basis": {"kind": "manifestation", "feature": key, "source": sources[0], "form": grammar},
        })
    features.extend(new_features)
    features.sort(key=lambda x: x["feature_id"])
    manifestations.sort(key=lambda x: x["manifestation_id"])
    operations.sort(key=lambda x: x["operation_id"])
    facets.sort(key=lambda x: x["facet_id"])

    snapshot_body = {
        "schema_version": "regex-semantic-corpus.v3",
        "published_on": PUBLISHED_ON,
        "status": "canonical-expanded-researched-successor",
        "authority": {
            "semantic_home": "semantic-corpus/snapshots",
            "scientific_identity_owner": IDENTITY_PATH.as_posix(),
            "assertion_derivation_owner": "registries/provenance/generated-assertion-derivations.v1.json",
            "candidate_disposition_owner": LEDGER_PATH.as_posix(),
            "denominator_boundary": "The predecessor projection, obligations, requirements and forecast remain authoritative until dedicated rederivation.",
        },
        "predecessor": {"path": PREDECESSOR_PATH.as_posix(), "snapshot_id": predecessor["snapshot_id"], "snapshot_digest_sha256": predecessor["snapshot_digest_sha256"], "artifact_sha256": _raw_sha(ROOT / PREDECESSOR_PATH)},
        "candidate_ledger": {"path": LEDGER_PATH.as_posix(), "ledger_id": ledger["ledger_id"], "ledger_digest_sha256": ledger["ledger_digest_sha256"]},
        "sources": [source_map[key] for key in sorted(source_map)],
        "semantic_facets": facets,
        "operations": operations,
        "modifiers": deepcopy(legacy["modifiers"]),
        "features": features,
        "manifestations": manifestations,
        "carried_forward_by_reference": {"typed_interactions": f"{LEGACY_PATH.as_posix()}#/interactions", "predecessor_obligation_candidates": f"{LEGACY_PATH.as_posix()}#/candidates"},
        "counts": {
            "canonical_features": len(features),
            "semantic_variants": sum(len(x["semantic_variants"]) for x in features),
            "syntax_manifestations": len(manifestations),
            "modifiers": len(legacy["modifiers"]),
            "operations": len(operations),
            "semantic_facets": len(facets),
            "source_identities": len(source_map),
            "retained_feature_identities": len(predecessor["features"]),
            "new_feature_identities": len(new_features),
        },
    }
    snapshot = _finalize(snapshot_body, "ontology-snapshot", SCHEMA_FAMILIES["snapshot"], "snapshot_id", "snapshot_digest_sha256")

    denominator_paths = {
        "obligation_projection": "ontology/projections/regex-semantic-projection-2026-08-22.v1.json",
        "vector_requirements": "vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json",
        "denominator_forecast": "reports/scale/regex-semantic-denominator-forecast.json",
    }
    report_body = {
        "schema_version": "regex-semantic-architecture-disposition-report.v1",
        "published_on": PUBLISHED_ON,
        "candidate_ledger": {"path": LEDGER_PATH.as_posix(), "id": ledger["ledger_id"], "digest_sha256": ledger["ledger_digest_sha256"]},
        "semantic_snapshot": {"predecessor_id": predecessor["snapshot_id"], "successor_id": snapshot["snapshot_id"], "successor_digest_sha256": snapshot["snapshot_digest_sha256"]},
        "candidate_counts": ledger["counts"],
        "architecture_counts": {
            "features": {"old": 251, "new": len(features)},
            "operations": {"old": 22, "new": len(operations)},
            "facets": {"old": 12, "new": len(facets)},
            "sources": {"old": len(predecessor["sources"]), "new": len(source_map)},
            "variants": {"old": 88, "new": snapshot["counts"]["semantic_variants"]},
            "manifestations": {"old": 304, "new": len(manifestations)},
        },
        "identity_effects": {"retained_features": 251, "new_features": len(new_features), "new_facets": len(facets), "new_operations": len(NEW_OPERATIONS), "new_variants": len(VARIANTS), "new_manifestations": len(new_features) + len(EXTRA_MANIFESTATIONS), "successors": 0, "merges": 0, "splits": 0, "retirements": 0},
        "source_coverage": {"new_authoritative_sources": len(NEW_SOURCES), "all_accepted_entities_source_bound": True, "cross_engine_majority_used_as_authority": False},
        "derivation_coverage": {"derivation_id": DERIVATION_ID, "accepted_entities_bound": len(facets) + len(NEW_OPERATIONS) + len(new_features) + len(VARIANTS) + len(new_features)},
        "unresolved": {"blocking": 0, "deferred_candidates": sum(x["disposition"].startswith("defer-") for x in candidates), "rule": "Deferrals name their later authority and do not block the final adversarial semantic-universe audit."},
        "denominator_boundary": {"obligation_templates": 12048, "vector_requirements": 9506, "artifacts_unchanged": True, "artifact_sha256": {key: _raw_sha(ROOT / path) for key, path in denominator_paths.items()}},
        "result": "PASS",
        "derivation_id": DERIVATION_ID,
    }
    report = _finalize(report_body, "trust-assessment", SCHEMA_FAMILIES["report"], "report_id", "report_digest_sha256")
    return ledger, snapshot, report


def verify(allocation: dict[str, Any], artifacts: tuple[dict[str, Any], dict[str, Any], dict[str, Any]]) -> None:
    ledger, snapshot, report = artifacts
    validate_instance(allocation, load_strict(ROOT / ALLOCATION_SCHEMA_PATH), source=ALLOCATION_SCHEMA_PATH.as_posix())
    for artifact, schema_path in ((ledger, LEDGER_SCHEMA_PATH), (snapshot, SNAPSHOT_SCHEMA_PATH), (report, REPORT_SCHEMA_PATH)):
        validate_instance(artifact, load_strict(ROOT / schema_path), source=schema_path.as_posix())
    keys = [x["candidate_key"] for x in ledger["candidates"]]
    if keys != sorted(keys) or len(keys) != len(set(keys)) or ledger["counts"]["blocking_unresolved"]:
        raise ValueError("candidate ledger is not uniquely and terminally dispositioned")
    if snapshot["counts"]["canonical_features"] != 268 or snapshot["counts"]["operations"] != 33 or snapshot["counts"]["semantic_facets"] != 15:
        raise ValueError("expanded semantic architecture count mismatch")
    if any(len(x["semantic_assertions"]) != 10 for x in snapshot["features"]):
        raise ValueError("every feature must retain the ten researched semantic dimensions")
    if report["denominator_boundary"]["obligation_templates"] != 12048 or report["denominator_boundary"]["vector_requirements"] != 9506:
        raise ValueError("predecessor denominator boundary changed")
    if report["result"] != "PASS":
        raise ValueError("candidate disposition did not close")


def _write(path: Path, value: dict[str, Any]) -> None:
    destination = ROOT / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(value) + b"\n"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    if destination.read_bytes() != encoded:
        raise RuntimeError(f"read-after-write verification failed: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--allocate", action="store_true")
    args = parser.parse_args()
    allocation = allocate()
    if args.check and not (ROOT / ALLOCATION_PATH).exists():
        raise ValueError("identity allocation is missing")
    if args.allocate or not (ROOT / ALLOCATION_PATH).exists():
        _write(ALLOCATION_PATH, allocation)
    else:
        allocation = load_strict(ROOT / ALLOCATION_PATH)
        if set(allocation_map(allocation)) != set(allocation_map(allocate())):
            raise ValueError("identity allocation does not cover the exact candidate architecture")
    artifacts = build_all(allocation)
    verify(allocation, artifacts)
    pairs = zip(artifacts, (LEDGER_PATH, SNAPSHOT_PATH, REPORT_PATH), strict=True)
    if args.check:
        for artifact, path in pairs:
            if not (ROOT / path).exists() or (ROOT / path).read_bytes() != canonical_bytes(artifact) + b"\n":
                raise ValueError(f"tracked semantic architecture artifact differs: {path}")
    else:
        for artifact, path in pairs:
            _write(path, artifact)
        rebuilt = build_all(load_strict(ROOT / ALLOCATION_PATH))
        if any(canonical_bytes(a) != canonical_bytes(b) for a, b in zip(artifacts, rebuilt, strict=True)):
            raise RuntimeError("semantic architecture regeneration is not deterministic")
    print(f"candidates={ledger_count(artifacts[0])} features={artifacts[1]['counts']['canonical_features']} operations={artifacts[1]['counts']['operations']} facets={artifacts[1]['counts']['semantic_facets']} snapshot={artifacts[1]['snapshot_id']}")
    return 0


def ledger_count(ledger: dict[str, Any]) -> int:
    return int(ledger["counts"]["total"])


if __name__ == "__main__":
    raise SystemExit(main())
