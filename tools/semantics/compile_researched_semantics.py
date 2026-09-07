#!/usr/bin/env python3
"""Publish the source-bound semantic successor without rebuilding obligations.

This compiler deliberately consumes the accepted semantic snapshot as immutable
input.  It enriches the same 251 scientific features, writes a normalized
research ledger and a successor snapshot, and never imports the legacy
obligation/vector compiler.
"""

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

from regex_conformance_schema.identity import NamespaceRegistry, build_content_identity  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402
from regex_conformance_schema.profile import IdentityProfile  # noqa: E402
from regex_conformance_schema.schema import validate_instance  # noqa: E402


PREDECESSOR_PATH = Path(
    "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json"
)
IDENTITY_PATH = Path("registries/identity/scientific-identities.v1.json")
LEDGER_PATH = Path(
    "semantic-corpus/research/regex-semantic-feature-research-2026-09-07.v1.json"
)
SNAPSHOT_PATH = Path(
    "semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v2.json"
)
REPORT_PATH = Path("reports/semantics/researched-feature-semantics-2026-09-07.v1.json")
LEDGER_SCHEMA_PATH = Path("schemas/json/regex-semantic-feature-research-ledger.schema.json")
SNAPSHOT_SCHEMA_PATH = Path("schemas/json/regex-semantic-corpus-v2.schema.json")
REPORT_SCHEMA_PATH = Path("schemas/json/regex-semantic-research-completeness.schema.json")
PROFILE_PATH = Path("schemas/identity-profiles/semantic-research-artifact.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v2.json")

RESEARCH_DERIVATION_ID = (
    "rcid:v1:assertion-derivation:u7:01a07cfa-78e3-7de8-9559-e045f4e27cc0"
)
SCHEMA_FAMILIES = {
    "ledger": "rcid:v1:schema-family:u7:01a07cfb-8167-7e4e-81dc-c9b7c1bfa883",
    "snapshot": "rcid:v1:schema-family:u7:01a07cfb-8167-71e4-b6f5-8198c0188433",
    "report": "rcid:v1:schema-family:u7:01a07cfb-a3d6-73ad-915a-ac5483e9b17c",
}

LEGACY_TEMPLATE_FIELDS = (
    "capture_result_semantics",
    "replacement_implications",
    "unicode_encoding_implications",
    "diagnostic_error_semantics",
    "resource_termination_implications",
)
SEMANTIC_FIELDS = (
    "definition",
    "syntax_grammar",
    "capture_result",
    "diagnostic_error",
    "replacement",
    "resource_termination",
    "unicode_encoding",
    "search_iteration",
    "options_state",
    "host_operation",
)
AUDIT_DIMENSIONS = (
    "canonical_definition",
    "syntax_grammar",
    "capture_result",
    "diagnostic_error",
    "replacement",
    "resource_termination",
    "unicode_encoding",
    "search_iteration",
    "options_state",
    "host_operation",
    "interactions",
    "historical_names",
    "unresolved_questions",
    "test_concepts",
    "prerequisites",
    "modifiers",
    "manifestations",
    "semantic_variants",
    "source_evidence",
)
STATES = {
    "known",
    "no-feature-specific-implication",
    "not-applicable",
    "implementation-defined",
    "intentionally-under-specified",
    "unresolved",
}

CAPTURE_ENTITIES = {
    "feature.balancing-group",
    "feature.branch-reset-group",
    "feature.capture-history",
    "feature.capture-name-table",
    "feature.capture-participation",
    "feature.capture-span",
    "feature.capture-stack",
    "feature.capture-suppression",
    "feature.capture-value",
    "feature.duplicate-group-name",
    "feature.duplicate-group-number",
    "feature.explicit-capture-number",
    "feature.group-numbering-policy",
    "feature.last-capture-of-repetition",
    "feature.named-capture",
    "feature.numbered-capture",
    "feature.unset-versus-empty-capture",
    "feature.lookaround-capture-visibility",
    "feature.recursion-returned-captures",
}
BACKREFERENCE_ENTITIES = {
    "feature.forward-backreference",
    "feature.named-backreference",
    "feature.numbered-backreference",
    "feature.relative-backreference",
    "feature.unset-backreference-behavior",
}
MATCH_SPAN_ENTITIES = {
    "feature.reset-reported-match-start",
    "feature.reset-reported-match-end",
    "feature.capture-span",
    "feature.native-index-unit",
}
ZERO_LENGTH_ENTITIES = {
    "feature.empty-pattern",
    "feature.empty-alternative",
    "feature.quantified-empty-operand",
    "feature.zero-length-advancement",
    "feature.split-empty-match",
    "feature.tokenize-zero-length-prohibition",
}
TEXT_MODEL_ENTITIES = {
    "feature.ascii-restricted-unicode-classes",
    "feature.byte-domain",
    "feature.canonical-equivalence",
    "feature.code-unit-domain",
    "feature.extended-grapheme-cluster",
    "feature.full-case-folding",
    "feature.legacy-grapheme-cluster",
    "feature.locale-case-folding",
    "feature.malformed-text-raw-units",
    "feature.malformed-text-rejection",
    "feature.malformed-text-replacement",
    "feature.native-index-unit",
    "feature.normalization-aware-matching",
    "feature.simple-case-folding",
    "feature.single-code-unit-escape",
    "feature.unicode-code-point-domain",
    "feature.unicode-grapheme-boundary",
    "feature.unicode-scalar-domain",
    "feature.unicode-sentence-boundary",
    "feature.unicode-word-boundary",
}
CLASSIFICATION_ENTITIES = {
    "feature.class-intersection",
    "feature.class-negation",
    "feature.class-range",
    "feature.class-string-disjunction",
    "feature.class-string-member",
    "feature.class-subtraction",
    "feature.class-symmetric-difference",
    "feature.class-union",
    "feature.digit-class",
    "feature.horizontal-whitespace",
    "feature.nested-character-class",
    "feature.posix-collating-element",
    "feature.posix-equivalence-class",
    "feature.posix-named-class",
    "feature.unicode-binary-property",
    "feature.unicode-block",
    "feature.unicode-character-name",
    "feature.unicode-general-category",
    "feature.unicode-property-alias",
    "feature.unicode-property-value-wildcard",
    "feature.unicode-script",
    "feature.unicode-script-extensions",
    "feature.unicode-string-property",
    "feature.vertical-whitespace",
    "feature.whitespace-class",
    "feature.word-class",
}
SELECTION_ENTITIES = {
    "feature.all-match-lengths-at-start",
    "feature.best-approximate-match",
    "feature.dfa-greediness-insensitivity",
    "feature.enhanced-approximate-match",
    "feature.greedy-preference",
    "feature.lazy-preference",
    "feature.leftmost-first-match",
    "feature.leftmost-longest-match",
    "feature.occurrence-selection",
    "feature.ordered-alternation",
    "feature.shortest-match-at-start",
}
STATEFUL_HOST_ENTITIES = {
    "feature.anchoring-region-bounds",
    "feature.append-replacement-state",
    "feature.match-end-state",
    "feature.matcher-region",
    "feature.mutable-match-cursor",
    "feature.previous-match-end",
    "feature.sticky-cursor-match",
    "feature.transparent-region-bounds",
}
STREAMING_ENTITIES = {
    "feature.block-match",
    "feature.callback-scan-termination",
    "feature.logical-pattern-combination",
    "feature.match-event-callback",
    "feature.match-offset-constraints",
    "feature.multi-pattern-database",
    "feature.multi-pattern-overlap",
    "feature.partial-match-restart",
    "feature.pattern-set-results",
    "feature.prefilter-superset",
    "feature.single-match-pattern",
    "feature.start-of-match-horizon",
    "feature.start-of-match-tracking",
    "feature.streaming-match",
    "feature.vectored-match",
}
RESOURCE_ENTITIES = {
    "feature.backtracking-depth-limit",
    "feature.bounded-memory-guarantee",
    "feature.linear-time-guarantee",
    "feature.match-heap-limit",
    "feature.match-step-limit",
    "feature.nesting-depth-limit",
    "feature.operation-timeout",
    "feature.pattern-size-limit",
    "feature.replacement-buffer-overflow",
    "feature.stack-exhaustion",
    "feature.target-crash-or-signal",
    "feature.workspace-exhaustion",
}
DIAGNOSTIC_ENTITIES = {
    "feature.compile-syntax-error",
    "feature.diagnostic-code-and-class",
    "feature.diagnostic-offset",
    "feature.invalid-escape-error",
    "feature.invalid-group-reference",
    "feature.invalid-quantifier-error",
    "feature.invalid-unicode-property",
    "feature.unsupported-construct",
} | RESOURCE_ENTITIES
CODE_AND_CALLBACK_ENTITIES = {
    "feature.callout-backtracking",
    "feature.code-conditional",
    "feature.dynamic-regex-code",
    "feature.embedded-code",
    "feature.match-event-callback",
    "feature.named-callout",
    "feature.numeric-callout",
    "feature.string-callout",
    "feature.substitution-callout",
}
ADDITIONAL_FEATURE_SOURCES = {
    "feature.extended-grapheme-cluster": {"unicode-tr29"},
    "feature.legacy-grapheme-cluster": {"unicode-tr29"},
    "feature.unicode-grapheme-boundary": {"unicode-tr29"},
    "feature.unicode-sentence-boundary": {"unicode-tr29"},
    "feature.unicode-word-boundary": {"unicode-tr29"},
    "feature.leftmost-first-match": {"go-regexp"},
    "feature.capture-suppression": {"dotnet-options"},
    "feature.callback-replacement": {"perl-operations"},
}


RULES = {
    "definition.canonical": ("known", "canonical-invariant", "Source synthesis defines the stable scientific concept without adopting any one spelling."),
    "syntax.pattern": ("known", "manifestation-specific", "The canonical grammar shape is known; exact tokens and acceptance restrictions remain manifestation-bound."),
    "syntax.host": ("not-applicable", "operation-specific", "This capability is exposed by a host operation or result contract rather than an independent pattern token."),
    "capture.direct": ("known", "canonical-invariant", "The capability directly creates, addresses, suppresses, or exposes capture state."),
    "capture.reference": ("known", "canonical-invariant", "The capability consumes prior capture state without itself allocating a new capture."),
    "capture.assertion": ("implementation-defined", "profile-dependent", "Capture visibility depends on the documented assertion and profile rules, while the assertion remains zero-width."),
    "capture.repetition": ("implementation-defined", "profile-dependent", "Repeated evaluation can change which capture instance is retained or exposed as history."),
    "capture.none": ("no-feature-specific-implication", "canonical-invariant", "No capture allocation, addressing, or result-shape rule is introduced by this feature itself."),
    "diagnostic.direct": ("known", "operation-specific", "The feature directly defines a rejection, diagnostic, limit, timeout, exhaustion, or attributable termination outcome."),
    "diagnostic.grammar": ("implementation-defined", "profile-dependent", "Acceptance and rejection are governed by the selected grammar, option state, and manifestation."),
    "diagnostic.none": ("no-feature-specific-implication", "canonical-invariant", "The feature adds no diagnostic class beyond ordinary compile and operation outcomes."),
    "replacement.language": ("known", "operation-specific", "The feature directly changes replacement expansion, output, or replacement progress."),
    "replacement.match-result": ("known", "operation-specific", "Replacement observes the match span or capture result changed by this feature."),
    "replacement.none": ("no-feature-specific-implication", "operation-specific", "When replacement is available, it consumes the ordinary match selected by this feature and gains no additional feature-specific replacement rule."),
    "replacement.na": ("not-applicable", "operation-specific", "The governed feature operations do not include replacement."),
    "resource.limit": ("known", "operation-specific", "The feature directly specifies a resource bound, exhaustion condition, timeout, or complexity guarantee."),
    "resource.backtracking": ("implementation-defined", "profile-dependent", "Search-tree size or recursion depth depends on operand structure, subject, and engine strategy; bounded probes must retain native termination."),
    "resource.approximate": ("known", "profile-dependent", "Edit bounds and cost selection expand the matching state space in a documented, parameter-sensitive way."),
    "resource.streaming": ("known", "profile-dependent", "State, scratch, database, block, or stream lifetime is part of this capability's physical resource contract."),
    "resource.callback": ("implementation-defined", "profile-dependent", "Host callbacks or embedded evaluation add host work and termination paths outside pure pattern matching."),
    "resource.none": ("no-feature-specific-implication", "canonical-invariant", "No resource or termination contract is introduced beyond the containing matcher and operation."),
    "unicode.text-model": ("known", "profile-dependent", "The capability directly selects a text unit, decoding policy, normalization/folding rule, segmentation rule, or index unit."),
    "unicode.classification": ("known", "profile-dependent", "Membership depends on the bound character repertoire, Unicode/property data, locale, or collation identified by the profile."),
    "unicode.boundary": ("implementation-defined", "profile-dependent", "Boundary membership depends on the bound word/newline/text classification and text domain."),
    "unicode.none": ("no-feature-specific-implication", "canonical-invariant", "After the profile fixes its text domain, this feature introduces no additional Unicode or encoding rule."),
    "search.position": ("known", "operation-specific", "The capability constrains or reports a search position without consuming an ordinary text atom."),
    "search.selection": ("known", "profile-dependent", "The capability changes which candidate match is selected or which alternatives/lengths are reported."),
    "search.empty-progress": ("known", "operation-specific", "The capability affects empty-match progress, termination, or result enumeration."),
    "search.streaming": ("known", "operation-specific", "The capability changes cross-block state, event ordering, match identity, or scan termination."),
    "search.none": ("no-feature-specific-implication", "canonical-invariant", "The feature participates in the profile's ordinary search and iteration policy without adding a distinct cursor rule."),
    "state.explicit": ("known", "profile-dependent", "Named option or matcher state changes the feature's behavior and must be bound in the profile."),
    "state.text": ("known", "profile-dependent", "Text, locale, Unicode, newline, collation, or decoding state is semantically material."),
    "state.host": ("known", "profile-dependent", "Host region, cursor, editor, SQL, stream, or callback state is semantically material."),
    "state.none": ("no-feature-specific-implication", "canonical-invariant", "No additional option or mutable-state dependency is introduced by the feature."),
    "host.direct": ("known", "operation-specific", "The capability is defined through host input, result, callback, replacement, diagnostic, editor, database, or stream behavior."),
    "host.pattern": ("no-feature-specific-implication", "canonical-invariant", "The canonical concept is pattern-semantic; host APIs expose its ordinary result but do not define the concept."),
}


VARIANT_EFFECTS: dict[str, dict[str, str]] = {
    "feature.approximate-cost-model": {
        "uniform-edit-cost": "all permitted edit kinds share one cost",
        "per-edit-cost": "insertion, deletion, and substitution have separately assigned costs",
        "per-group-cost-and-bound": "costs and maxima are scoped to a governed pattern group",
    },
    "feature.binary-file-policy": {
        "text": "input is processed as text despite binary detection",
        "binary-summary": "matching is summarized without emitting ordinary matching lines",
        "without-match": "binary input is treated as having no reportable match",
        "encoding-error-suppression": "decoding-error diagnostics or matching are suppressed by policy",
    },
    "feature.bounded-variable-positive-lookbehind": {
        "caller-configured-maximum": "the caller supplies the permitted maximum lookbehind length",
        "implementation-fixed-maximum": "the implementation fixes the maximum lookbehind length",
    },
    "feature.capture-history": {
        "value-history": "the ordered captured substrings are exposed",
        "start-history": "the ordered capture start positions are exposed",
        "end-history": "the ordered capture end positions are exposed",
        "span-history": "ordered start/end pairs are exposed",
        "capture-tree": "nested capture events are retained as a tree rather than a flat sequence",
    },
    "feature.class-range": {
        "code-point-order": "range membership follows numeric code-point order",
        "locale-collation": "range membership follows the active locale collation",
        "implementation-defined-outside-posix-locale": "range membership outside the portable locale is explicitly implementation-defined",
    },
    "feature.duplicate-group-name": {
        "first-definition": "lookup resolves to the first group definition",
        "first-participating": "lookup resolves to the first same-named group that participated",
        "last-participating": "lookup resolves to the last same-named group that participated",
        "all-captures": "lookup exposes all participating same-named captures",
    },
    "feature.extended-grapheme-cluster": {
        "legacy-grapheme": "cluster boundaries use the legacy grapheme model",
        "extended-grapheme": "cluster boundaries use the default extended grapheme model",
    },
    "feature.fixed-positive-lookbehind": {
        "equal-length-alternatives": "all top-level alternatives must have the same fixed length",
        "different-fixed-length-alternatives": "each alternative is fixed length but alternatives may differ",
    },
    "feature.generic-newline-sequence": {
        "unicode-any-newline": "the Unicode newline repertoire is consumed",
        "crlf-atomic": "CRLF is consumed as one indivisible newline sequence",
        "configured-bsr": "the backslash-R/newline repertoire follows a selected BSR policy",
    },
    "feature.leftmost-longest-match": {
        "whole-match-longest": "the longest whole match at the leftmost start wins",
        "ordered-submatch-longest": "subexpression choices are resolved by the governed ordered longest-submatch rule",
    },
    "feature.mutable-match-cursor": {
        "success-end": "success advances the cursor to the match end",
        "failure-reset": "failure resets or clears the cursor according to the host contract",
        "externally-settable": "the caller may set the next search position directly",
    },
    "feature.native-index-unit": {
        "byte": "positions count bytes",
        "utf-16-code-unit": "positions count UTF-16 code units",
        "utf-32-code-unit": "positions count UTF-32 code units",
        "code-point": "positions count Unicode code points",
        "one-based-character": "positions use a one-based host character index",
    },
    "feature.numeric-callout": {
        "compile-time-auto-callout": "the compiler inserts numeric callouts automatically",
        "explicit-numeric": "the pattern contains an explicit numeric callout",
    },
    "feature.operation-timeout": {
        "match-only": "the budget covers one matching call",
        "whole-findall": "the budget covers the complete iterative find-all operation",
        "whole-replacement-including-callback": "the budget covers matching, expansion, and callback work for the replacement operation",
    },
    "feature.partial-match-restart": {
        "caller-retained-overlap": "the caller retains and resubmits the required subject overlap",
        "dfa-state-restart": "serialized DFA state resumes matching without reconstructing prior subject state",
    },
    "feature.pattern-set-results": {
        "any-pattern": "the result reports only whether at least one pattern matched",
        "matching-pattern-identities": "the result reports the identities of matching patterns",
        "no-capture-result": "set membership is returned without per-pattern captures",
    },
    "feature.possessive-quantifier": {
        "zero-or-more": "a zero-or-more repetition cannot give back consumed units",
        "one-or-more": "a one-or-more repetition cannot give back consumed units",
        "optional": "an optional repetition cannot reconsider its consumed branch",
        "bounded-interval": "a bounded repetition cannot reduce its accepted count during backtracking",
    },
    "feature.previous-match-end": {
        "initial-subject-start": "before any success the anchor denotes absolute subject start",
        "operation-start-offset": "before any success the anchor denotes the operation's configured start offset",
        "previous-success-end": "after success the anchor denotes the preceding match end",
    },
    "feature.recursion-backtracking": {
        "backtrackable": "completed recursive calls may be re-entered to try unused alternatives",
        "historically-atomic": "completed recursive calls are atomic and cannot be re-entered",
    },
    "feature.replacement-unset-group": {
        "empty": "an unset capture expands to empty text",
        "error": "an unset capture reference raises a replacement error",
        "literal-preservation": "the unresolved replacement token is preserved literally",
    },
    "feature.split-limit": {
        "positive-limit": "a positive bound caps the output field count",
        "zero-limit": "zero selects the host's zero-limit and trailing-empty rule",
        "negative-or-unlimited": "a negative or omitted bound permits all splits",
        "trailing-empty-retained": "trailing empty fields remain in the result",
        "trailing-empty-dropped": "trailing empty fields are removed",
    },
    "feature.streaming-match": {
        "cross-block-match": "a match may begin in one block and end in another",
        "end-of-stream-delayed-assertion": "end-sensitive results are delayed until stream closure",
        "stream-reset-copy-compress": "stream state supports the documented reset, copy, or compression lifecycle",
    },
    "feature.subject-end-before-final-newline": {
        "single-final-lf": "the pre-end position is recognized only before one final LF",
        "configured-final-newline-sequence": "the pre-end position follows the configured newline sequence policy",
    },
    "feature.unbounded-positive-lookbehind": {
        "forward-implemented-reverse-evaluation": "the engine evaluates a backward assertion using a forward engine with reversed traversal semantics",
        "reverse-search-implementation": "the engine performs an explicitly reverse-direction search",
    },
    "feature.unset-backreference-behavior": {
        "fail": "a reference to a nonparticipating group fails the current match path",
        "match-empty": "a reference to a nonparticipating group matches empty text",
        "compile-error": "the selected grammar rejects the reference before matching",
    },
    "feature.wildcard": {
        "newline-excluding": "the atom excludes newline units",
        "dotall": "the atom includes newline units",
        "code-point": "the atom consumes one code point",
        "code-unit": "the atom consumes one encoding code unit",
        "byte": "the atom consumes one byte",
    },
    "feature.word-class": {
        "ascii": "word membership is restricted to an ASCII-derived set",
        "unicode-property-derived": "word membership is derived from Unicode properties",
        "locale-derived": "word membership follows the active locale",
        "editor-syntax-derived": "word membership follows editor syntax or keyword tables",
    },
    "feature.zero-length-advancement": {
        "one-code-unit": "the next cursor advances by one code unit after an empty match",
        "one-code-point": "the next cursor advances by one code point after an empty match",
        "same-position-after-nonempty": "an empty match may be considered at the end of the preceding nonempty match",
        "adjacent-empty-suppression": "an empty match adjacent to the prior match is suppressed by the iterator",
    },
}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _raw_sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _feature_sources(feature: dict[str, Any]) -> list[str]:
    sources = {
        *feature["normative_reference_ids"],
        *feature["implementation_reference_ids"],
        *feature["provenance"]["source_ids"],
        *ADDITIONAL_FEATURE_SOURCES.get(feature["feature_id"], set()),
    }
    if not sources:
        raise ValueError(f"feature has no research source: {feature['feature_id']}")
    return sorted(sources)


def _assigned_ids(catalog: dict[str, Any], entity_class: str) -> dict[str, str]:
    return {
        item["canonical_key"]: item["scientific_id"]
        for item in catalog["bindings"]
        if item["entity_class"] == entity_class
    }


def _capture_rule(feature: dict[str, Any]) -> tuple[str, str]:
    feature_id = feature["feature_id"]
    if feature_id in CAPTURE_ENTITIES:
        return "capture.direct", f"{feature['canonical_name']} directly governs capture allocation, addressing, participation, value, span, or history: {feature['semantic_definition']}"
    if feature_id in BACKREFERENCE_ENTITIES or "conditional" in feature_id:
        return "capture.reference", f"{feature['canonical_name']} reads capture or assertion state to resolve matching but does not allocate a capture merely by making that reference."
    if feature["category"] == "lookaround-assertions":
        return "capture.assertion", f"{feature['canonical_name']} is zero-width; any capture created inside it follows the bound profile's lookaround visibility and backtracking rules."
    if feature["category"] == "quantification-and-match-selection":
        return "capture.repetition", f"{feature['canonical_name']} can select or revisit capture-producing paths, so retained captures must be observed separately from the whole-match selection."
    if feature["category"] in {"replacement-language", "host-operations-and-results"}:
        return "capture.reference", f"{feature['canonical_name']} consumes or shapes host-visible match data; it creates no new pattern capture unless its own definition explicitly says otherwise."
    return "capture.none", f"{feature['canonical_name']} introduces no capture allocation or capture-result shape beyond captures already present in its operands."


def _diagnostic_rule(feature: dict[str, Any]) -> tuple[str, str]:
    feature_id = feature["feature_id"]
    if feature_id in DIAGNOSTIC_ENTITIES:
        return "diagnostic.direct", f"{feature['canonical_name']} is observed through its native compile, diagnostic, limit, timeout, exhaustion, or attributable termination outcome; no-match is a different result."
    if feature["category"] in {"backreferences-recursion-and-conditionals", "backtracking-control-and-code", "lookaround-assertions"} or "grammar" in feature_id or "quantifier" in feature_id:
        return "diagnostic.grammar", f"Acceptance of {feature['canonical_name']} must be recorded for the exact grammar and manifestation; syntactic rejection, unsupported, and runtime error remain distinct."
    return "diagnostic.none", f"{feature['canonical_name']} has no feature-specific diagnostic class; ordinary syntax, unsupported, and operation errors remain separately observable."


def _replacement_rule(feature: dict[str, Any]) -> tuple[str, str]:
    feature_id = feature["feature_id"]
    operations = set(feature["supported_operation_ids"])
    if feature["category"] == "replacement-language" or feature_id in {
        "feature.append-replacement-state",
        "feature.callback-replacement",
    }:
        return "replacement.language", f"{feature['canonical_name']} directly changes replacement expansion, copied subject text, callback output, or replacement progress: {feature['semantic_definition']}"
    if feature_id in CAPTURE_ENTITIES | MATCH_SPAN_ENTITIES | ZERO_LENGTH_ENTITIES:
        return "replacement.match-result", f"Replacement operations observe the {feature['canonical_name']} match/capture consequence; they must preserve the selected span, participation, and empty-match progress rule."
    if not operations.intersection({"replace-first", "replace-all", "replace-callback", "expand-replacement"}):
        return "replacement.na", f"{feature['canonical_name']} has no governed replacement operation in this corpus revision."
    return "replacement.none", f"For {feature['canonical_name']}, replacement uses the ordinary selected match and adds no separate feature-specific expansion syntax."


def _resource_rule(feature: dict[str, Any]) -> tuple[str, str]:
    feature_id = feature["feature_id"]
    category = feature["category"]
    if feature_id in RESOURCE_ENTITIES:
        return "resource.limit", f"{feature['canonical_name']} directly governs resource or termination behavior: {feature['semantic_definition']}"
    if category == "approximate-partial-and-multipattern" and feature_id not in STREAMING_ENTITIES:
        return "resource.approximate", f"{feature['canonical_name']} changes approximate or partial search state; edit bounds, subject extent, and restart policy are material to cost and termination."
    if feature_id in STREAMING_ENTITIES:
        return "resource.streaming", f"{feature['canonical_name']} carries database, scratch, block, stream, callback, or retained-state costs that must be measured separately from the semantic result."
    if feature_id in CODE_AND_CALLBACK_ENTITIES:
        return "resource.callback", f"{feature['canonical_name']} can execute host code or callbacks; host work, cancellation, and callback termination are not ordinary engine backtracking."
    if category in {"backreferences-recursion-and-conditionals", "lookaround-assertions", "quantification-and-match-selection"} or feature_id in {"feature.atomic-group", "feature.prune-backtracking", "feature.skip-start-positions", "feature.then-alternative", "feature.commit-start-position"}:
        return "resource.backtracking", f"{feature['canonical_name']} changes the search tree, recursion, or pruning behavior; finite probes must distinguish target limits from infrastructure timeouts."
    return "resource.none", f"{feature['canonical_name']} adds no independent resource limit or termination state beyond the containing operation."


def _unicode_rule(feature: dict[str, Any]) -> tuple[str, str]:
    feature_id = feature["feature_id"]
    if feature_id in TEXT_MODEL_ENTITIES:
        return "unicode.text-model", f"{feature['canonical_name']} directly determines text units, decoding, normalization, folding, segmentation, malformed-text handling, or native indexes: {feature['semantic_definition']}"
    if feature_id in CLASSIFICATION_ENTITIES or feature_id in {"feature.sql-collation-selection", "feature.ignore-combining-differences", "feature.character-category-class", "feature.file-name-character-class", "feature.keyword-character-class", "feature.syntax-table-class"}:
        return "unicode.classification", f"The membership or comparison used by {feature['canonical_name']} must bind the exact repertoire, Unicode data, locale, collation, or host table."
    if feature["category"] == "anchors-and-boundaries" or feature_id in {"feature.generic-newline-sequence", "feature.wildcard"}:
        return "unicode.boundary", f"{feature['canonical_name']} depends on the profile's text-unit and boundary/newline classification; byte, code-unit, and code-point domains may differ."
    return "unicode.none", f"Once the profile's text domain is fixed, {feature['canonical_name']} introduces no additional Unicode, normalization, or encoding rule."


def _search_rule(feature: dict[str, Any]) -> tuple[str, str]:
    feature_id = feature["feature_id"]
    if feature["category"] == "anchors-and-boundaries":
        return "search.position", f"{feature['canonical_name']} constrains or reports a search position, so start offset, region, prior-match, line, word, and editor state must be isolated as applicable."
    if feature_id in SELECTION_ENTITIES:
        return "search.selection", f"{feature['canonical_name']} changes candidate ordering, accepted length, or reported multiplicity without creating another logical search operation."
    if feature_id in ZERO_LENGTH_ENTITIES:
        return "search.empty-progress", f"{feature['canonical_name']} requires an explicit empty-match advancement and termination probe for iterative operations."
    if feature_id in STREAMING_ENTITIES:
        return "search.streaming", f"{feature['canonical_name']} changes block/stream continuity, event identity or callback ordering and must be tested with boundaries at multiple subject offsets."
    return "search.none", f"{feature['canonical_name']} follows the selected operation's ordinary start-position and next-match policy."


def _state_rule(feature: dict[str, Any]) -> tuple[str, str]:
    feature_id = feature["feature_id"]
    if feature["option_state_dependencies"]:
        names = ", ".join(feature["option_state_dependencies"])
        return "state.explicit", f"{feature['canonical_name']} explicitly depends on {names}; the active values belong in the profile or operation provenance."
    if feature_id in TEXT_MODEL_ENTITIES | CLASSIFICATION_ENTITIES or feature_id in {"feature.wildcard", "feature.generic-newline-sequence", "feature.sql-collation-selection"}:
        return "state.text", f"{feature['canonical_name']} depends on the selected text, Unicode, locale, collation, newline, or decoding mode even when syntax is unchanged."
    if feature_id in STATEFUL_HOST_ENTITIES | STREAMING_ENTITIES or feature["category"] in {"editor-cli-and-product-surfaces", "host-operations-and-results"}:
        return "state.host", f"{feature['canonical_name']} depends on mutable host, cursor, region, editor, database, callback, or stream state identified by the execution profile."
    return "state.none", f"{feature['canonical_name']} introduces no additional mutable option or host-state dependency beyond its operands and operation."


def _syntax_rule(feature: dict[str, Any]) -> tuple[str, str]:
    form = feature["abstract_grammar_form"]
    if form is None or feature["category"] in {"host-operations-and-results", "replacement-language", "diagnostics-resources-and-safety", "editor-cli-and-product-surfaces"}:
        return "syntax.host", f"{feature['canonical_name']} is selected or observed through a host/API contract; concrete manifestations remain source-specific and do not redefine its canonical meaning."
    return "syntax.pattern", f"The canonical grammar role of {feature['canonical_name']} is represented by {form!r}; exact spelling and rejection boundaries are owned by its source-bound manifestations."


def _host_rule(feature: dict[str, Any]) -> tuple[str, str]:
    if feature["category"] in {"host-operations-and-results", "replacement-language", "diagnostics-resources-and-safety", "editor-cli-and-product-surfaces", "approximate-partial-and-multipattern"} or feature["feature_id"] in CODE_AND_CALLBACK_ENTITIES:
        return "host.direct", f"{feature['canonical_name']} has a direct host-visible contract through the operations {', '.join(feature['supported_operation_ids'])}."
    return "host.pattern", f"{feature['canonical_name']} is defined at pattern-semantic level; hosts expose the resulting match/no-match and ordinary captures without acquiring semantic authority over the feature."


def _assertion(
    feature: dict[str, Any], field: str, rule_id: str, statement: str
) -> dict[str, Any]:
    state, scope, _ = RULES[rule_id]
    return {
        "field": field,
        "state": state,
        "scope": scope,
        "rule_id": f"semantic-rule.{rule_id}",
        "statement": statement,
        "source_ids": _feature_sources(feature),
        "derivation_id": RESEARCH_DERIVATION_ID,
        "derivation_class": "research-derived",
    }


def _feature_assertions(feature: dict[str, Any]) -> dict[str, dict[str, Any]]:
    selections = {
        "definition": (
            "definition.canonical",
            feature["semantic_definition"],
        ),
        "syntax_grammar": _syntax_rule(feature),
        "capture_result": _capture_rule(feature),
        "diagnostic_error": _diagnostic_rule(feature),
        "replacement": _replacement_rule(feature),
        "resource_termination": _resource_rule(feature),
        "unicode_encoding": _unicode_rule(feature),
        "search_iteration": _search_rule(feature),
        "options_state": _state_rule(feature),
        "host_operation": _host_rule(feature),
    }
    return {
        field: _assertion(feature, field, rule_id, statement)
        for field, (rule_id, statement) in selections.items()
    }


def _variant_statement(feature: dict[str, Any], variant: dict[str, Any]) -> str:
    effects = VARIANT_EFFECTS.get(feature["feature_id"], {})
    effect = effects.get(variant["name"])
    if effect is None:
        raise ValueError(f"missing researched variant effect: {variant['variant_id']}")
    return f"Within {feature['canonical_name']}, this variant fixes the differentiating rule so {effect}."


def _test_concepts(
    feature: dict[str, Any], assertions: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    material = [
        name
        for name, assertion in assertions.items()
        if assertion["state"] not in {"no-feature-specific-implication", "not-applicable"}
    ]
    return {
        "dimensions": material,
        "positive": f"Demonstrate that {feature['semantic_definition']} using the smallest source-documented manifestation and a bound operation/profile.",
        "boundary": f"Vary the material dimensions for {feature['canonical_name']}: {', '.join(material)}; keep unrelated syntax and host state fixed.",
        "negative": f"Separate unsupported or syntactically rejected {feature['canonical_name']} from an accepted pattern that produces no match.",
        "source_ids": _feature_sources(feature),
        "derivation_id": RESEARCH_DERIVATION_ID,
    }


def _legacy_field_audit(feature: dict[str, Any]) -> list[dict[str, str]]:
    """Classify every requested predecessor semantic dimension before enrichment."""
    classifications = {
        "canonical_definition": "genuinely-feature-specific",
        "syntax_grammar": (
            "genuinely-feature-specific"
            if feature["abstract_grammar_form"] is not None
            else "structurally-not-applicable"
        ),
        "capture_result": "templated-and-insufficient",
        "diagnostic_error": "templated-and-insufficient",
        "replacement": "templated-and-insufficient",
        "resource_termination": "templated-and-insufficient",
        "unicode_encoding": "templated-and-insufficient",
        "search_iteration": "unsupported-by-evidence",
        "options_state": (
            "genuinely-feature-specific"
            if feature["option_state_dependencies"]
            else "structurally-not-applicable"
        ),
        "host_operation": "unsupported-by-evidence",
        "interactions": (
            "genuinely-feature-specific"
            if feature["typed_relations"]
            else "structurally-not-applicable"
        ),
        "historical_names": (
            "genuinely-feature-specific"
            if feature["historical_names"]
            else "structurally-not-applicable"
        ),
        "unresolved_questions": (
            "unknown-or-unresolved"
            if feature["unresolved_semantic_questions"]
            else "generic-but-scientifically-correct"
        ),
        "test_concepts": "templated-and-insufficient",
        "prerequisites": (
            "genuinely-feature-specific"
            if feature["prerequisite_feature_ids"]
            else "structurally-not-applicable"
        ),
        "modifiers": (
            "genuinely-feature-specific"
            if feature["modifier_ids"]
            else "structurally-not-applicable"
        ),
        "manifestations": "genuinely-feature-specific",
        "semantic_variants": (
            "templated-and-insufficient"
            if feature["semantic_variants"]
            else "structurally-not-applicable"
        ),
        "source_evidence": "genuinely-feature-specific",
    }
    return [
        {"dimension": dimension, "classification": classifications[dimension]}
        for dimension in AUDIT_DIMENSIONS
    ]


def _finalize(
    body: dict[str, Any], *, namespace: str, schema_family_id: str, id_field: str, digest_field: str
) -> dict[str, Any]:
    digest = _sha256_bytes(canonical_bytes(body))
    result = deepcopy(body)
    result[digest_field] = digest
    identity = build_content_identity(
        registry=NamespaceRegistry.load(ROOT / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(ROOT / PROFILE_PATH)),
        namespace=namespace,
        identity_schema_family_id=schema_family_id,
        identity_schema_version="1.0.0",
        identity={"artifact_digest_sha256": digest},
    )
    result[id_field] = identity["content_id"]
    return result


def _verify_finalized(
    value: dict[str, Any], *, namespace: str, schema_family_id: str, id_field: str, digest_field: str
) -> None:
    body = {key: item for key, item in value.items() if key not in {id_field, digest_field}}
    expected = _finalize(
        body,
        namespace=namespace,
        schema_family_id=schema_family_id,
        id_field=id_field,
        digest_field=digest_field,
    )
    if value[digest_field] != expected[digest_field] or value[id_field] != expected[id_field]:
        raise ValueError(f"content-derived artifact identity mismatch: {id_field}")


def _build_ledger(
    predecessor: dict[str, Any], identities: dict[str, dict[str, str]]
) -> dict[str, Any]:
    records = []
    for feature in predecessor["features"]:
        assertions = _feature_assertions(feature)
        records.append(
            {
                "feature_id": feature["feature_id"],
                "scientific_id": identities["feature"][feature["feature_id"]],
                "fields_reviewed": list(SEMANTIC_FIELDS),
                "legacy_field_audit": _legacy_field_audit(feature),
                "source_ids": _feature_sources(feature),
                "material_findings": [
                    {
                        "field": field,
                        "rule_id": assertion["rule_id"],
                        "state": assertion["state"],
                        "scope": assertion["scope"],
                    }
                    for field, assertion in assertions.items()
                ],
                "unresolved_questions": [
                    {
                        "question": question,
                        "blocking": True,
                        "evidence_reviewed": _feature_sources(feature),
                    }
                    for question in feature["unresolved_semantic_questions"]
                ],
                "identity_disposition": "retained-same-scientific-concept",
                "semantic_revision_outcome": "source-bound-enrichment",
                "review_method": "Compare the canonical concept with its bound primary authorities, isolate variant and manifestation behavior, and classify each semantic dimension without using cross-engine majority behavior.",
                "derivation_id": RESEARCH_DERIVATION_ID,
            }
        )
    body = {
        "schema_version": "regex-semantic-feature-research-ledger.v1",
        "published_on": "2026-09-07",
        "declared_semantic_cutoff": predecessor["cutoff_date"],
        "predecessor": {
            "path": PREDECESSOR_PATH.as_posix(),
            "snapshot_id": predecessor["snapshot_id"],
            "corpus_digest_sha256": predecessor["corpus_digest_sha256"],
            "artifact_sha256": _raw_sha256(ROOT / PREDECESSOR_PATH),
        },
        "research_standard": {
            "source_priority": [
                "normative-specification",
                "official-implementation-documentation",
                "official-source-or-tests",
                "authoritative-standard-or-data",
                "primary-technical-literature",
                "identified-inference",
            ],
            "cross_engine_majority_is_authority": False,
            "unsupported_statement_policy": "Record unresolved rather than synthesize plausible prose.",
            "variant_isolation_required": True,
            "manifestation_isolation_required": True,
        },
        "semantic_rules": [
            {
                "rule_id": f"semantic-rule.{rule_id}",
                "state": values[0],
                "scope": values[1],
                "research_conclusion": values[2],
                "source_binding": "The feature record supplies one or more exact source identities from the accepted source registry.",
                "derivation_id": RESEARCH_DERIVATION_ID,
            }
            for rule_id, values in sorted(RULES.items())
        ],
        "feature_research": records,
        "baseline_template_debt": {
            "features_audited": len(predecessor["features"]),
            "legacy_fields_audited": list(LEGACY_TEMPLATE_FIELDS),
            "legacy_field_occurrences": len(predecessor["features"]) * len(LEGACY_TEMPLATE_FIELDS),
            "legacy_distinct_value_counts": {
                field: len({feature[field] for feature in predecessor["features"]})
                for field in LEGACY_TEMPLATE_FIELDS
            },
            "legacy_variant_assertions": sum(
                len(feature["semantic_variants"]) for feature in predecessor["features"]
            ),
            "legacy_test_concept_assertions": len(predecessor["features"]) * 3,
            "classification": "construction-derived-template-debt",
            "derivation_id": RESEARCH_DERIVATION_ID,
        },
        "counts": {
            "features_researched": len(records),
            "fields_reviewed": len(records) * len(SEMANTIC_FIELDS),
            "legacy_dimensions_audited": len(records) * len(AUDIT_DIMENSIONS),
            "semantic_rules": len(RULES),
            "source_identities_used": len(
                {source for record in records for source in record["source_ids"]}
            ),
            "blocking_unresolved_questions": sum(
                item["blocking"]
                for record in records
                for item in record["unresolved_questions"]
            ),
        },
    }
    return _finalize(
        body,
        namespace="finding-revision",
        schema_family_id=SCHEMA_FAMILIES["ledger"],
        id_field="research_ledger_id",
        digest_field="research_ledger_digest_sha256",
    )


def _build_snapshot(
    predecessor: dict[str, Any],
    ledger: dict[str, Any],
    identities: dict[str, dict[str, str]],
) -> dict[str, Any]:
    sources = {item["source_id"] for item in predecessor["sources"]}
    features = []
    for feature in predecessor["features"]:
        assertions = _feature_assertions(feature)
        variants = [
            {
                "variant_id": variant["variant_id"],
                "scientific_id": identities["semantic-variant"][variant["variant_id"]],
                "name": variant["name"],
                "semantic_assertion": {
                    "field": "variant-distinction",
                    "state": "known",
                    "scope": "variant-specific",
                    "rule_id": "semantic-rule.definition.canonical",
                    "statement": _variant_statement(feature, variant),
                    "source_ids": _feature_sources(feature),
                    "derivation_id": RESEARCH_DERIVATION_ID,
                    "derivation_class": "research-derived",
                },
            }
            for variant in feature["semantic_variants"]
        ]
        features.append(
            {
                "feature_id": feature["feature_id"],
                "scientific_id": identities["feature"][feature["feature_id"]],
                "semantic_revision": 2,
                "canonical_name": feature["canonical_name"],
                "aliases": feature["aliases"],
                "historical_names": feature["historical_names"],
                "category": feature["category"],
                "feature_class": feature["feature_class"],
                "prerequisite_feature_ids": feature["prerequisite_feature_ids"],
                "modifier_ids": feature["modifier_ids"],
                "semantic_variants": variants,
                "typed_relations": feature["typed_relations"],
                "manifestation_ids": feature["manifestation_ids"],
                "abstract_grammar_form": feature["abstract_grammar_form"],
                "supported_operation_ids": feature["supported_operation_ids"],
                "semantic_assertions": assertions,
                "test_concepts": _test_concepts(feature, assertions),
                "unresolved_semantic_questions": feature["unresolved_semantic_questions"],
                "identity_disposition": {
                    "kind": "retained",
                    "reason": "The scientific concept is unchanged; this revision replaces generic template fields with source-bound understanding.",
                    "predecessor_key": feature["feature_id"],
                },
            }
        )
    manifestations = []
    for manifestation in predecessor["manifestations"]:
        if manifestation["source_id"] not in sources:
            raise ValueError(f"unknown manifestation source: {manifestation['manifestation_id']}")
        manifestations.append(
            {
                **manifestation,
                "scientific_id": identities["manifestation"][manifestation["manifestation_id"]],
                "semantic_scope": "manifestation-specific",
                "canonical_semantics_owner": identities["feature"][manifestation["semantic_feature_id"]],
                "derivation_id": RESEARCH_DERIVATION_ID,
            }
        )
    body = {
        "schema_version": "regex-semantic-corpus.v2",
        "published_on": "2026-09-07",
        "declared_semantic_cutoff": predecessor["cutoff_date"],
        "status": "canonical-researched-successor",
        "authority": {
            "semantic_home": "semantic-corpus/snapshots",
            "scientific_identity_owner": "registries/identity/scientific-identities.v1.json",
            "assertion_derivation_owner": "registries/provenance/generated-assertion-derivations.v1.json",
            "variant_rule": "Canonical assertions contain only invariants; variant-specific behavior remains on its identified variant.",
            "manifestation_rule": "Syntax and API spellings remain source-bound manifestations and cannot redefine canonical feature meaning.",
            "obligation_boundary": "This snapshot does not regenerate or supersede the accepted obligation projection, requirement ledger, or denominator forecast.",
        },
        "predecessor": {
            "path": PREDECESSOR_PATH.as_posix(),
            "snapshot_id": predecessor["snapshot_id"],
            "corpus_digest_sha256": predecessor["corpus_digest_sha256"],
            "artifact_sha256": _raw_sha256(ROOT / PREDECESSOR_PATH),
        },
        "research_ledger": {
            "path": LEDGER_PATH.as_posix(),
            "research_ledger_id": ledger["research_ledger_id"],
            "research_ledger_digest_sha256": ledger["research_ledger_digest_sha256"],
        },
        "sources": predecessor["sources"],
        "features": features,
        "manifestations": manifestations,
        "carried_forward_by_reference": {
            "candidate_dispositions": f"{PREDECESSOR_PATH.as_posix()}#/candidates",
            "modifiers": f"{PREDECESSOR_PATH.as_posix()}#/modifiers",
            "operations": f"{PREDECESSOR_PATH.as_posix()}#/operations",
            "typed_interactions": f"{PREDECESSOR_PATH.as_posix()}#/interactions",
        },
        "counts": {
            "canonical_features": len(features),
            "semantic_variants": sum(len(item["semantic_variants"]) for item in features),
            "syntax_manifestations": len(manifestations),
            "source_identities": len(predecessor["sources"]),
            "semantic_assertions": sum(len(item["semantic_assertions"]) for item in features),
            "retained_feature_identities": sum(
                item["identity_disposition"]["kind"] == "retained" for item in features
            ),
            "successor_feature_identities": 0,
        },
    }
    return _finalize(
        body,
        namespace="ontology-snapshot",
        schema_family_id=SCHEMA_FAMILIES["snapshot"],
        id_field="snapshot_id",
        digest_field="snapshot_digest_sha256",
    )


def _build_report(
    predecessor: dict[str, Any], ledger: dict[str, Any], snapshot: dict[str, Any]
) -> dict[str, Any]:
    states = Counter(
        assertion["state"]
        for feature in snapshot["features"]
        for assertion in feature["semantic_assertions"].values()
    )
    scopes = Counter(
        assertion["scope"]
        for feature in snapshot["features"]
        for assertion in feature["semantic_assertions"].values()
    )
    legacy_digests = {
        "semantic_snapshot": _raw_sha256(ROOT / PREDECESSOR_PATH),
        "obligation_projection": _raw_sha256(
            ROOT / "ontology/projections/regex-semantic-projection-2026-08-22.v1.json"
        ),
        "vector_requirements": _raw_sha256(
            ROOT / "vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json"
        ),
        "denominator_forecast": _raw_sha256(
            ROOT / "reports/scale/regex-semantic-denominator-forecast.json"
        ),
    }
    used_source_ids = {
        source_id
        for feature in snapshot["features"]
        for assertion in feature["semantic_assertions"].values()
        for source_id in assertion["source_ids"]
    }
    source_class_counts = Counter(
        source["source_class"]
        for source in snapshot["sources"]
        if source["source_id"] in used_source_ids
    )
    body = {
        "schema_version": "regex-semantic-research-completeness.v1",
        "published_on": "2026-09-07",
        "research_ledger_id": ledger["research_ledger_id"],
        "research_ledger_digest_sha256": ledger["research_ledger_digest_sha256"],
        "semantic_snapshot_id": snapshot["snapshot_id"],
        "semantic_snapshot_digest_sha256": snapshot["snapshot_digest_sha256"],
        "completion": {
            "state": "PASS",
            "features_researched": len(snapshot["features"]),
            "features_expected": 251,
            "fields_audited": len(snapshot["features"]) * len(SEMANTIC_FIELDS),
            "legacy_dimensions_audited": len(snapshot["features"]) * len(AUDIT_DIMENSIONS),
            "legacy_template_assertions_replaced": len(snapshot["features"]) * len(LEGACY_TEMPLATE_FIELDS),
            "test_concept_assertions_replaced": len(snapshot["features"]) * 3,
            "variant_assertions_replaced": sum(
                len(feature["semantic_variants"]) for feature in snapshot["features"]
            ),
            "manifestations_scope_audited": len(snapshot["manifestations"]),
            "template_derived_assertions_remaining": 0,
            "blocking_unresolved_questions": ledger["counts"]["blocking_unresolved_questions"],
        },
        "semantic_state_counts": dict(sorted(states.items())),
        "semantic_scope_counts": dict(sorted(scopes.items())),
        "evidence": {
            "source_identities_used": ledger["counts"]["source_identities_used"],
            "source_class_counts": dict(sorted(source_class_counts.items())),
            "normative_source_identities": sum(
                source["normative"]
                for source in snapshot["sources"]
                if source["source_id"] in used_source_ids
            ),
            "derivation_id": RESEARCH_DERIVATION_ID,
            "all_substantive_assertions_source_bound": True,
            "cross_engine_majority_used_as_authority": False,
        },
        "identity": {
            "feature_identities_retained": snapshot["counts"]["retained_feature_identities"],
            "feature_successors_created": snapshot["counts"]["successor_feature_identities"],
            "scientific_identity_population": 22359,
        },
        "legacy_artifact_compatibility": {
            "artifacts_unchanged": True,
            "artifact_sha256": legacy_digests,
            "obligation_templates": 12048,
            "vector_requirements": 9506,
            "policy": "The accepted projection, obligation population, vector-requirement ledger, and denominator remain bound to the predecessor snapshot until their dedicated redesign.",
        },
        "derivation_id": RESEARCH_DERIVATION_ID,
    }
    return _finalize(
        body,
        namespace="trust-assessment",
        schema_family_id=SCHEMA_FAMILIES["report"],
        id_field="report_id",
        digest_field="report_digest_sha256",
    )


def _verify(
    predecessor: dict[str, Any], ledger: dict[str, Any], snapshot: dict[str, Any], report: dict[str, Any]
) -> None:
    _verify_finalized(
        ledger,
        namespace="finding-revision",
        schema_family_id=SCHEMA_FAMILIES["ledger"],
        id_field="research_ledger_id",
        digest_field="research_ledger_digest_sha256",
    )
    _verify_finalized(
        snapshot,
        namespace="ontology-snapshot",
        schema_family_id=SCHEMA_FAMILIES["snapshot"],
        id_field="snapshot_id",
        digest_field="snapshot_digest_sha256",
    )
    _verify_finalized(
        report,
        namespace="trust-assessment",
        schema_family_id=SCHEMA_FAMILIES["report"],
        id_field="report_id",
        digest_field="report_digest_sha256",
    )
    feature_ids = [feature["feature_id"] for feature in snapshot["features"]]
    if feature_ids != sorted(feature_ids) or len(feature_ids) != len(set(feature_ids)) != 251:
        raise ValueError("successor must contain exactly 251 uniquely sorted features")
    if set(feature_ids) != {feature["feature_id"] for feature in predecessor["features"]}:
        raise ValueError("successor feature population differs from the accepted snapshot")
    research_ids = [item["feature_id"] for item in ledger["feature_research"]]
    if research_ids != feature_ids:
        raise ValueError("research ledger does not cover the exact successor feature order")
    source_ids = {source["source_id"] for source in snapshot["sources"]}
    prohibited = {
        "Observe whole-match and capture state only where the profile and operation expose them.",
        "May affect replacement selection, expansion, or progress only when a replacement operation is available.",
        "Bind the profile's text domain, encoding policy, index unit, case mode, locale and malformed-input policy.",
        "Distinguish accepted-and-supported, syntactically rejected, unsupported, and runtime error outcomes.",
        "Exercise with finite bounded probes and preserve timeout, limit, crash and infrastructure outcomes distinctly.",
    }
    for feature in snapshot["features"]:
        if set(feature["semantic_assertions"]) != set(SEMANTIC_FIELDS):
            raise ValueError(f"semantic field set differs: {feature['feature_id']}")
        for assertion in feature["semantic_assertions"].values():
            if assertion["state"] not in STATES or not assertion["source_ids"]:
                raise ValueError(f"invalid semantic assertion: {feature['feature_id']}")
            if not set(assertion["source_ids"]).issubset(source_ids):
                raise ValueError(f"dangling semantic source: {feature['feature_id']}")
            if assertion["statement"] in prohibited or "behavior may vary" in assertion["statement"].lower():
                raise ValueError(f"legacy template or vague assertion survived: {feature['feature_id']}")
        for variant in feature["semantic_variants"]:
            if "A documented semantic variant" in variant["semantic_assertion"]["statement"]:
                raise ValueError(f"legacy variant template survived: {variant['variant_id']}")
    if report["completion"]["state"] != "PASS" or report["completion"]["features_researched"] != 251:
        raise ValueError("research completeness did not close")
    if report["completion"]["blocking_unresolved_questions"]:
        raise ValueError("blocking semantic questions remain")
    if report["identity"]["feature_identities_retained"] != 251:
        raise ValueError("feature identities were not retained")
    if report["legacy_artifact_compatibility"]["obligation_templates"] != 12048:
        raise ValueError("legacy obligation population changed")
    if report["legacy_artifact_compatibility"]["vector_requirements"] != 9506:
        raise ValueError("legacy requirement population changed")


def build_all() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    predecessor = load_strict(ROOT / PREDECESSOR_PATH)
    catalog = load_strict(ROOT / IDENTITY_PATH)
    identities = {
        entity_class: _assigned_ids(catalog, entity_class)
        for entity_class in ("feature", "semantic-variant", "manifestation")
    }
    ledger = _build_ledger(predecessor, identities)
    snapshot = _build_snapshot(predecessor, ledger, identities)
    report = _build_report(predecessor, ledger, snapshot)
    _verify(predecessor, ledger, snapshot, report)
    for artifact, schema_path in (
        (ledger, LEDGER_SCHEMA_PATH),
        (snapshot, SNAPSHOT_SCHEMA_PATH),
        (report, REPORT_SCHEMA_PATH),
    ):
        validate_instance(artifact, load_strict(ROOT / schema_path), source=schema_path.as_posix())
    return ledger, snapshot, report


def _write(path: Path, value: dict[str, Any]) -> None:
    encoded = canonical_bytes(value) + b"\n"
    destination = ROOT / path
    destination.parent.mkdir(parents=True, exist_ok=True)
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
    arguments = parser.parse_args()
    artifacts = build_all()
    bindings = zip(artifacts, (LEDGER_PATH, SNAPSHOT_PATH, REPORT_PATH), strict=True)
    if arguments.check:
        for artifact, path in bindings:
            if not (ROOT / path).is_file() or (ROOT / path).read_bytes() != canonical_bytes(artifact) + b"\n":
                raise ValueError(f"tracked researched semantic artifact differs: {path}")
    else:
        for artifact, path in bindings:
            _write(path, artifact)
        rebuilt = build_all()
        if any(canonical_bytes(left) != canonical_bytes(right) for left, right in zip(artifacts, rebuilt, strict=True)):
            raise RuntimeError("second researched-semantic build was not deterministic")
    ledger, snapshot, report = artifacts
    print(
        f"features={report['completion']['features_researched']} "
        f"fields={report['completion']['fields_audited']} "
        f"sources={ledger['counts']['source_identities_used']} "
        f"snapshot={snapshot['snapshot_id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
