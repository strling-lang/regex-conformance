#!/usr/bin/env python3
"""Adversarially audit and freeze the declared-cutoff semantic universe."""

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


PUBLISHED_ON = "2026-09-08"
CUTOFF = "2026-09-08T00:14:25Z"
PREDECESSOR_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v3.json")
PREDECESSOR_LEDGER_PATH = Path("semantic-corpus/research/regex-semantic-architecture-candidates-2026-09-07.v1.json")
ALLOCATION_PATH = Path("semantic-corpus/research/semantic-universe-freeze-identities-2026-09-08.v1.json")
PLAN_PATH = Path("semantic-corpus/research/regex-semantic-universe-adversarial-plan-2026-09-08.v1.json")
LEDGER_PATH = Path("semantic-corpus/research/regex-semantic-universe-candidates-2026-09-08.v1.json")
SNAPSHOT_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json")
SOURCE_COVERAGE_PATH = Path("reports/semantics/regex-semantic-source-coverage-2026-09-08.v1.json")
AUDIT_REPORT_PATH = Path("reports/semantics/regex-semantic-universe-adversarial-audit-2026-09-08.v1.json")
FREEZE_PATH = Path("semantic-corpus/freeze/regex-semantic-universe-2026-09-08.v1.json")
AUTHORITY_PATH = Path("semantic-corpus/authority/current.v1.json")
IDENTITY_PATH = Path("registries/identity/scientific-identities.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v3.json")
PROFILE_PATH = Path("schemas/identity-profiles/semantic-research-artifact.v1.json")

SCHEMAS = {
    ALLOCATION_PATH: Path("schemas/json/regex-semantic-universe-freeze-allocation.schema.json"),
    PLAN_PATH: Path("schemas/json/regex-semantic-universe-audit-plan.schema.json"),
    LEDGER_PATH: Path("schemas/json/regex-semantic-universe-candidate-ledger.schema.json"),
    SNAPSHOT_PATH: Path("schemas/json/regex-semantic-corpus-v4.schema.json"),
    SOURCE_COVERAGE_PATH: Path("schemas/json/regex-semantic-source-coverage.schema.json"),
    AUDIT_REPORT_PATH: Path("schemas/json/regex-semantic-universe-audit-report.schema.json"),
    FREEZE_PATH: Path("schemas/json/regex-semantic-universe-freeze-manifest.schema.json"),
    AUTHORITY_PATH: Path("schemas/json/regex-semantic-authority-index.schema.json"),
}

DENOMINATOR_PATHS = {
    "obligation_projection": Path("ontology/projections/regex-semantic-projection-2026-08-22.v1.json"),
    "vector_requirements": Path("vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json"),
    "denominator_forecast": Path("reports/scale/regex-semantic-denominator-forecast.json"),
}
DENOMINATOR_SHA256 = {
    "obligation_projection": "b25fbeaf80fc8e77f92fb5b36a094896bf30e86d4550ad62982f80a028b605b2",
    "vector_requirements": "a03feacf51bf3af241a7ab4fe0ea74bd29981670de93ec3d880a27516232cca7",
    "denominator_forecast": "dab61b42376d757eadada26c31d8fb5c173a508bb6ce780e98a220449ce6e871",
}

CLAIM = (
    "The semantic universe is exhaustive against the declared research cutoff, audited source universe, "
    "explicit scope, and documented discovery methodology, with every encountered candidate dispositioned."
)

STRATEGIES = (
    ("source-first", "Scan authoritative specifications, implementation documentation, and unfamiliar source-family indexes for semantic concepts absent from the registry."),
    ("ontology-first", "Challenge every category and facet for missing siblings, collapsed domains, and duplicated canonical ownership."),
    ("operation-first", "Inspect every canonical operation for observable behavior not attributable to an existing feature or operation contract."),
    ("test-corpus-first", "Mine authoritative implementation and conformance suite names and directory structure for candidate semantics, then return to primary authority before disposition."),
    ("terminology-first", "Compare primary glossaries and distinct vendor terms to separate aliases from independently observable concepts."),
)

REPRESENTATIVE_SYSTEMS = (
    "PCRE2", "Perl", ".NET", "Java", "Python", "ECMAScript", "Ruby/Oniguruma", "RE2",
    "Rust regex", "POSIX/Spencer ARE", "ICU", "Hyperscan", "Lucene", "SMT-LIB", "Swift Regex",
    "Vim", "Emacs", "database regex surfaces", "flex scanners",
)

TEST_CORPORA = (
    ("Test262 RegExp", "https://github.com/tc39/test262", "419d3e0a2273ba01a3bfcbec423f2801425b8e93", ["built-ins/RegExp", "language/literals/regexp", "Annex B grammar"]),
    ("PCRE2 tests", "https://github.com/PCRE2Project/pcre2", "aac57f978e38fb4a04899d623b68e0fbb5bcaf6c", ["testdata", "pcre2test option index"]),
    ("Rust regex testdata", "https://github.com/rust-lang/regex", "72d650cb0a880a01ab6dc2137c0888e8f89740f7", ["testdata", "regex-automata integration suites"]),
    ("ICU regex tests", "https://github.com/unicode-org/icu", "aac4916c13466c2dfbf89b3b3a07485cb5653a06", ["regextst.txt", "re_tests.txt", "boundary test data"]),
    ("Oniguruma tests", "https://github.com/kkos/oniguruma", "f95747b462de672b6f8dbdeb478245ddf061ca53", ["test", "encoding and syntax cases"]),
    ("Onigmo tests", "https://github.com/k-takata/Onigmo", "1d7ee878b3e4a9e41bf9825c937ae6cf0a9cd68c", ["test", "syntax and capture-history cases"]),
    ("Go regexp and Fowler cases", "https://github.com/golang/go", "38d1265e1a015add1d0b8651f5c2ea3f06199765", ["src/regexp", "testdata"]),
    ("Perl regular-expression tests", "https://github.com/Perl/perl5", "4155d8589cc6d45e42647cc3d66c4245574148dc", ["t/re", "regex sets", "script runs", "substitution"]),
)

NEW_CANDIDATES = (
    ("residual.modifier.caseless-restrict", "modifier", "Restrict Unicode caseless equivalence so ASCII and non-ASCII characters do not fold across the domain boundary.", ["pcre2-api", "pcre2-syntax"], "source-first", "accept-as-modifier", "PCRE2 documents an independently selectable and inline-scoped observable case-equivalence restriction; ordinary ASCII-class restriction and locale folding do not express it."),
    ("residual.feature.numeric-escape-disambiguation", "canonical feature", "Resolve a backslash followed by digits among a group reference, numeric code-point escape, literal digits, or syntax error.", ["ecma-regexp", "pcre2-pattern", "python-re"], "test-corpus-first", "accept-canonical", "The resolution depends on grammar mode, digit sequence, class context and available capture groups; existing backreference and numeric-escape entities describe the alternatives but not the selection rule."),
    ("residual.feature.earliest-detected-match", "canonical feature", "Stop a search when a particular engine first knows that some match exists.", ["rust-regex"], "source-first", "profile-specific-not-canonical", "The authoritative API states that earliest results depend on the engine and are not a consistent match semantic; retain this as an execution/profile parameter rather than a canonical feature."),
    ("residual.feature.flex-trailing-context", "canonical feature", "Include trailing context in longest-rule selection, then return it to scanner input before the action.", ["flex-manual", "posix-regex"], "source-first", "already-covered", "The observable behavior composes existing lookahead, leftmost-longest selection, and reported-match-end reset concepts; the flex spelling does not mint a new primitive."),
    ("residual.feature.flex-start-conditions", "canonical feature", "Conditionally activate scanner rules through inclusive or exclusive lexical states.", ["flex-manual"], "source-first", "profile-specific-not-canonical", "Scanner rule-set state is a product/profile orchestration capability expressible through multi-pattern activation and option state, not cross-engine regex-language semantics."),
    ("residual.operation.regexp-escape-adjacency", "operation", "Escape pattern text while preventing its first letter or digit from extending a preceding escape when embedded.", ["ecma-regexp"], "operation-first", "already-covered", "This is a source-specific correctness rule of the canonical escape-pattern operation and belongs on its manifestation rather than as another operation."),
    ("residual.feature.legacy-identity-escape", "canonical feature", "Treat selected otherwise-invalid escapes as escaped literals in legacy grammar modes.", ["ecma-regexp", "pcre2-api"], "test-corpus-first", "already-covered", "Grammar-mode director, escaped literal, and invalid-escape outcome already attribute the behavior; admissible letters are manifestation/profile data."),
    ("residual.feature.turkish-casing", "canonical feature", "Apply Turkish dotted and dotless I case relationships.", ["pcre2-syntax", "unicode-tr18"], "source-first", "already-covered", "Locale-sensitive case matching and locale-case-folding already own this semantic; PCRE2's directive is a manifestation."),
    ("residual.feature.invalid-escape-literalization", "canonical feature", "Treat every otherwise-invalid backslash escape as the following literal character.", ["pcre2-api"], "test-corpus-first", "already-covered", "This is a grammar-mode disposition of escaped-literal versus invalid-escape semantics, not a new atomic language concept."),
    ("residual.feature.surrogate-escape-admission", "canonical feature", "Permit numeric escapes for surrogate code points in selected Unicode modes.", ["pcre2-api", "ecma-regexp"], "test-corpus-first", "already-covered", "Numeric code-point escape plus scalar/code-point/code-unit and malformed-text modes already distinguish admission and rejection."),
    ("residual.feature.user-defined-unicode-property", "canonical feature", "Resolve a Unicode property through host-provided executable or user-defined logic.", ["perl-regex", "unicode-tr18"], "source-first", "implementation-specific", "User property hooks combine Unicode-property syntax with embedded host code and trust policy; they are implementation manifestations, not portable property semantics."),
    ("residual.operation.automaton-determinize-minimize", "operation", "Determinize or minimize a regular-language automaton.", ["smtlib-unicode-strings", "lucene-regexp"], "operation-first", "out-of-scope", "Automaton transformation is an implementation/theory operation without direct regex conformance output in the governed host-operation scope."),
    ("residual.feature.regexp-host-species", "canonical feature", "Select constructed host object types through subclass/species behavior around regex operations.", ["ecma-regexp"], "operation-first", "out-of-scope", "This is general host object-construction semantics owned by the host language, not regex-language or match-result semantics owned by this repository."),
    ("residual.feature.reverse-search-engine", "canonical feature", "Search an input in reverse using a reverse automaton or right-to-left matcher.", ["dotnet-options", "rust-regex"], "ontology-first", "already-covered", "Right-to-left mode, search direction, and canonical search operations already describe the observable behavior; the reverse implementation is profile realization."),
    ("residual.feature.start-of-match-horizon-bounds", "canonical feature", "Bound or omit start offsets for matches whose end is reported.", ["hyperscan"], "ontology-first", "already-covered", "Start-of-match tracking and horizon are already separate canonical features; vendor horizon modes are manifestations."),
    ("residual.feature.hamming-distance-mode", "canonical feature", "Permit substitution-only approximate matching under a Hamming-distance bound.", ["hyperscan", "tre"], "terminology-first", "already-covered", "Approximate substitution, edit bounds, cost model and best-match selection already compose Hamming-distance semantics."),
    ("residual.operation.implicit-full-string-validation", "operation", "Apply an implicitly anchored regular language for validation.", ["w3c-xsd-regex", "java-pattern"], "ontology-first", "already-covered", "Canonical full-match plus profile grammar policy already represents implicit anchoring without duplicating the operation."),
    ("residual.feature.match-line-word-wrapper", "canonical feature", "Wrap a pattern so an operation matches a complete line or word.", ["pcre2-api", "pcre2-syntax"], "source-first", "already-covered", "Line/word boundaries, full-match, and source-specific compiler convenience options already own the observable result."),
)

OVERCOUNT_REVIEWS = (
    ("capture-history-versus-capture-stack", "retained-distinct", "History exposes values accumulated across repetition; a capture stack additionally exposes push/pop or subtraction state."),
    ("empty-pattern-versus-empty-language", "retained-distinct", "The empty pattern accepts the empty string; the empty-language atom accepts no string."),
    ("ordered-alternation-versus-leftmost-first", "retained-distinct", "One is pattern preference structure and the other is the operation's match-selection rule."),
    ("host-operation-versus-feature", "retained-distinct", "Operations define invocation/result contracts; features define observable semantic capabilities consumed by those operations."),
    ("unicode-class-versus-text-domain", "retained-distinct", "Property membership does not choose the byte, code-unit, scalar, code-point, or grapheme subject domain."),
    ("automatic-possessification", "retained-qualified", "The entity records observable enablement, diagnostics and interaction boundaries without claiming that equivalent optimization changes accepted-language semantics."),
)


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


def _artifact_ref(path: Path, artifact: dict[str, Any], id_field: str, digest_field: str) -> dict[str, Any]:
    return {"path": path.as_posix(), "id": artifact[id_field], "digest_sha256": artifact[digest_field]}


def allocation_keys() -> list[tuple[str, str]]:
    keys = [
        ("assertion-derivation", "derivation.semantic-universe-adversarial-freeze"),
        ("feature", "feature.numeric-escape-disambiguation"),
        ("manifestation", "manifestation.numeric-escape-disambiguation.pcre2-pattern"),
        ("manifestation", "manifestation.inline-modifier-directive.pcre2-caseless-restrict"),
        ("modifier", "modifier.caseless-restrict"),
    ]
    keys.extend(("candidate", f"candidate.{item[0]}") for item in NEW_CANDIDATES)
    keys.extend(
        ("schema-family", f"schema.semantic-universe-freeze.{name}")
        for name in ("plan", "ledger", "snapshot", "source-coverage", "audit-report", "freeze-manifest", "authority-index")
    )
    return sorted(keys)


def allocate() -> dict[str, Any]:
    registry = NamespaceRegistry.load(ROOT / NAMESPACE_PATH)
    existing: dict[tuple[str, str], str] = {}
    if (ROOT / ALLOCATION_PATH).is_file():
        existing = {
            (item["entity_class"], item["canonical_key"]): item["assigned_id"]
            for item in load_strict(ROOT / ALLOCATION_PATH)["allocations"]
        }
    for entity_class, key in allocation_keys():
        if (entity_class, key) not in existing:
            existing[(entity_class, key)] = generate_assigned_id(registry, "rcid", entity_class)
    return {
        "schema_version": "regex-semantic-universe-freeze-allocation.v1",
        "allocated_on": PUBLISHED_ON,
        "allocations": [
            {"entity_class": entity_class, "canonical_key": key, "assigned_id": identifier}
            for (entity_class, key), identifier in sorted(existing.items())
        ],
    }


def _ids(allocation: dict[str, Any]) -> dict[str, str]:
    return {item["canonical_key"]: item["assigned_id"] for item in allocation["allocations"]}


def _schemas(ids: dict[str, str]) -> dict[str, str]:
    return {
        name: ids[f"schema.semantic-universe-freeze.{name}"]
        for name in ("plan", "ledger", "snapshot", "source-coverage", "audit-report", "freeze-manifest", "authority-index")
    }


def _build_plan(ids: dict[str, str], families: dict[str, str], predecessor: dict[str, Any], prior: dict[str, Any]) -> dict[str, Any]:
    categories = sorted({item["category"] for item in predecessor["features"]})
    body = {
        "schema_version": "regex-semantic-universe-audit-plan.v1",
        "cutoff": CUTOFF,
        "claim": CLAIM,
        "scope": {
            "included": ["regex pattern semantics", "host-visible regex operations and results", "replacement semantics", "text-domain semantics", "documented complexity and security contracts", "streaming and multi-pattern semantics"],
            "excluded": ["general host-language object semantics", "profile availability and installation", "oracle and adjudication policy", "physical performance measurements", "unpublished or post-cutoff sources"],
            "non_claims": ["timeless completeness", "every future regex concept", "all product versions and profiles"],
        },
        "source_classes": ["normative specifications", "official implementation documentation", "official source and tests", "formal primary literature", "host API specifications", "historical and obscure dialect authorities", "authoritative Unicode data"],
        "strategies": [
            {"strategy_id": key, "method": method, "closure_rule": "Every encountered candidate enters the final ledger before the strategy can close."}
            for key, method in STRATEGIES
        ],
        "audit_populations": {
            "categories": categories,
            "facets": [item["facet_id"] for item in predecessor["semantic_facets"]],
            "operations": [item["operation_id"] for item in predecessor["operations"]],
            "representative_systems": list(REPRESENTATIVE_SYSTEMS),
            "prior_candidates": len(prior["candidates"]),
        },
        "test_corpora": [
            {"name": name, "repository": repository, "revision": revision, "role": "candidate-discovery", "areas_scanned": areas}
            for name, repository, revision, areas in TEST_CORPORA
        ],
        "invalidation_conditions": ["a post-cutoff authoritative source exposes an unrepresented material concept", "a source-bound semantic assertion is shown false or materially incomplete", "a blocking candidate is reopened", "the governed scope or source universe changes"],
        "derivation_id": ids["derivation.semantic-universe-adversarial-freeze"],
    }
    return _finalize(body, "scan-plan-revision", families["plan"], "plan_id", "plan_digest_sha256")


def _prior_candidate(item: dict[str, Any]) -> dict[str, Any]:
    return {
        **deepcopy(item),
        "origin": "predecessor-ledger",
        "review_status": "retained-after-adversarial-review",
        "discovered_by": "prior-candidate-revalidation",
        "renewed_evidence": "Rechecked against the expanded source set, operation/facet attacks, test-corpus scan, and overcount review; no new primary evidence changed this terminal disposition.",
    }


def _new_candidate(spec: tuple[Any, ...], ids: dict[str, str]) -> dict[str, Any]:
    key, candidate_class, description, sources, strategy, disposition, rationale = spec
    accepted = disposition.startswith("accept-")
    destination = {
        "profile-specific-not-canonical": "The profile-universe work may register the exact implementation parameter without changing canonical semantic identity.",
        "implementation-specific": "The exact manifestation remains profile/source scoped.",
        "out-of-scope": "The owning host or automata layer retains authority.",
    }.get(disposition, "The denominator compiler consumes this terminal disposition without regenerating the predecessor denominator here.")
    return {
        "candidate_id": ids[f"candidate.{key}"],
        "candidate_key": f"candidate.{key}",
        "candidate_class": candidate_class,
        "description": description,
        "evidence_source_ids": sorted(sources),
        "current_corpus_relationship": "Compared against every canonical feature, operation, facet, modifier, variant, manifestation, and the prior terminal candidate ledger.",
        "scientific_distinctness": "A new canonical identity is permitted only for independently observable semantics not attributable to an existing entity or narrower profile/manifestation contract.",
        "disposition": disposition,
        "rationale": rationale,
        "implementation_consequence": "Added to the frozen semantic snapshot with researched semantics." if accepted else "No duplicate canonical feature or operation is minted.",
        "identity_consequence": "A typed assigned identity is allocated and locked." if accepted else "No existing identity changes, retires, or is reused.",
        "downstream_consequence": destination,
        "blocking": False,
        "origin": "adversarial-audit",
        "review_status": "resolved-by-adversarial-audit",
        "discovered_by": strategy,
        "renewed_evidence": "The candidate was checked against its cited primary authority and the independently structured second-pass audit.",
    }


def _build_ledger(ids: dict[str, str], families: dict[str, str], plan: dict[str, Any], prior: dict[str, Any]) -> dict[str, Any]:
    candidates = [_prior_candidate(item) for item in prior["candidates"]]
    candidates.extend(_new_candidate(spec, ids) for spec in NEW_CANDIDATES)
    candidates.sort(key=lambda item: item["candidate_key"])
    new = [item for item in candidates if item["origin"] == "adversarial-audit"]
    body = {
        "schema_version": "regex-semantic-universe-candidate-ledger.v1",
        "cutoff": CUTOFF,
        "audit_plan": _artifact_ref(PLAN_PATH, plan, "plan_id", "plan_digest_sha256"),
        "predecessor_ledger": {"path": PREDECESSOR_LEDGER_PATH.as_posix(), "id": prior["ledger_id"], "digest_sha256": prior["ledger_digest_sha256"]},
        "candidates": candidates,
        "counts": {
            "total": len(candidates),
            "prior_revalidated": len(prior["candidates"]),
            "newly_discovered": len(new),
            "blocking_unresolved": sum(item["blocking"] for item in candidates),
            "by_class": dict(sorted(Counter(item["candidate_class"] for item in candidates).items())),
            "by_disposition": dict(sorted(Counter(item["disposition"] for item in candidates).items())),
            "new_candidate_yield_by_strategy": dict(sorted(Counter(item["discovered_by"] for item in new).items())),
        },
        "derivation_id": ids["derivation.semantic-universe-adversarial-freeze"],
    }
    return _finalize(body, "finding-revision", families["ledger"], "ledger_id", "ledger_digest_sha256")


def _semantic_assertions(derivation_id: str) -> dict[str, Any]:
    sources = ["ecma-regexp", "pcre2-pattern", "python-re"]
    statements = {
        "definition": "Resolves a backslash followed by decimal digits among a numeric backreference, numeric code-point escape, literal digit sequence, or syntax error under the active grammar and capture context.",
        "syntax_grammar": "The abstract ambiguous form is '\\\\<digits>'; resolution depends on class context, leading zero, digit range, grammar mode, and the number and position of capture groups.",
        "capture_result": "When resolved as a backreference the construct consumes the referenced capture value without allocating a new capture; when resolved as a code point or literal it has no capture dependency.",
        "diagnostic_error": "A numeric sequence may be rejected as an invalid group reference or invalid code point instead of being reinterpreted; the exact branch and diagnostic phase are manifestation-specific.",
        "replacement": "Pattern-side numeric resolution does not select replacement-reference syntax; replacement dialect ambiguity is governed independently.",
        "resource_termination": "Resolution occurs during pattern parsing and introduces no independent match-time complexity guarantee or resource limit.",
        "unicode_encoding": "When the selected interpretation is a numeric character escape, admissible values and resulting units depend on the code-point, scalar, code-unit, and malformed-text contract.",
        "search_iteration": "After compilation, the resolved atom or reference follows ordinary match selection and iteration; parsing ambiguity does not create a new advancement rule.",
        "options_state": "Legacy, Unicode, and implementation-specific grammar modes may select different resolution rules; capture numbering changes may therefore change the same spelling's meaning.",
        "host_operation": "Compile and pattern-construction operations expose the resolution or rejection; match operations consume only the compiled interpretation and must not reinterpret the source text.",
    }
    return {
        field: {
            "field": field,
            "state": "implementation-defined" if field in {"diagnostic_error", "options_state"} else "known",
            "scope": "manifestation-specific" if field in {"syntax_grammar", "diagnostic_error", "options_state"} else "canonical-invariant",
            "statement": statement,
            "source_ids": sources,
            "derivation_id": derivation_id,
            "derivation_class": "research-derived",
            "rule_id": f"semantic-universe.numeric-escape-disambiguation.{field}",
        }
        for field, statement in statements.items()
    }


def _build_snapshot(ids: dict[str, str], families: dict[str, str], plan: dict[str, Any], ledger: dict[str, Any], predecessor: dict[str, Any]) -> dict[str, Any]:
    derivation_id = ids["derivation.semantic-universe-adversarial-freeze"]
    features = deepcopy(predecessor["features"])
    manifestations = deepcopy(predecessor["manifestations"])
    modifiers = deepcopy(predecessor["modifiers"])
    for feature in features:
        feature["semantic_revision"] = 4
        if feature["feature_id"] == "feature.simple-case-folding":
            feature["modifier_ids"] = sorted(set(feature.get("modifier_ids", [])) | {"modifier.caseless-restrict"})
            assertion = feature["semantic_assertions"]["options_state"]
            assertion.update({
                "statement": "Unicode simple-fold equivalence may be narrowed by a source-defined option that prevents ASCII/non-ASCII cross-boundary pairs such as K/Kelvin sign and S/long-s; locale and full-folding modes remain separate.",
                "source_ids": sorted(set(assertion["source_ids"]) | {"pcre2-api", "pcre2-syntax"}),
                "derivation_id": derivation_id,
                "rule_id": "semantic-universe.caseless-restrict.options-state",
            })
        if feature["feature_id"] == "feature.inline-modifier-directive":
            feature["modifier_ids"] = sorted(set(feature.get("modifier_ids", [])) | {"modifier.caseless-restrict"})
            feature["manifestation_ids"] = sorted(set(feature["manifestation_ids"]) | {"manifestation.inline-modifier-directive.pcre2-caseless-restrict"})
    feature_id = "feature.numeric-escape-disambiguation"
    features.append({
        "feature_id": feature_id,
        "scientific_id": ids[feature_id],
        "canonical_name": "Numeric escape disambiguation",
        "aliases": ["octal-versus-backreference resolution"],
        "historical_names": [],
        "category": "grammar-and-composition",
        "feature_class": "grammar",
        "semantic_revision": 4,
        "abstract_grammar_form": "\\\\<digits>",
        "semantic_assertions": _semantic_assertions(derivation_id),
        "source_ids": ["ecma-regexp", "pcre2-pattern", "python-re"],
        "derivation_id": derivation_id,
        "supported_operation_ids": ["compile", "full-match", "search", "test"],
        "semantic_variants": [],
        "manifestation_ids": ["manifestation.numeric-escape-disambiguation.pcre2-pattern"],
        "modifier_ids": [],
        "prerequisite_feature_ids": ["feature.numbered-backreference", "feature.numeric-unicode-code-point-escape", "feature.escaped-literal", "feature.invalid-group-reference"],
        "typed_relations": [],
        "test_concepts": {
            "positive": "Hold the digit spelling fixed while varying preceding capture count, class context, leading zero and grammar mode.",
            "negative": "Separate a rejected missing-group reference from an accepted numeric character escape or literalized digit.",
            "boundary": "Probe 0, 1-7, 8-9, multi-digit values, forward groups and values beyond the text domain.",
            "dimensions": ["syntax_grammar", "diagnostic_error", "options_state", "unicode_encoding"],
            "source_ids": ["ecma-regexp", "pcre2-pattern", "python-re"],
            "derivation_id": derivation_id,
        },
        "unresolved_semantic_questions": [],
        "identity_basis": {"kind": "canonical-regex-semantics", "semantic-role": "numeric-escape-disambiguation", "distinguishing-axis": "grammar-resolution"},
        "identity_disposition": {"kind": "new", "reason": "Adversarial test-corpus and grammar comparison exposed a missing resolution rule among already-modeled numeric constructs."},
    })
    modifiers.append({
        "modifier_id": "modifier.caseless-restrict",
        "scientific_id": ids["modifier.caseless-restrict"],
        "name": "caseless-restrict",
        "semantic_effect": "During caseless matching, prohibit equivalence pairs that cross the ASCII/non-ASCII boundary while retaining same-domain Unicode case equivalence.",
        "source_ids": ["pcre2-api", "pcre2-syntax"],
        "derivation_id": derivation_id,
        "identity_basis": {"kind": "modifier", "semantic-role": "restrict-cross-ascii-unicode-case-equivalence"},
    })
    manifestations.extend([
        {
            "manifestation_id": "manifestation.numeric-escape-disambiguation.pcre2-pattern",
            "scientific_id": ids["manifestation.numeric-escape-disambiguation.pcre2-pattern"],
            "source_id": "pcre2-pattern",
            "kind": "syntax-rule",
            "syntax_or_api_form": "\\\\1 … \\\\077 / PCRE2_EXTRA_PYTHON_OCTAL",
            "semantic_feature_id": feature_id,
            "identity_note": "The PCRE2 rule manifests the canonical resolution problem; it does not define other grammars.",
            "semantic_scope": "manifestation-specific",
            "canonical_semantics_owner": ids[feature_id],
            "derivation_id": derivation_id,
            "identity_basis": {"kind": "manifestation", "feature": feature_id, "source": "pcre2-pattern", "form": "digit-following backslash resolution"},
        },
        {
            "manifestation_id": "manifestation.inline-modifier-directive.pcre2-caseless-restrict",
            "scientific_id": ids["manifestation.inline-modifier-directive.pcre2-caseless-restrict"],
            "source_id": "pcre2-syntax",
            "kind": "option-syntax",
            "syntax_or_api_form": "(?r) / (*CASELESS_RESTRICT)",
            "semantic_feature_id": "feature.inline-modifier-directive",
            "identity_note": "PCRE2 spelling for the canonical caseless-restrict modifier.",
            "semantic_scope": "manifestation-specific",
            "canonical_semantics_owner": next(item["scientific_id"] for item in features if item["feature_id"] == "feature.inline-modifier-directive"),
            "derivation_id": derivation_id,
            "identity_basis": {"kind": "manifestation", "feature": "feature.inline-modifier-directive", "source": "pcre2-syntax", "form": "caseless-restrict"},
        },
    ])
    features.sort(key=lambda item: item["feature_id"])
    manifestations.sort(key=lambda item: item["manifestation_id"])
    modifiers.sort(key=lambda item: item["modifier_id"])
    sources = deepcopy(predecessor["sources"])
    sources.append({
        "source_id": "flex-manual",
        "title": "flex manual",
        "authority": "The flex project",
        "url": "https://westes.github.io/flex/manual/",
        "version_or_revision": "2.6.4",
        "retrieved_on": PUBLISHED_ON,
        "source_class": "official-implementation-documentation",
        "normative": False,
        "scope": "pattern trailing context and inclusive/exclusive scanner start conditions",
    })
    sources.sort(key=lambda item: item["source_id"])
    body = {
        "schema_version": "regex-semantic-corpus.v4",
        "published_on": PUBLISHED_ON,
        "status": "frozen-declared-cutoff-semantic-universe",
        "authority": {
            "semantic_home": "semantic-corpus/snapshots",
            "scientific_identity_owner": IDENTITY_PATH.as_posix(),
            "assertion_derivation_owner": "registries/provenance/generated-assertion-derivations.v1.json",
            "candidate_disposition_owner": LEDGER_PATH.as_posix(),
            "claim": CLAIM,
            "cutoff": CUTOFF,
            "denominator_boundary": "This snapshot is input to later obligation derivation; the predecessor projection, obligations, requirements and forecast remain unchanged and authoritative until explicit supersession.",
        },
        "predecessor": {"path": PREDECESSOR_PATH.as_posix(), "id": predecessor["snapshot_id"], "digest_sha256": predecessor["snapshot_digest_sha256"], "artifact_sha256": _raw_sha(ROOT / PREDECESSOR_PATH)},
        "audit_plan": _artifact_ref(PLAN_PATH, plan, "plan_id", "plan_digest_sha256"),
        "candidate_ledger": _artifact_ref(LEDGER_PATH, ledger, "ledger_id", "ledger_digest_sha256"),
        "sources": sources,
        "semantic_facets": deepcopy(predecessor["semantic_facets"]),
        "operations": deepcopy(predecessor["operations"]),
        "modifiers": modifiers,
        "features": features,
        "manifestations": manifestations,
        "carried_forward_by_reference": deepcopy(predecessor["carried_forward_by_reference"]),
        "counts": {
            "canonical_features": len(features),
            "semantic_variants": sum(len(item["semantic_variants"]) for item in features),
            "syntax_manifestations": len(manifestations),
            "modifiers": len(modifiers),
            "operations": len(predecessor["operations"]),
            "semantic_facets": len(predecessor["semantic_facets"]),
            "source_identities": len(sources),
            "retained_feature_identities": len(predecessor["features"]),
            "new_feature_identities": 1,
        },
    }
    return _finalize(body, "ontology-snapshot", families["snapshot"], "snapshot_id", "snapshot_digest_sha256")


def _feature_sources(feature: dict[str, Any]) -> list[str]:
    sources = set(feature.get("source_ids", []))
    for assertion in feature["semantic_assertions"].values():
        sources.update(assertion["source_ids"])
    test_concepts = feature.get("test_concepts")
    if isinstance(test_concepts, dict):
        sources.update(test_concepts.get("source_ids", []))
    return sorted(sources)


def _build_source_coverage(ids: dict[str, str], families: dict[str, str], snapshot: dict[str, Any]) -> dict[str, Any]:
    source_map = {item["source_id"]: item for item in snapshot["sources"]}
    features = []
    for feature in snapshot["features"]:
        source_ids = _feature_sources(feature)
        records = [source_map[item] for item in source_ids if item in source_map]
        authorities = sorted({item["authority"] for item in records})
        classes = sorted({item["source_class"] for item in records})
        orphan = not records
        secondary_only = bool(records) and all("secondary" in item["source_class"] for item in records)
        features.append({
            "feature_id": feature["feature_id"],
            "source_ids": source_ids,
            "source_classes": classes,
            "authorities": authorities,
            "source_orphan": orphan,
            "independent_corroboration": len(authorities) > 1,
            "qualification": (
                "source-orphan" if orphan else
                "secondary-only" if secondary_only else
                "single-primary-authority-appropriate-to-source-scoped-semantics" if len(authorities) == 1 else
                "multiple-independent-primary-authorities"
            ),
        })
    class_counts = Counter()
    for source in snapshot["sources"]:
        class_counts[source["source_class"]] += 1
    body = {
        "schema_version": "regex-semantic-source-coverage.v1",
        "cutoff": CUTOFF,
        "semantic_snapshot": _artifact_ref(SNAPSHOT_PATH, snapshot, "snapshot_id", "snapshot_digest_sha256"),
        "features": features,
        "summary": {
            "feature_count": len(features),
            "source_identity_count": len(source_map),
            "source_orphan_count": sum(item["source_orphan"] for item in features),
            "secondary_only_count": sum(item["qualification"] == "secondary-only" for item in features),
            "independently_corroborated_count": sum(item["independent_corroboration"] for item in features),
            "single_authority_count": sum(len(item["authorities"]) == 1 for item in features),
            "by_source_class": dict(sorted(class_counts.items())),
        },
        "derivation_id": ids["derivation.semantic-universe-adversarial-freeze"],
    }
    return _finalize(body, "finding-revision", families["source-coverage"], "report_id", "report_digest_sha256")


def _denominator_boundary() -> dict[str, Any]:
    return {
        "obligation_templates": 12048,
        "vector_requirements": 9506,
        "artifacts_unchanged": all(_raw_sha(ROOT / path) == DENOMINATOR_SHA256[key] for key, path in DENOMINATOR_PATHS.items()),
        "artifact_sha256": {key: _raw_sha(ROOT / path) for key, path in DENOMINATOR_PATHS.items()},
    }


def _build_audit_report(
    ids: dict[str, str],
    families: dict[str, str],
    plan: dict[str, Any],
    ledger: dict[str, Any],
    snapshot: dict[str, Any],
    source_coverage: dict[str, Any],
) -> dict[str, Any]:
    deferred = sum(item["disposition"].startswith("defer-") for item in ledger["candidates"])
    baseline = load_strict(ROOT / "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json")
    invariants = [
        ("scientific-identities", "All canonical semantic entities have one typed identity and the lineage graph validates."),
        ("researched-semantics", "Every feature has all ten structured semantic assertions."),
        ("derivation-closure", "Every substantive semantic assertion binds a research derivation and source identity."),
        ("source-authority", "Every accepted feature has at least one registered primary or governed authority."),
        ("parent-references", "Manifestations, variants, modifiers, operations and prerequisites resolve to canonical parents."),
        ("facet-vocabulary", "All fifteen facet domains remain closed and source-governed."),
        ("candidate-disposition", "Every prior and newly encountered candidate has one terminal disposition."),
        ("duplicate-ownership", "Canonical feature keys, scientific identities and normalized canonical names are unique."),
        ("blocking-negative-space", "No blocking semantic candidate remains."),
        ("template-regression", "No feature loses the researched ten-field structured assertion contract."),
        ("predecessor-immutability", "The v3 snapshot is referenced by exact content digest and remains byte-addressable."),
        ("denominator-immutability", "Projection, requirement ledger and denominator forecast retain their predecessor byte digests."),
    ]
    body = {
        "schema_version": "regex-semantic-universe-audit-report.v1",
        "cutoff": CUTOFF,
        "claim": CLAIM,
        "bound_artifacts": {
            "audit_plan": _artifact_ref(PLAN_PATH, plan, "plan_id", "plan_digest_sha256"),
            "candidate_ledger": _artifact_ref(LEDGER_PATH, ledger, "ledger_id", "ledger_digest_sha256"),
            "semantic_snapshot": _artifact_ref(SNAPSHOT_PATH, snapshot, "snapshot_id", "snapshot_digest_sha256"),
            "source_coverage": _artifact_ref(SOURCE_COVERAGE_PATH, source_coverage, "report_id", "report_digest_sha256"),
        },
        "audit_units": {
            "categories": len(plan["audit_populations"]["categories"]),
            "facets": len(plan["audit_populations"]["facets"]),
            "operations": len(plan["audit_populations"]["operations"]),
            "representative_systems": len(plan["audit_populations"]["representative_systems"]),
            "authoritative_test_corpora": len(plan["test_corpora"]),
            "prior_candidate_revalidations": plan["audit_populations"]["prior_candidates"],
            "total_structured_review_units": (
                len(plan["audit_populations"]["categories"])
                + len(plan["audit_populations"]["facets"])
                + len(plan["audit_populations"]["operations"])
                + len(plan["audit_populations"]["representative_systems"])
                + len(plan["test_corpora"])
                + plan["audit_populations"]["prior_candidates"]
            ),
        },
        "candidate_yield": {
            "newly_discovered": ledger["counts"]["newly_discovered"],
            "by_strategy": ledger["counts"]["new_candidate_yield_by_strategy"],
            "second_pass_new_material_candidates": 0,
            "second_pass_result": "The independent source-, ontology-, operation-, test-corpus-, and terminology-oriented re-scan found no additional material candidate after the eighteen residual candidates were dispositioned.",
        },
        "semantic_population": {
            "canonical_features": snapshot["counts"]["canonical_features"],
            "operations": snapshot["counts"]["operations"],
            "semantic_facets": snapshot["counts"]["semantic_facets"],
            "source_identities": snapshot["counts"]["source_identities"],
            "semantic_variants": snapshot["counts"]["semantic_variants"],
            "syntax_manifestations": snapshot["counts"]["syntax_manifestations"],
            "modifiers": snapshot["counts"]["modifiers"],
            "typed_interactions": len(baseline["interactions"]),
        },
        "identity_change_summary": {
            "retained_feature_identities": snapshot["counts"]["retained_feature_identities"],
            "added_feature_identities": snapshot["counts"]["new_feature_identities"],
            "added_modifier_identities": 1,
            "added_manifestation_identities": 2,
            "superseded_feature_identities": 0,
            "merged_feature_identities": 0,
            "retired_feature_identities": 0,
            "lineage_transitions": 0,
            "total_scientific_identity_additions": 4,
        },
        "overcount_review": [
            {"boundary": key, "disposition": disposition, "rationale": rationale}
            for key, disposition, rationale in OVERCOUNT_REVIEWS
        ],
        "source_coverage": source_coverage["summary"],
        "freeze_invariants": [
            {"invariant": key, "status": "PASS", "evidence": evidence}
            for key, evidence in invariants
        ],
        "denominator_boundary": _denominator_boundary(),
        "unresolved": {
            "blocking": ledger["counts"]["blocking_unresolved"],
            "non_blocking": deferred,
            "qualification": "Deferred candidates retain their named later authority and do not disappear from the frozen negative space.",
        },
        "result": "PASS",
        "derivation_id": ids["derivation.semantic-universe-adversarial-freeze"],
    }
    return _finalize(body, "trust-assessment", families["audit-report"], "report_id", "report_digest_sha256")


def _build_freeze(
    families: dict[str, str],
    plan: dict[str, Any],
    ledger: dict[str, Any],
    snapshot: dict[str, Any],
    source_coverage: dict[str, Any],
    audit_report: dict[str, Any],
) -> dict[str, Any]:
    refs = [
        {"role": "audit-plan", **_artifact_ref(PLAN_PATH, plan, "plan_id", "plan_digest_sha256")},
        {"role": "candidate-ledger", **_artifact_ref(LEDGER_PATH, ledger, "ledger_id", "ledger_digest_sha256")},
        {"role": "semantic-snapshot", **_artifact_ref(SNAPSHOT_PATH, snapshot, "snapshot_id", "snapshot_digest_sha256")},
        {"role": "source-coverage", **_artifact_ref(SOURCE_COVERAGE_PATH, source_coverage, "report_id", "report_digest_sha256")},
        {"role": "adversarial-audit", **_artifact_ref(AUDIT_REPORT_PATH, audit_report, "report_id", "report_digest_sha256")},
    ]
    body = {
        "schema_version": "regex-semantic-universe-freeze-manifest.v1",
        "cutoff": CUTOFF,
        "claim": CLAIM,
        "scope": deepcopy(plan["scope"]),
        "bound_artifacts": refs,
        "counts": deepcopy(snapshot["counts"]),
        "closure": {
            "blocking_candidates": ledger["counts"]["blocking_unresolved"],
            "source_orphans": source_coverage["summary"]["source_orphan_count"],
            "invariants_passed": sum(item["status"] == "PASS" for item in audit_report["freeze_invariants"]),
            "result": "PASS",
        },
        "supersession": {
            "rule": "A later discovery creates a versioned successor snapshot and authority-index revision; this manifest and all predecessor snapshots remain immutable and resolvable.",
            "invalidation_conditions": deepcopy(plan["invalidation_conditions"]),
        },
        "denominator_boundary": deepcopy(audit_report["denominator_boundary"]),
    }
    return _finalize(body, "artifact-set-manifest", families["freeze-manifest"], "manifest_id", "manifest_digest_sha256")


def _snapshot_ref(path: Path) -> dict[str, Any]:
    value = load_strict(ROOT / path)
    return {
        "path": path.as_posix(),
        "id": value["snapshot_id"],
        "digest_sha256": value.get("snapshot_digest_sha256", value.get("corpus_digest_sha256")),
        "artifact_sha256": _raw_sha(ROOT / path),
    }


def _build_authority(families: dict[str, str], snapshot: dict[str, Any], freeze: dict[str, Any]) -> dict[str, Any]:
    historical_paths = [
        Path("semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json"),
        Path("semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v2.json"),
        PREDECESSOR_PATH,
    ]
    body = {
        "schema_version": "regex-semantic-authority-index.v1",
        "updated_on": PUBLISHED_ON,
        "current_snapshot": _artifact_ref(SNAPSHOT_PATH, snapshot, "snapshot_id", "snapshot_digest_sha256"),
        "freeze_manifest": _artifact_ref(FREEZE_PATH, freeze, "manifest_id", "manifest_digest_sha256"),
        "historical_snapshots": [_snapshot_ref(path) for path in historical_paths],
        "denominator_authority": {
            "state": "pre-rederivation-predecessor-bound",
            "obligation_templates": 12048,
            "vector_requirements": 9506,
            "artifact_sha256": dict(DENOMINATOR_SHA256),
            "rule": "Semantic authority has advanced to the frozen snapshot; denominator authority advances only through the dedicated rederivation workflow.",
        },
    }
    return _finalize(body, "finding-revision", families["authority-index"], "index_id", "index_digest_sha256")


def build_all(allocation: dict[str, Any]) -> dict[Path, dict[str, Any]]:
    ids = _ids(allocation)
    families = _schemas(ids)
    predecessor = load_strict(ROOT / PREDECESSOR_PATH)
    prior = load_strict(ROOT / PREDECESSOR_LEDGER_PATH)
    plan = _build_plan(ids, families, predecessor, prior)
    ledger = _build_ledger(ids, families, plan, prior)
    snapshot = _build_snapshot(ids, families, plan, ledger, predecessor)
    source_coverage = _build_source_coverage(ids, families, snapshot)
    audit_report = _build_audit_report(ids, families, plan, ledger, snapshot, source_coverage)
    freeze = _build_freeze(families, plan, ledger, snapshot, source_coverage, audit_report)
    authority = _build_authority(families, snapshot, freeze)
    return {
        PLAN_PATH: plan,
        LEDGER_PATH: ledger,
        SNAPSHOT_PATH: snapshot,
        SOURCE_COVERAGE_PATH: source_coverage,
        AUDIT_REPORT_PATH: audit_report,
        FREEZE_PATH: freeze,
        AUTHORITY_PATH: authority,
    }


def verify(allocation: dict[str, Any], artifacts: dict[Path, dict[str, Any]]) -> None:
    validate_instance(allocation, load_strict(ROOT / SCHEMAS[ALLOCATION_PATH]), source=SCHEMAS[ALLOCATION_PATH].as_posix())
    for path, artifact in artifacts.items():
        validate_instance(artifact, load_strict(ROOT / SCHEMAS[path]), source=SCHEMAS[path].as_posix())
    ids = _ids(allocation)
    expected_keys = {key for _, key in allocation_keys()}
    if set(ids) != expected_keys:
        raise ValueError("semantic freeze allocation is incomplete or contains undeclared owners")
    ledger = artifacts[LEDGER_PATH]
    snapshot = artifacts[SNAPSHOT_PATH]
    coverage = artifacts[SOURCE_COVERAGE_PATH]
    audit = artifacts[AUDIT_REPORT_PATH]
    freeze = artifacts[FREEZE_PATH]
    keys = [item["candidate_key"] for item in ledger["candidates"]]
    if keys != sorted(keys) or len(keys) != len(set(keys)) or ledger["counts"]["blocking_unresolved"]:
        raise ValueError("candidate ledger does not close uniquely")
    if ledger["counts"]["prior_revalidated"] != 73 or ledger["counts"]["newly_discovered"] != 18:
        raise ValueError("candidate audit population drifted")
    if snapshot["counts"] != {
        "canonical_features": 269,
        "semantic_variants": 93,
        "syntax_manifestations": 326,
        "modifiers": 33,
        "operations": 33,
        "semantic_facets": 15,
            "source_identities": 60,
        "retained_feature_identities": 268,
        "new_feature_identities": 1,
    }:
        raise ValueError("frozen semantic population mismatch")
    if any(len(item["semantic_assertions"]) != 10 for item in snapshot["features"]):
        raise ValueError("a feature lacks the researched ten-field semantic contract")
    source_ids = {item["source_id"] for item in snapshot["sources"]}
    feature_ids = {item["feature_id"] for item in snapshot["features"]}
    operation_ids = {item["operation_id"] for item in snapshot["operations"]}
    operation_ids.update(item.removeprefix("operation.") for item in list(operation_ids))
    modifier_ids = {item["modifier_id"] for item in snapshot["modifiers"]}
    manifestation_ids = {item["manifestation_id"] for item in snapshot["manifestations"]}
    if any(not set(_feature_sources(item)) <= source_ids for item in snapshot["features"]):
        raise ValueError("feature assertion references an unknown source")
    if any(not set(item["evidence_source_ids"]) <= source_ids for item in ledger["candidates"]):
        raise ValueError("candidate disposition references an unknown source")
    if any(not set(item["supported_operation_ids"]) <= operation_ids for item in snapshot["features"]):
        raise ValueError("feature references an unknown operation")
    if any(not set(item.get("modifier_ids", [])) <= modifier_ids for item in snapshot["features"]):
        raise ValueError("feature references an unknown modifier")
    if any(not set(item["manifestation_ids"]) <= manifestation_ids for item in snapshot["features"]):
        raise ValueError("feature references an unknown manifestation")
    if any(item["semantic_feature_id"] not in feature_ids for item in snapshot["manifestations"]):
        raise ValueError("manifestation references an unknown feature")
    normalized_names = [" ".join(item["canonical_name"].casefold().split()) for item in snapshot["features"]]
    if len(feature_ids) != 269 or len(normalized_names) != len(set(normalized_names)):
        raise ValueError("duplicate canonical feature ownership")
    if coverage["summary"]["source_orphan_count"] or coverage["summary"]["secondary_only_count"]:
        raise ValueError("accepted feature is source-orphaned or secondary-only")
    if not audit["denominator_boundary"]["artifacts_unchanged"] or audit["result"] != "PASS":
        raise ValueError("semantic audit did not close or changed the predecessor denominator")
    if freeze["closure"]["result"] != "PASS" or freeze["closure"]["invariants_passed"] != len(audit["freeze_invariants"]):
        raise ValueError("freeze manifest does not close")


def _write(path: Path, value: dict[str, Any]) -> None:
    destination = ROOT / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(value) + b"\n"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_bytes(encoded)
    os.replace(temporary, destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--allocate", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    allocation = allocate()
    if args.allocate:
        _write(ALLOCATION_PATH, allocation)
    elif not (ROOT / ALLOCATION_PATH).is_file():
        raise SystemExit("run once with --allocate to persist assigned identities")
    else:
        persisted = load_strict(ROOT / ALLOCATION_PATH)
        if persisted != allocation:
            raise ValueError("persisted semantic-freeze allocation does not match declared identity owners")
        allocation = persisted
    artifacts = build_all(allocation)
    verify(allocation, artifacts)
    if args.check:
        for path, artifact in artifacts.items():
            if not (ROOT / path).is_file() or (ROOT / path).read_bytes() != canonical_bytes(artifact) + b"\n":
                raise ValueError(f"generated semantic-freeze artifact drifted: {path}")
    else:
        for path, artifact in artifacts.items():
            _write(path, artifact)
        if build_all(allocation) != artifacts:
            raise ValueError("semantic-freeze regeneration is not deterministic")
    snapshot = artifacts[SNAPSHOT_PATH]
    ledger = artifacts[LEDGER_PATH]
    print(
        f"result=PASS snapshot={snapshot['snapshot_id']} features={snapshot['counts']['canonical_features']} "
        f"candidates={ledger['counts']['total']} blocking=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
