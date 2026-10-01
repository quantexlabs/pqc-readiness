#!/usr/bin/env python3
"""Validate the vendored CycloneDX derivative without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import warnings
from pathlib import Path
from typing import Any

warnings.filterwarnings("ignore", category=DeprecationWarning)
from jsonschema import Draft7Validator, RefResolver  # type: ignore[import-untyped]  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "data" / "schemas"
DROP_ANNOTATIONS = {"$comment", "$id", "$schema", "description", "examples", "meta:enum", "title"}
REQUIRED_PROVENANCE = ("upstream_revision", "upstream_sha256", "consumer_ingestion")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def constraint_projection(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: constraint_projection(item)
            for key, item in sorted(value.items())
            if key not in DROP_ANNOTATIONS
        }
    if isinstance(value, list):
        return [constraint_projection(item) for item in value]
    return value


def constraint_digest(schema: dict[str, Any]) -> str:
    encoded = json.dumps(
        constraint_projection(schema), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def exact_derivative_match(
    official: dict[str, Any], derivative: dict[str, Any]
) -> bool:
    """Compare all JSON values after replacing the two documented annotations."""
    expected = json.loads(json.dumps(official))
    expected["$comment"] = derivative.get("$comment")
    expected["definitions"]["modelCard"]["properties"]["modelParameters"][
        "properties"
    ]["modelArchitecture"]["description"] = derivative["definitions"]["modelCard"][
        "properties"
    ]["modelParameters"]["properties"]["modelArchitecture"]["description"]
    return bool(expected == derivative)


def external_references(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str) and not ref.startswith("#") and ref.split("#", 1)[0]:
            refs.add(ref.split("#", 1)[0])
        for child in value.values():
            refs.update(external_references(child))
    elif isinstance(value, list):
        for child in value:
            refs.update(external_references(child))
    return refs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        type=Path,
        default=ROOT / "results" / "latest" / "inventory.cbom.json",
        help="CBOM JSON fixture to validate (default: results/latest/inventory.cbom.json)",
    )
    parser.add_argument(
        "--official-source",
        type=Path,
        help="optional exact pinned upstream JSON source for byte-independent comparison",
    )
    args = parser.parse_args()

    schema_path = SCHEMA_DIR / "bom-1.6.schema.json"
    provenance_path = SCHEMA_DIR / "provenance.json"
    schema = read_json(schema_path)
    provenance = read_json(provenance_path)
    missing_provenance = [
        key for key in REQUIRED_PROVENANCE if not provenance.get(key)
    ]
    expected_digest = provenance.get("constraint_fingerprint", {}).get("sha256")
    actual_digest = constraint_digest(schema)
    refs = sorted(external_references(schema))
    missing_refs = [ref for ref in refs if not (SCHEMA_DIR / ref.split("#", 1)[0]).is_file()]
    store: dict[str, Any] = {}
    for ref in refs:
        path = SCHEMA_DIR / ref.split("#", 1)[0]
        if not path.is_file():
            continue
        value = read_json(path)
        store[ref.split("#", 1)[0]] = value
        if isinstance(value, dict) and isinstance(value.get("$id"), str):
            store[value["$id"]] = value

    schema_error = ""
    try:
        Draft7Validator.check_schema(schema)
    except Exception as exc:  # pragma: no cover - defensive receipt path
        schema_error = str(exc)

    fixture_errors: list[str] = []
    if not args.fixture.is_file():
        fixture_errors.append(f"fixture missing: {args.fixture}")
    elif not schema_error and not missing_refs:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            resolver = RefResolver.from_schema(schema, store=store)
            fixture_errors = [
                error.message
                for error in Draft7Validator(schema, resolver=resolver).iter_errors(
                    read_json(args.fixture)
                )
            ]

    errors = missing_provenance + ([schema_error] if schema_error else [])
    if expected_digest != actual_digest:
        errors.append("constraint fingerprint mismatch")
    expected_derivative = provenance.get("derivative_sha256")
    if expected_derivative and expected_derivative != file_digest(schema_path):
        errors.append("derivative file hash mismatch")
    expected_refs = provenance.get("vendored_references", {})
    for ref in refs:
        path = SCHEMA_DIR / ref.split("#", 1)[0]
        if (
            ref in expected_refs
            and path.is_file()
            and expected_refs[ref].get("sha256") != file_digest(path)
        ):
            errors.append(f"vendored file hash mismatch: {ref}")
    if missing_refs:
        errors.append("external schema reference is not vendored")
    if fixture_errors:
        errors.append("fixture validation failed")
    exact_comparison = "not provided"
    official_source_hash_match: bool | None = None
    official_schema_error = ""
    official_missing_refs: list[str] = []
    official_fixture_errors: list[str] = []
    if args.official_source:
        if not args.official_source.is_file():
            errors.append("official source file is missing")
            exact_comparison = "missing"
        else:
            official = read_json(args.official_source)
            official_source_hash_match = (
                file_digest(args.official_source) == provenance.get("upstream_sha256")
            )
            if not official_source_hash_match:
                errors.append("official source hash mismatch")
            try:
                Draft7Validator.check_schema(official)
            except Exception as exc:  # pragma: no cover - defensive receipt path
                official_schema_error = str(exc)
            official_refs = sorted(external_references(official))
            official_missing_refs = [
                ref
                for ref in official_refs
                if not (SCHEMA_DIR / ref.split("#", 1)[0]).is_file()
            ]
            if official_schema_error:
                errors.append("official schema syntax failed")
            if official_missing_refs:
                errors.append("official external schema reference is not vendored")
            if not args.fixture.is_file():
                official_fixture_errors.append(f"fixture missing: {args.fixture}")
            elif not official_schema_error and not official_missing_refs:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    resolver = RefResolver.from_schema(official, store=store)
                    official_fixture_errors = [
                        error.message
                        for error in Draft7Validator(
                            official, resolver=resolver
                        ).iter_errors(read_json(args.fixture))
                    ]
            if official_fixture_errors:
                errors.append("official fixture validation failed")
            exact_comparison = (
                "pass"
                if exact_derivative_match(official, schema)
                else "fail"
            )
            if exact_comparison == "fail":
                errors.append("derivative differs beyond documented annotations")

    receipt = {
        "status": "pass" if not errors else "fail",
        "schema_syntax": "pass" if not schema_error else "fail",
        "format_checking": "format annotations are not asserted; no format checker enabled",
        "external_references": refs,
        "missing_references": missing_refs,
        "constraint_fingerprint": {
            "expected": expected_digest,
            "actual": actual_digest,
            "match": expected_digest == actual_digest,
        },
        "exact_official_comparison": exact_comparison,
        "official_source_hash_match": official_source_hash_match,
        "official_schema_syntax": (
            "not provided"
            if not args.official_source
            else "pass"
            if not official_schema_error
            else "fail"
        ),
        "official_missing_references": official_missing_refs,
        "official_fixture_errors": official_fixture_errors,
        "fixture": (
            str(args.fixture.relative_to(ROOT))
            if args.fixture.is_relative_to(ROOT)
            else str(args.fixture)
        ),
        "fixture_errors": fixture_errors,
        "consumer_ingestion": provenance.get("consumer_ingestion"),
        "errors": errors,
    }
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
