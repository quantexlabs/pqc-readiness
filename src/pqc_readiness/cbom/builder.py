"""CycloneDX CBOM builder (CycloneDX 1.6 cryptoProperties)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pqc_readiness.models import CryptoFinding, EvidenceSource, ScanResult


def _primitive_for_algorithm(algorithm: str) -> str:
    upper = algorithm.upper()
    if "ML-KEM" in upper or "KYBER" in upper:
        return "kem"
    if any(token in upper for token in ("DSA", "ECDSA", "ED25519", "ED448", "ML-DSA")):
        return "signature"
    if any(token in upper for token in ("ECDH", "X25519", "ML-KEM", "KYBER", "DH")):
        return "key-agree"
    if "AES" in upper:
        return "block-cipher"
    if "CHACHA" in upper:
        return "stream-cipher"
    if "SHA" in upper or "HASH" in upper or "MD5" in upper:
        return "hash"
    if "TLS" in upper or "SSH" in upper:
        return "other"
    if "KDF" in upper or "PBKDF" in upper:
        return "kdf"
    return "unknown"


def _asset_type_for_finding(finding: CryptoFinding) -> str:
    if finding.source == EvidenceSource.X509:
        return "certificate"
    if finding.source in {EvidenceSource.TLS, EvidenceSource.CONFIG}:
        return "protocol"
    if finding.source == EvidenceSource.SSH:
        return "related-crypto-material"
    return "algorithm"


def _security_levels(finding: CryptoFinding) -> dict[str, int]:
    # No reviewed parameter-specific strength table is supplied.
    return {}


def _algorithm_properties(finding: CryptoFinding) -> dict[str, Any]:
    props: dict[str, Any] = {"primitive": _primitive_for_algorithm(finding.algorithm)}
    if finding.metadata.get("use") == "signature":
        props["primitive"] = "signature"
    if finding.key_size is not None:
        props["parameterSetIdentifier"] = str(finding.key_size)
    props.update(_security_levels(finding))
    return props


def _certificate_properties(finding: CryptoFinding) -> dict[str, Any]:
    subject = str(finding.metadata.get("subject", "unknown"))
    return {
        "subjectName": subject[:256],
        "issuerName": str(finding.metadata.get("issuer", "unknown"))[:256],
        "certificateFormat": "X.509",
    }


def _protocol_properties(finding: CryptoFinding) -> dict[str, Any]:
    proto = "tls"
    if finding.source == EvidenceSource.SSH or "SSH" in finding.algorithm.upper():
        proto = "ssh"
    return {"type": proto, "version": str(finding.metadata.get("protocol_version", "unspecified"))}


def _related_material_properties(finding: CryptoFinding) -> dict[str, Any]:
    return {"type": "public-key", "format": "unknown"}


def finding_to_component(finding: CryptoFinding) -> dict[str, Any]:
    """Convert a finding to a CycloneDX component with cryptoProperties."""
    asset_type = _asset_type_for_finding(finding)
    crypto_properties: dict[str, Any] = {"assetType": asset_type}
    if asset_type == "certificate":
        crypto_properties["certificateProperties"] = _certificate_properties(finding)
        crypto_properties["algorithmProperties"] = _algorithm_properties(finding)
    elif asset_type == "protocol":
        crypto_properties["protocolProperties"] = _protocol_properties(finding)
        crypto_properties["algorithmProperties"] = _algorithm_properties(finding)
    elif asset_type == "related-crypto-material":
        crypto_properties["relatedCryptoMaterialProperties"] = _related_material_properties(finding)
        crypto_properties["algorithmProperties"] = _algorithm_properties(finding)
    else:
        crypto_properties["algorithmProperties"] = _algorithm_properties(finding)

    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": finding.finding_id,
        "name": finding.algorithm,
        "description": finding.evidence[:500],
        "cryptoProperties": crypto_properties,
        "properties": [
            {
                "name": "pqc-readiness:observation",
                "value": str(finding.metadata.get("observation", "unknown")),
            },
            {"name": "pqc-readiness:use", "value": str(finding.metadata.get("use", "unknown"))},
            {"name": "pqc-readiness:quantum_risk", "value": finding.quantum_risk.value},
            {"name": "pqc-readiness:migration_priority", "value": finding.migration_priority.value},
            {"name": "pqc-readiness:location", "value": finding.location[:500]},
            {"name": "pqc-readiness:evidence", "value": finding.evidence[:500]},
        ],
    }
    return component


def build_cbom(scan: ScanResult, project_name: str = "pqc-readiness-scan") -> dict[str, Any]:
    """Build a CycloneDX 1.6 BOM document from scan results."""
    serial = uuid.uuid4().urn
    seen_refs: set[str] = set()
    components: list[dict[str, Any]] = []
    for finding in scan.findings:
        if finding.finding_id in seen_refs:
            continue
        seen_refs.add(finding.finding_id)
        components.append(finding_to_component(finding))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pqc-readiness",
                        "version": "0.1.0",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": project_name,
            },
            "properties": [
                {"name": "scan_targets", "value": ",".join(scan.scan_targets[:20])},
                {"name": "finding_count", "value": str(len(scan.findings))},
                {"name": "coverage", "value": str(scan.coverage.to_dict())},
            ],
        },
        "components": components,
        "dependencies": [],
    }
