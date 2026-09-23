#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

def spdx_id(text: str) -> str:
    safe = []
    for ch in text:
        safe.append(ch if ch.isalnum() or ch in ".-" else "-")
    return "SPDXRef-" + "".join(safe)

def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: m2_spdx_from_cargo_metadata.py <Cargo.lock> <cargo-metadata.json> <out.spdx.json>",
            file=sys.stderr,
        )
        return 2

    lock_path = Path(sys.argv[1])
    metadata_path = Path(sys.argv[2])
    output_path = Path(sys.argv[3])

    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    locked_packages = {
        (pkg.get("name"), pkg.get("version")): pkg
        for pkg in lock.get("package", [])
    }

    metadata_bytes = metadata_path.read_bytes()
    data = json.loads(metadata_bytes.decode("utf-8"))
    metadata_sha256 = hashlib.sha256(metadata_bytes).hexdigest()

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    created = datetime.fromtimestamp(epoch, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    packages = data.get("packages", [])
    resolve = data.get("resolve") or {}
    nodes = resolve.get("nodes", [])

    package_by_id = {pkg["id"]: pkg for pkg in packages}
    spdx_by_id = {
        pkg_id: spdx_id(f'{pkg["name"]}-{pkg["version"]}-{idx}')
        for idx, pkg_id in enumerate(sorted(package_by_id))
        for pkg in [package_by_id[pkg_id]]
    }

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "SYNERGY M2 locked Cargo dependency SBOM",
        "documentNamespace": f"https://synergy.local/spdx/m2/cargo-metadata-{metadata_sha256}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: scripts/m2_spdx_from_cargo_metadata.py"],
        },
        "packages": [],
        "relationships": [],
    }

    for pkg_id in sorted(package_by_id):
        pkg = package_by_id[pkg_id]
        source = pkg.get("source")
        license_expr = pkg.get("license") or "NOASSERTION"
        locked = locked_packages.get((pkg["name"], pkg["version"]), {})
        checksum = locked.get("checksum")
        lock_source = locked.get("source")

        external_refs = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f'pkg:cargo/{pkg["name"]}@{pkg["version"]}',
            }
        ]
        annotations = []
        if lock_source:
            annotations.append({
                "annotationDate": created,
                "annotationType": "OTHER",
                "annotator": "Tool: scripts/m2_spdx_from_cargo_metadata.py",
                "comment": f"Cargo.lock source: {lock_source}",
            })

        doc["packages"].append({
            "name": pkg["name"],
            "SPDXID": spdx_by_id[pkg_id],
            "versionInfo": pkg["version"],
            "downloadLocation": source if source else "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license_expr,
            "copyrightText": "NOASSERTION",
            "checksums": (
                [{"algorithm": "SHA256", "checksumValue": checksum}]
                if checksum
                else []
            ),
            "externalRefs": external_refs,
            "annotations": annotations,
        })

    for node in sorted(nodes, key=lambda n: n["id"]):
        src = spdx_by_id.get(node["id"])
        if not src:
            continue
        for dep in sorted(node.get("deps", []), key=lambda d: (d.get("pkg",""), d.get("name",""))):
            dst = spdx_by_id.get(dep.get("pkg"))
            if not dst:
                continue
            doc["relationships"].append({
                "spdxElementId": src,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": dst,
            })

    root = resolve.get("root")
    if root in spdx_by_id:
        doc["relationships"].append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_by_id[root],
        })

    output_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
