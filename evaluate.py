from __future__ import annotations

import json
from pathlib import Path

from attack_paths import load_fixture

ROOT = Path(__file__).parent
PAYLOAD = json.loads((ROOT / "data" / "fixtures.json").read_text())
OUTPUT = ROOT / "artifacts" / "attack_paths.json"


def main() -> None:
    analyzer = load_fixture(PAYLOAD)
    findings = [finding.to_dict() for finding in analyzer.find_paths()]
    result = {
        "resources": len(PAYLOAD["resources"]),
        "relations": len(PAYLOAD["relations"]),
        "findings": findings,
        "data_note": "Local authorized cloud-configuration fixture; read-only analysis.",
    }
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
