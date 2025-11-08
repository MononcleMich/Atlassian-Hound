from __future__ import annotations

import argparse
import json
from pathlib import Path

from utils.model_template import MODEL_TEMPLATE


def generate_model(destination: Path) -> None:
    destination.write_text(json.dumps(MODEL_TEMPLATE, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"model.json regenerated at {destination}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate model.json from the embedded template.")
    parser.add_argument("--output", default="model.json", help="Path to write the generated model.json (default: model.json)")
    args = parser.parse_args()
    generate_model(Path(args.output))


if __name__ == "__main__":
    main()
