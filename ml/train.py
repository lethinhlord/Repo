from __future__ import annotations

import argparse
from pathlib import Path

from ml.training import train


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and select Week 3 model candidates")
    parser.add_argument("--config", type=Path, default=Path("ml/training_config.yaml"))
    args = parser.parse_args()
    metadata = train(args.config)
    print(f"Model package ready: {metadata['model_version']}")
    print("Selection used validation only; locked test remains UNOPENED.")


if __name__ == "__main__":
    main()
