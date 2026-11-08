"""Helpers for writing experiment outputs under results directory."""
import csv
import json
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
DATA_DIR = RESULTS_DIR / "data"
FIGURES_DIR = RESULTS_DIR / "figures"

# TODO: Was added when writing Task 2, but no longer needed, thought might be needed for Task 4. If this function is not needed for any of the tasks, remove it.
def save_csv(rows: list[dict], path: Path) -> Path:
    """Write a list of flat dicts to CSV, using the first row's keys as the header."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path

def save_json(data, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))
    return path
