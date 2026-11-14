"""Acquire only official UNSW-NB15 split files, or verify manual downloads."""

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
from urllib.parse import urlparse
from urllib.request import urlopen

from preprocess import load_csv


DATASET_PAGE = "https://research.unsw.edu.au/projects/unsw-nb15-dataset"
COLLECTION_URL = (
    "https://unsw-my.sharepoint.com/:f:/g/personal/z5025758_ad_unsw_edu_au/"
    "EnuQZZn3XuNBjgfcUu4DIVMBLCHyoLHqOswirpOQifr1ag?e=gKWkLS"
)
RAW_DIRECTORY = Path(__file__).resolve().parent / "data" / "raw"
SPLITS = {
    "UNSW_NB15_training-set.csv": 175341,
    "UNSW_NB15_testing-set.csv": 82332,
}


def verify_file(path, expected_rows):
    """Check the full labeled schema and return a local byte fingerprint."""
    features, labels = load_csv(path, require_label=True)
    if len(features) != expected_rows:
        raise ValueError(f"{path}: expected {expected_rows} records, got {len(features)}")
    if set(labels.unique()) != {0, 1}:
        raise ValueError(f"{path}: official split must contain both binary labels")
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "rows": len(features), "columns": 45, "sha256": digest.hexdigest(),
        "bytes": Path(path).stat().st_size,
        "labels": {int(label): int(count) for label, count in labels.value_counts().items()},
    }


def _official_url(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or not (
        host == "unsw.edu.au" or host.endswith(".unsw.edu.au")
        or host == "unsw-my.sharepoint.com"
    ):
        raise ValueError("Use an HTTPS file URL from the official UNSW collection")


def download_file(url, destination, expected_rows):
    """Validate temporary bytes before publishing; never replace an existing file."""
    _official_url(url)
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with urlopen(url, timeout=60) as response:
            _official_url(response.geturl())
            with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
                temporary_path = Path(temporary.name)
                shutil.copyfileobj(response, temporary)
        result = verify_file(temporary_path, expected_rows)
        # A same-directory hard link publishes atomically and fails if the name exists.
        os.link(temporary_path, destination)
        return result
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _record_verification(results):
    readme = Path(__file__).resolve().parent / "data" / "README.md"
    text = readme.read_text(encoding="utf-8")
    start = "<!-- verification:start -->"
    end = "<!-- verification:end -->"
    before, remainder = text.split(start, 1)
    history, after = remainder.split(end, 1)
    if "No successful local official-split verification yet." in history:
        history = "\n"
    lines = ["", "Successful local verification: " + datetime.now(timezone.utc).isoformat(), ""]
    for filename, result, source in results:
        lines.extend([
            f"- `{filename}`: {result['rows']:,} rows, {result['columns']} columns, "
            f"{result['bytes']} bytes; labels {result['labels']}.",
            f"  SHA-256: `{result['sha256']}`.",
            f"  Acquisition: {source}",
        ])
    # Retain earlier acquisition dates and URLs when a later run only verifies files.
    readme.write_text(before + start + history + "\n".join(lines) + "\n" + end + after, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-url", help="Direct official training CSV download URL")
    parser.add_argument("--testing-url", help="Direct official testing CSV download URL")
    args = parser.parse_args()
    results = []
    failed = False
    for (filename, expected_rows), url in zip(SPLITS.items(), [args.training_url, args.testing_url]):
        path = RAW_DIRECTORY / filename
        try:
            if path.exists():
                result = verify_file(path, expected_rows)
                source = "Existing file; manual placement/source must be confirmed by the operator."
            elif url:
                result = download_file(url, path, expected_rows)
                source = f"Downloaded at {datetime.now(timezone.utc).isoformat()} from {url}"
            else:
                raise ValueError(
                    f"Missing {path}. The official SharePoint collection requires browser access; "
                    "place the unchanged named file there, or supply its direct official URL. "
                    f"See data/README.md and {COLLECTION_URL}"
                )
            results.append((filename, result, source))
            print(f"{filename}: {result['rows']} rows, 45 columns; SHA-256 {result['sha256']}")
        except (OSError, ValueError) as error:
            print(f"Error: {error}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    try:
        _record_verification(results)
    except (OSError, ValueError) as error:
        print(f"Error recording provenance: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
