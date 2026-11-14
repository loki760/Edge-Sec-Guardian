"""Predict one validated UNSW-NB15 record, with an optional local explanation."""

import argparse
import sys

from explain import explain_prediction
from preprocess import load_csv


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Headered UNSW-NB15 CSV")
    parser.add_argument("--row", type=int, default=0,
                        help="Zero-based data row, excluding the header (default: 0)")
    parser.add_argument("--model", default="artifacts/model.pkl",
                        help="Trusted project-generated pipeline (default: artifacts/model.pkl)")
    parser.add_argument("--explain", action="store_true",
                        help="Request an explanation from local llama3.2:1b")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="Local Ollama URL, used only with --explain")
    args = parser.parse_args()

    try:
        if args.row < 0:
            raise ValueError("--row must be nonnegative")
        features, _ = load_csv(args.input)
        if args.row >= len(features):
            raise ValueError(f"--row {args.row} is out of range; CSV has {len(features)} data rows")
        row = features.iloc[[args.row]]
        # Delay this import so help and input validation work before ML integration.
        from predict import load_model, predict_row

        bundle = load_model(args.model)
        prediction = predict_row(bundle, row)
    except ImportError as error:
        print(f"Error: prediction module unavailable: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"Row: {args.row}")
    print(f"Prediction: {prediction['prediction']} (label={prediction['label']})")
    print(f"Attack probability: {prediction['attack_probability']:.4f}")
    if args.explain:
        try:
            explanation = explain_prediction(row.iloc[0].to_dict(), prediction,
                                             base_url=args.ollama_url)
        except (OSError, ValueError, RuntimeError) as error:
            print(f"Explanation unavailable: {error}", file=sys.stderr)
            return 1
        print(f"Explanation: {explanation}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
