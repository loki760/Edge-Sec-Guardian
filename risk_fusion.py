"""Score completed CIC flows using a trusted fitted model and optional traffic rules."""
from collections import OrderedDict
import math
from numbers import Real
import pickle
from time import perf_counter

import pandas as pd
import sklearn

from nf_flow_extractor import MODEL_FEATURE_COLUMNS


def validate_bundle(bundle):
    if not isinstance(bundle, dict) or type(bundle.get("schema_version")) is not int or bundle["schema_version"] != 1:
        raise ValueError("Expected CIC model bundle schema version 1")
    fields = ("model", "algorithm", "feature_columns", "sklearn_version", "med_threshold",
              "high_threshold", "med_threshold_method", "attack_families")
    if any(key not in bundle for key in fields):
        raise ValueError("Incomplete CIC model bundle")
    cols = bundle["feature_columns"]
    if (not isinstance(cols, list) or not cols or any(c not in MODEL_FEATURE_COLUMNS for c in cols)
            or len(cols) != len(set(cols))):
        raise ValueError("Invalid model feature columns")
    med, high = bundle["med_threshold"], bundle["high_threshold"]
    if (any(isinstance(x, bool) or not isinstance(x, Real) for x in (med, high))
            or not 0 < med < high < 1):
        raise ValueError("Expected 0 < med_threshold < high_threshold < 1")
    model = bundle["model"]
    if (bundle["sklearn_version"] != sklearn.__version__
            or type(model).__name__ != bundle["algorithm"]
            or not callable(getattr(model, "predict_proba", None))
            or list(getattr(model, "classes_", ())) != [0, 1]
            or list(getattr(model, "feature_names_in_", ())) != cols):
        raise ValueError("Incompatible fitted model, feature order, classes or sklearn version")
    if not isinstance(bundle["attack_families"], list):
        raise ValueError("Expected a list of attack families")
    return bundle


def load_ciciot_bundle(path):
    # Pickle executes code during loading. Use a trusted project training output.
    with open(path, "rb") as stream:
        try:
            bundle = pickle.load(stream)
        except (pickle.UnpicklingError, EOFError, ImportError, AttributeError) as exc:
            raise ValueError(f"Cannot load CIC model bundle: {exc}") from exc
    return validate_bundle(bundle)


class RiskFusionScorer:
    def __init__(self, bundle=None, enable_rules=True):
        self.bundle = validate_bundle(bundle) if bundle is not None else None
        self.enable_rules = enable_rules
        self.reset()

    def reset(self):
        self.sources = OrderedDict()
        self.latest_end = float("-inf")

    def scan_burst(self, metadata):
        if metadata["protocol"] not in ("TCP", "UDP"):
            return False
        end = float(metadata["flow_end_ts"])
        self.latest_end = max(self.latest_end, end)
        cutoff = self.latest_end - 10
        if end < cutoff:
            return False
        source, port = metadata["src_ip"], metadata["dst_port"]
        if source not in self.sources and len(self.sources) >= 2000:
            self.sources.popitem(last=False)
        ports = self.sources.setdefault(source, {})
        self.sources.move_to_end(source)
        for old in [p for p, t in ports.items() if t < cutoff]:
            del ports[old]
        ports[port] = max(end, ports.get(port, end))
        if len(ports) > 64:
            del ports[min(ports, key=ports.get)]
        return len(ports) >= 8

    def __call__(self, features, metadata):
        start = perf_counter()
        signals = []
        probability = None
        ml_alert = False
        if self.bundle is not None:
            cols = self.bundle["feature_columns"]
            values = [float(features[col]) for col in cols]
            if not all(math.isfinite(v) for v in values):
                raise ValueError("Non-finite model feature")
            frame = pd.DataFrame([values], columns=cols)
            probability = float(self.bundle["model"].predict_proba(frame)[0, 1])
            if not 0 <= probability <= 1:
                raise ValueError("Invalid attack probability")
            ml_alert = probability >= self.bundle["high_threshold"]
            if ml_alert:
                signals.append("ML: attack probability reached the validation threshold")
        rules = []
        if self.enable_rules:
            if self.scan_burst(metadata):
                rules.append("Rule: distinct destination port burst")
            if (features["PROTOCOL_NUM"] == 6 and features["IN_PKTS"] >= 10
                    and features["SYN_RATIO"] >= 0.8 and features["ACK_RATIO"] <= 0.1):
                rules.append("Rule: SYN-heavy TCP flow")
            if features["PKTS_PER_SEC"] >= 1000 and features["IN_PKTS"] + features["OUT_PKTS"] >= 10:
                rules.append("Rule: extreme packet rate")
        signals.extend(rules)
        flagged = bool(signals)
        scored = self.bundle is not None or self.enable_rules
        risk = max(probability or 0, 1.0 if rules else 0) if scored else None
        medium = self.bundle is not None and probability >= self.bundle["med_threshold"]
        verdict = ("Flagged" if flagged else "Clear") if scored else "Unscored"
        level = ("High" if flagged else "Medium" if medium else "Low") if scored else None
        explanation = ". ".join(signals) if flagged else "No detector triggered." if scored else ""
        return dict(verdict=verdict, prediction=int(flagged) if scored else None, risk_score=risk,
                    risk_level=level, ml_probability=probability, signals=signals,
                    detector_ms=(perf_counter() - start) * 1000, explanation=explanation)
