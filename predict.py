"""Load trusted project-generated model bundles and predict one UNSW feature row."""

import math
import pickle

import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.utils.validation import check_is_fitted

from preprocess import CATEGORICAL_COLUMNS, FEATURE_COLUMNS, NUMERIC_COLUMNS


def _validate_bundle(bundle):
    if not isinstance(bundle, dict) or set(bundle) != {
        "schema_version", "feature_columns", "sklearn_version", "pipeline",
    }:
        raise ValueError("Invalid model bundle fields")
    if type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1:
        raise ValueError("Incompatible model schema version")
    if bundle["feature_columns"] != FEATURE_COLUMNS:
        raise ValueError("Incompatible model feature columns or order")
    if bundle["sklearn_version"] != sklearn.__version__:
        raise ValueError("Incompatible scikit-learn version; use the training version")
    pipeline = bundle["pipeline"]
    if not isinstance(pipeline, Pipeline) or [name for name, _ in pipeline.steps] != [
        "preprocess", "classifier",
    ]:
        raise ValueError("Model must contain preprocessing and classification pipeline steps")
    preprocessor = pipeline.named_steps["preprocess"]
    classifier = pipeline.named_steps["classifier"]
    if not isinstance(preprocessor, ColumnTransformer) or not isinstance(classifier, RandomForestClassifier):
        raise ValueError("Invalid preprocessing or classifier type")
    check_is_fitted(preprocessor)
    check_is_fitted(classifier)
    if list(getattr(pipeline, "feature_names_in_", [])) != FEATURE_COLUMNS:
        raise ValueError("Fitted model feature columns do not match the schema")
    if set(classifier.classes_) != {0, 1}:
        raise ValueError("Model must have binary classes 0 and 1")


def load_model(path):
    """Load only trusted pickle files: unpickling can execute arbitrary code."""
    try:
        with open(path, "rb") as source:
            bundle = pickle.load(source)
    except (pickle.UnpicklingError, EOFError, AttributeError, ImportError, IndexError) as error:
        raise ValueError(f"Cannot read model bundle: {error}") from error
    _validate_bundle(bundle)
    return bundle


def predict_row(bundle, X):
    """Predict from exactly one validated, canonically ordered raw feature row."""
    _validate_bundle(bundle)
    if not isinstance(X, pd.DataFrame) or len(X) != 1 or list(X.columns) != FEATURE_COLUMNS:
        raise ValueError("Prediction requires one row with exactly the 42 ordered feature columns")
    for column in CATEGORICAL_COLUMNS:
        value = X[column].iloc[0]
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError(f"Column '{column}': expected a validated nonempty category")
    for column in NUMERIC_COLUMNS:
        value = X[column].iloc[0]
        if not pd.api.types.is_number(value) or not math.isfinite(value):
            raise ValueError(f"Column '{column}': expected a finite numeric value")
    pipeline = bundle["pipeline"]
    label = int(pipeline.predict(X)[0])
    # Probability columns follow classes_, not an assumed fixed column index.
    attack_index = list(pipeline.named_steps["classifier"].classes_).index(1)
    probability = float(pipeline.predict_proba(X)[0, attack_index])
    return {
        "label": label,
        "prediction": "attack" if label == 1 else "normal",
        "attack_probability": probability,
    }
