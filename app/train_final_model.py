"""Trains the final 5-class model once on all data and saves it for the Streamlit demo.

Final model = Set B from WP-F1 (README, Results): LGBMClassifier with default
parameters on F_FULL, no sampler. This is NOT an evaluation: the scores of this
setup come from grouped CV (reports/results_final.csv). Run from the repo root:
    .venv/bin/python app/train_final_model.py
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

import joblib
import pandas as pd
from lightgbm import LGBMClassifier

from src.config import F_FULL, LABEL
from src.cv import drop_conflicts
from src.preprocessing import clean

DATA_PATH = ROOT / "data" / "ASEADOS_SDN_IoT.csv"
MODEL_PATH = ROOT / "models" / "final_lgbm.joblib"
RANDOM_STATE = 42


def load_training_data():
    """Reads the raw CSV, cleans it and removes conflicting rows.

    Returns the cleaned dataframe used to fit the final model.
    """
    raw = pd.read_csv(DATA_PATH, low_memory=False)
    df = clean(raw)
    # Same as every CV training fold (Kural 4): conflicting rows are dropped
    # from training data only, so the final model sees the same kind of data.
    before = len(df)
    df = drop_conflicts(df, F_FULL, LABEL)
    print(f"dropped {before - len(df)} conflicting rows, {len(df)} rows left")
    print(df[LABEL].value_counts())
    return df


def main():
    """Fits the final model and saves it to models/final_lgbm.joblib."""
    df = load_training_data()

    model = LGBMClassifier(random_state=RANDOM_STATE, verbose=-1)
    start = time.perf_counter()
    model.fit(df[F_FULL], df[LABEL])
    print(f"fit time: {time.perf_counter() - start:.1f} s")

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"saved: {MODEL_PATH.relative_to(ROOT)}")
    print(f"classes: {list(model.classes_)}")


if __name__ == "__main__":
    main()
