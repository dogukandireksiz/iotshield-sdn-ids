import re
from src.config import FEATURE_COLS

TIME_PREFIXES = ("Flow Duration", "Flow IAT", "Fwd IAT", "Bwd IAT", "Active", "Idle")


def to_snake(name):
    """'Flow Byts/s' -> 'flow_byts_s'"""
    return re.sub(r"[ /]+", "_", name.lower())


def cicflow_to_dataset(df):
    """Convert Python cicflowmeter output to the dataset's 62 feature columns."""
    rename_map = {to_snake(col): col for col in FEATURE_COLS}
    out = df.rename(columns=rename_map)[FEATURE_COLS].copy()

    for col in FEATURE_COLS:
        if col.startswith(TIME_PREFIXES):
            out[col] = out[col] * 1_000_000      # seconds -> microseconds
    return out