"""Cleaning steps shared by experiments, the Streamlit demo and the Mininet test.

clean() follows the 6-step table in plan WP-0A (docs/is_paketleri_v2.html, section 5).
Each step is a small function so it can be read and checked on its own.
"""
import numpy as np
import pandas as pd

from src.config import ID_COLS, SHORTCUT_COLS, CONSTANT_COLS, DUPLICATE_COLS, FEATS

# Timestamp format in the raw CSV, e.g. "12/03/2025 01:23:45 PM" (same as the EDA notebook).
TIMESTAMP_FORMAT = '%d/%m/%Y %I:%M:%S %p'
SECONDS_PER_MINUTE = 60

# -1 means "no information" in this column (100% of broken rows), so it is NOT clipped.
NO_CLIP_COL = 'Init Bwd Win Byts'
BENIGN_LABEL = 'Benign'
OUTPUT_EXTRA_COLS = ['Label', 'label_binary', 'broken', 'minute']


def add_eval_columns(df):
    """Plan step 1: adds 'broken' and 'minute' columns.

    broken = True when Protocol == 0 (CICFlowMeter could not read the headers).
    minute = minutes since 1970, used to build class+session groups for CV.
    These are not model features; they must be made before Protocol/Timestamp are dropped.
    """
    df['broken'] = df['Protocol'] == 0

    timestamps = pd.to_datetime(df['Timestamp'], format=TIMESTAMP_FORMAT)
    seconds = timestamps.astype('datetime64[s]').astype('int64')
    df['minute'] = seconds // SECONDS_PER_MINUTE
    return df


def drop_unused_columns(df):
    """Plan step 2: drops ID columns, Protocol, Timestamp, 14 constant and 3 duplicate columns.

    Returns the dataframe without these columns.
    """
    # ID_COLS already contains Timestamp; SHORTCUT_COLS is ['Protocol'].
    # IDs/Protocol leak which rows are broken; constant and duplicate columns add nothing.
    columns_to_drop = ID_COLS + SHORTCUT_COLS + CONSTANT_COLS + DUPLICATE_COLS
    df = df.drop(columns=columns_to_drop)
    return df


def drop_inf_nan_rows(df):
    """Plan step 3: drops rows that have inf or NaN in any feature column.

    Returns the dataframe without these rows (~70 rows on the raw data).
    """
    # Not filled with 0: in these rows duration is 0, so the rate is "infinite".
    # Writing 0 would mean "no packets", which reverses the meaning.
    values = df[FEATS]
    bad_rows = np.isinf(values).any(axis=1) | values.isna().any(axis=1)
    print(f'clean: dropped {bad_rows.sum()} rows with inf/NaN')
    return df[~bad_rows]


def clip_negative_values(df):
    """Plan step 4: sets negative duration/IAT values to 0.

    All features except 'Init Bwd Win Byts' are clipped at 0.
    Returns the changed dataframe.
    """
    clip_cols = []
    for col in FEATS:
        if col != NO_CLIP_COL:
            clip_cols.append(col)

    negative_rows = (df[clip_cols] < 0).any(axis=1)
    print(f'clean: clipped negative values to 0 in {negative_rows.sum()} rows')
    df[clip_cols] = df[clip_cols].clip(lower=0)
    return df


def remove_duplicate_rows(df):
    """Plan step 5: removes rows with the same features AND the same label.

    Conflicting rows (same features, different label) are kept on purpose:
    they are removed only from the training fold (WP-0B), and depend on the feature set.
    """
    before = len(df)
    df = df.drop_duplicates(subset=FEATS + ['Label'])
    print(f'clean: removed {before - len(df)} duplicate rows (features + label)')
    return df


def add_binary_label(df):
    """Plan step 6: adds label_binary (Benign = 0, every attack = 1)."""
    df['label_binary'] = (df['Label'] != BENIGN_LABEL).astype(int)
    return df


def clean(df, drop_duplicates=True):
    """Cleans the raw ASEADOS-SDN-IoT dataframe (plan WP-0A, steps 1-6).

    Returns FEATS columns + Label, label_binary, broken, minute (index reset).
    The input dataframe is not changed (a copy is used).
    """
    df = df.copy()
    df.columns = df.columns.str.strip()

    df = add_eval_columns(df)       # step 1 (before Protocol/Timestamp are dropped)
    df = drop_unused_columns(df)    # step 2
    df = drop_inf_nan_rows(df)      # step 3
    df = clip_negative_values(df)   # step 4
    if drop_duplicates:
        df = remove_duplicate_rows(df)  # step 5
    df = add_binary_label(df)       # step 6

    df = df[FEATS + OUTPUT_EXTRA_COLS].reset_index(drop=True)
    print(f'clean: final shape {df.shape}')
    return df
