"""Cleaning steps shared by training, the Streamlit demo and the Mininet test."""
import numpy as np
import pandas as pd

from src.config import ID_COLS, SHORTCUT_COLS, CONSTANT_COLS


def clean(df, drop_duplicates=True):

    df = df.copy()
    df.columns = df.columns.str.strip()

    df = df.drop(columns=ID_COLS + SHORTCUT_COLS + CONSTANT_COLS)
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    df = df[df['Flow Duration'] >= 0]

    if drop_duplicates:
        df = df.drop_duplicates()

    return df
