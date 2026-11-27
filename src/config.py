"""Shared settings (paths, random_state, label names, column lists).

Plan WP-0A: column lists are FIXED lists copied from the EDA notebook output
(notebooks/01_EDA_ve_On_Isleme.ipynb). They are never recomputed in code,
so every experiment uses exactly the same columns.
"""

RANDOM_STATE = 42
LABEL = 'Label'

# Paths are relative to the notebooks/ folder (plan WP-0A).
DATA_PATH = "../data/ASEADOS_SDN_IoT.csv"
PROCESSED_DIR = "../data/processed/"

ID_COLS = ["Flow ID", "Src IP", "Src Port","Dst IP", "Dst Port", "Timestamp"]
SHORTCUT_COLS = ['Protocol']
CONSTANT_COLS = ['Fwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Init Fwd Win Byts', 'Fwd Seg Size Min']

# OLD (before WP-0A): still imported by src/cicflow_adapter.py, 03b, 03c and
# 05_mininet_test. Do not use in new code; new code uses FEATS.
FEATURE_COLS = ['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Bwd PSH Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']
LABEL_COLS = ["label_multi", "label_binary"]


# ---------------------------------------------------------------------------
# WP-0A column lists (new code uses only these)
# ---------------------------------------------------------------------------

# Exact copies of another column (EDA section 3) -> dropped in clean().
# PSH Flag Cnt == Bwd PSH Flags, Subflow Fwd Pkts == Tot Fwd Pkts,
# Subflow Bwd Pkts == Tot Bwd Pkts.
DUPLICATE_COLS = ['Subflow Fwd Pkts', 'Subflow Bwd Pkts', 'PSH Flag Cnt']

# All model features left after clean() (59 = 62 non-constant - 3 duplicates).
FEATS = ['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
         'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
         'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
         'Flow Byts/s', 'Flow Pkts/s',
         'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
         'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
         'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
         'Bwd PSH Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s',
         'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
         'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt', 'Down/Up Ratio',
         'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Subflow Fwd Byts', 'Subflow Bwd Byts',
         'Init Bwd Win Byts', 'Fwd Act Data Pkts',
         'Active Mean', 'Active Std', 'Active Max', 'Active Min',
         'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

# Columns that are (almost) always 0 / -1 in broken rows (EDA section 4).
# EDA printed 36; 'PSH Flag Cnt' is removed here because clean() drops it
# (decision WP-0A, option B) -> 35, so every name exists after clean().
ARTIFACT_COLS = ['TotLen Fwd Pkts', 'TotLen Bwd Pkts',
                 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
                 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
                 'Flow Byts/s',
                 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
                 'Bwd PSH Flags', 'Fwd Header Len', 'Bwd Header Len',
                 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
                 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt',
                 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
                 'Subflow Fwd Byts', 'Subflow Bwd Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts']

# Columns that still change in broken rows (EDA section 4).
# EDA printed 26; 'Subflow Fwd Pkts' and 'Subflow Bwd Pkts' are removed here
# because clean() drops them (decision WP-0A, option B) -> 24.
TIMING_COLS = ['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'Flow Pkts/s',
               'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
               'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
               'Fwd Pkts/s', 'Bwd Pkts/s', 'Down/Up Ratio',
               'Active Mean', 'Active Std', 'Active Max', 'Active Min',
               'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

# Feature sets after removing |Spearman r| > 0.95 pairs (EDA section 8 output).
# F_TIMING: only timing columns; F_FULL: all features.
F_TIMING = ['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'Flow Pkts/s',
            'Flow IAT Std', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Std', 'Fwd IAT Min',
            'Fwd Pkts/s', 'Down/Up Ratio', 'Active Mean', 'Active Std', 'Idle Mean', 'Idle Std']

F_FULL = ['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
          'Fwd Pkt Len Min', 'Bwd Pkt Len Min', 'Flow Byts/s', 'Flow Pkts/s',
          'Flow IAT Std', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Std', 'Fwd IAT Min',
          'Bwd IAT Tot', 'Bwd IAT Std', 'Bwd IAT Min', 'Bwd PSH Flags', 'Fwd Header Len',
          'Fwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max',
          'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt', 'Down/Up Ratio',
          'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Active Mean', 'Active Std', 'Idle Mean', 'Idle Std']

# Every one of the 59 features belongs to exactly one family (plan WP-0A).
FEATURE_FAMILIES = {
    'duration': ['Flow Duration'],
    'count': ['Tot Fwd Pkts', 'Tot Bwd Pkts', 'Fwd Act Data Pkts', 'Down/Up Ratio'],
    'bytes': ['TotLen Fwd Pkts', 'TotLen Bwd Pkts',
              'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
              'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std',
              'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
              'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
              'Subflow Fwd Byts', 'Subflow Bwd Byts'],
    'rate': ['Flow Byts/s', 'Flow Pkts/s', 'Fwd Pkts/s', 'Bwd Pkts/s'],
    'iat': ['Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min'],
    'active_idle': ['Active Mean', 'Active Std', 'Active Max', 'Active Min',
                    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'],
    'flags': ['Bwd PSH Flags', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'ACK Flag Cnt'],
    'header_window': ['Fwd Header Len', 'Bwd Header Len', 'Init Bwd Win Byts'],
}


# ---------------------------------------------------------------------------
# Checks: if a list is edited by mistake, importing config fails immediately.
# ---------------------------------------------------------------------------
assert len(CONSTANT_COLS) == 14
assert len(DUPLICATE_COLS) == 3
assert len(FEATS) == 59 and len(set(FEATS)) == 59
assert len(ARTIFACT_COLS) == 35 and len(set(ARTIFACT_COLS)) == 35
assert len(TIMING_COLS) == 24 and len(set(TIMING_COLS)) == 24
# Every feature is either an artifact column or a timing column, never both.
assert set(ARTIFACT_COLS) & set(TIMING_COLS) == set()
assert set(ARTIFACT_COLS) | set(TIMING_COLS) == set(FEATS)
# Dropped columns must not appear in the feature list.
assert set(FEATS) & set(CONSTANT_COLS + DUPLICATE_COLS) == set()

assert len(F_TIMING) == 15 and set(F_TIMING) <= set(TIMING_COLS)
assert len(F_FULL) == 33 and set(F_FULL) <= set(FEATS)

# Families: 8 families, no column in two families, together exactly FEATS.
assert len(FEATURE_FAMILIES) == 8
all_family_cols = []
for family_cols in FEATURE_FAMILIES.values():
    all_family_cols = all_family_cols + family_cols
assert len(all_family_cols) == len(set(all_family_cols)), "a column is in two families"
assert set(all_family_cols) == set(FEATS), "families do not cover FEATS"
