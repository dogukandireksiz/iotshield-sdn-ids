"""Shared settings (paths, random_state, label names, columns to drop)."""

RANDOM_STATE = 42
LABEL = 'Label'

ID_COLS = ["Flow ID", "Src IP", "Src Port","Dst IP", "Dst Port", "Timestamp"]    
SHORTCUT_COLS = ['Protocol']
CONSTANT_COLS = ['Fwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Init Fwd Win Byts', 'Fwd Seg Size Min']          