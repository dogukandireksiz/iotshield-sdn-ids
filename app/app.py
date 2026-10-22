"""IoTShield Streamlit demo (Faz 6). Run with: streamlit run app/app.py"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

import streamlit as st

st.title("IoTShield")

# TODO (Faz 6):
# - st.file_uploader for a CSV
# - src.preprocessing.clean(df, drop_duplicates=False)
# - load models/best_model.joblib and predict
# - show st.dataframe of predictions and a class distribution chart
