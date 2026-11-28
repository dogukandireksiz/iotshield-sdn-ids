"""IoTShield Streamlit demo (Faz 6). Run with: streamlit run app/app.py"""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

import joblib
import pandas as pd
import streamlit as st
from sklearn.metrics import accuracy_score, f1_score

from src.config import F_FULL, LABEL
from src.preprocessing import clean

MODEL_PATH = ROOT / "models" / "final_lgbm.joblib"
SAMPLE_PATH = ROOT / "app" / "sample_flows.csv"

# The CSV uses short label names; show the usual names in the app.
DISPLAY_NAMES = {"Benign": "Benign", "Dos": "DoS", "DDoS": "DDoS", "Bot": "Botnet", "Prob": "Probe"}


@st.cache_resource
def load_model():
    model = joblib.load(MODEL_PATH)
    # One flow file at a time: n_jobs=1 avoids the cost of starting
    # parallel threads on every call.
    model.set_params(n_jobs=1)
    return model


st.set_page_config(page_title="IoTShield", layout="wide")
st.title("IoTShield")
st.write(
    "Intrusion detection for SDN-IoT traffic. Upload a CICFlowMeter flow CSV "
    "and the model predicts one of five classes for each flow: "
    "Benign, DoS, DDoS, Botnet or Probe."
)
st.info(
    "**This screen is a demonstration, not an evaluation.** The model (LightGBM on F_full, "
    "the final 5-class model) was trained once on all data, including the sample flows below, "
    "so the scores shown here are optimistic. The measured performance comes from session-grouped "
    "3-fold CV: macro F1 0.499 ± 0.052 (see the README)."
)

if not MODEL_PATH.exists():
    st.error(
        f"Model not found: `{MODEL_PATH.relative_to(ROOT)}`. "
        "Run `.venv/bin/python app/train_final_model.py` once to train and save it."
    )
    st.stop()

model = load_model()

# 1) Input ---------------------------------------------------------------
uploaded = st.file_uploader("Flow CSV (CICFlowMeter format)", type="csv")
use_sample = st.checkbox(
    "Use the sample file instead (1,000 flows from the dataset, 200 per class)",
    value=uploaded is None,
)

if uploaded is not None and not use_sample:
    raw = pd.read_csv(uploaded, low_memory=False)
    source = uploaded.name
elif use_sample:
    raw = pd.read_csv(SAMPLE_PATH, low_memory=False)
    source = SAMPLE_PATH.name
else:
    st.info("Upload a CSV or tick the sample file box to start.")
    st.stop()

# 2) Clean ---------------------------------------------------------------
# clean() needs a Label column; a file without labels gets a placeholder,
# and the evaluation part below is skipped for it.
raw.columns = raw.columns.str.strip()
has_label = LABEL in raw.columns
if not has_label:
    raw[LABEL] = "Unknown"

# Same steps as training. Duplicates are kept: every uploaded flow gets a prediction.
try:
    df = clean(raw, drop_duplicates=False)
except KeyError as e:
    st.error(f"The file is missing columns that the cleaning step expects: {e}")
    st.stop()

missing = [c for c in F_FULL if c not in df.columns]
if missing:
    st.error(f"The file is missing {len(missing)} feature columns, for example: {missing[:5]}")
    st.stop()

removed = len(raw) - len(df)
st.caption(
    f"**{source}**: {len(raw):,} flows read, {removed:,} removed by cleaning "
    f"(rows with NaN/inf values), {len(df):,} flows predicted. "
    "Negative duration/IAT values are set to 0, not removed."
)

if df.empty:
    st.warning("No flows left after cleaning.")
    st.stop()

# 3) Predict -------------------------------------------------------------
t0 = time.perf_counter()
pred = model.predict(df[F_FULL])
elapsed_ms = (time.perf_counter() - t0) * 1000

results = pd.DataFrame({"prediction": pd.Series(pred, index=df.index).map(DISPLAY_NAMES)})
if has_label:
    results.insert(0, "true_label", df[LABEL].map(DISPLAY_NAMES))
results["confidence"] = model.predict_proba(df[F_FULL]).max(axis=1).round(3)

n_attack = int((results["prediction"] != "Benign").sum())

# 4) Summary -------------------------------------------------------------
cols = st.columns(4)
cols[0].metric("Flows", f"{len(results):,}")
cols[1].metric("Predicted attacks", f"{n_attack:,}", f"{n_attack / len(results):.1%}", delta_color="off")
cols[2].metric("Prediction time", f"{elapsed_ms:.0f} ms")
cols[3].metric("Per flow", f"{elapsed_ms / len(results):.3f} ms")

left, right = st.columns(2)
with left:
    st.subheader("Predicted classes")
    order = [n for n in DISPLAY_NAMES.values() if n in set(results["prediction"])]
    st.bar_chart(results["prediction"].value_counts().reindex(order), horizontal=True)

# 5) Evaluation (only if the file has true labels) -----------------------
with right:
    if has_label:
        st.subheader("Compared with the true labels")
        st.caption("Not a performance measure: the model has seen these flows during training.")
        y_true, y_pred = results["true_label"], results["prediction"]
        m1, m2 = st.columns(2)
        m1.metric("Accuracy", f"{accuracy_score(y_true, y_pred):.3f}")
        m2.metric("Macro F1", f"{f1_score(y_true, y_pred, average='macro'):.3f}")
        st.write("Confusion matrix (rows: true class, columns: predicted class)")
        labels = list(DISPLAY_NAMES.values())
        cm = pd.crosstab(y_true, y_pred).reindex(index=labels, columns=labels, fill_value=0)
        cm = cm.loc[cm.sum(axis=1) > 0]
        st.dataframe(cm, width="stretch")
    else:
        st.subheader("No true labels")
        st.write("The file has no `Label` column, so only predictions are shown.")

# 6) Per-flow table ------------------------------------------------------
st.subheader("Predictions per flow")
only_attacks = st.toggle("Show predicted attacks only")
table = results[results["prediction"] != "Benign"] if only_attacks else results
st.dataframe(table, width="stretch")
st.download_button(
    "Download predictions as CSV",
    table.to_csv().encode("utf-8"),
    file_name="iotshield_predictions.csv",
    mime="text/csv",
)
