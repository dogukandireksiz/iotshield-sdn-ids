# IoTShield: Machine Learning-Based Intrusion Detection for SDN-IoT Networks

Course project for **SE3513 Introduction to Machine Learning**, Muğla Sıtkı Koçman University.

We test whether **classical machine learning models** can detect attacks in SDN-IoT network traffic on the ASEADOS-SDN-IoT dataset, in two settings:

- **Multi-class classification:** Benign, DoS, DDoS, Botnet, Probe (main task)
- **Binary classification:** Benign vs. Attack

While analysing the data we found that a large part of it was parsed incorrectly and that every attack was recorded in a few short sessions (see [Key findings](#key-findings) and [Known issues](#known-issues)). Most of the project therefore focuses on a **fair evaluation design** and on measuring **what the data can and cannot separate**.

We also build a small SDN network with **Mininet + Ryu**, generate our own traffic, and check how a trained model behaves on a different network.

> **Status:** Data analysis, cleaning, the shared evaluation code, all experiments and the final evaluation are done (see [Results](#results)). 🚧 The Streamlit demo and the Mininet test still use an older model and are being updated.

---

## Team

| Name | Main responsibility |
| --- | --- |
| Doğukan Direksiz | Mininet + Ryu testing, repository |
| Berat Kaan Akcan | Preprocessing |
| Yaşar Kaki | Baseline models (Logistic Regression, Decision Tree, Random Forest) |
| Umut Şiar | LightGBM, class imbalance, hyperparameter tuning |

---

## Dataset

**ASEADOS-SDN-IoT** (Yasarathna & Le-Khac, 2026). It was collected from a hybrid SDN-IoT testbed with physical IoT devices (Raspberry Pi, Amazon Echo), virtual Mininet nodes, an ONOS controller and Open vSwitch.

- 457,044 labelled network flows, 83 flow features (extracted with CICFlowMeter)
- Labels in the CSV: `Benign`, `Dos`, `DDoS`, `Bot`, `Prob`
- Download: <https://aseados.ucd.ie/datasets/SDN-IoT/>
- Paper: <https://doi.org/10.1016/j.iot.2026.101891>

| Class | Flows (raw) | % | After `clean()` | Broken rows (`Protocol == 0`) |
| --- | --- | --- | --- | --- |
| Benign | 260,797 | 57.06 | 233,747 | 17.9% |
| DoS | 127,772 | 27.96 | 126,506 | 12.4% |
| DDoS | 51,465 | 11.26 | 50,269 | 100% |
| Botnet | 9,090 | 1.99 | 8,957 | 100% |
| Probe | 7,920 | 1.73 | 7,565 | 100% |
| **Total** | **457,044** | | **427,044** | **124,421 (29.1%)** |

⚠️ The CSV is **not** stored in this repository (231 MB). Download it and save it as **`data/ASEADOS_SDN_IoT.csv`** (the notebooks and `src/config.py` expect this exact name).

⚠️ Label spellings in the CSV are `Dos` and `Prob` (not `DoS` / `Probe`). Use the constants in `src/config.py` instead of typing them.

---

## Key findings

All numbers come from the notebooks below and are collected in `reports/results_all.csv`.

- **Broken parsing (`01_EDA`, section 4).** 127,290 raw rows (27.9%) have `Protocol == 0`. In these rows the byte, header, flag, port and TCP-window fields are 0 / −1 (in 99.6–100% of the rows, depending on the column). All Bot, DDoS and Probe flows are broken, and so are 42,740 Benign and 16,075 DoS flows. "Zero bytes" is not the same as "broken": 44% of the zero-byte rows (`Flow Byts/s == 0`) are healthy.
- **Attacks were recorded in a few short sessions (`01_EDA`, section 5).** Bot has 3 sessions in 6 active minutes and DDoS has 4 sessions in 11 active minutes. DoS comes from two recording periods (2023 and 2025) with different traffic.
- **A random split inflates the score.** On the same rows, random 3-fold CV gives a macro F1 about **0.21 higher** than session-grouped CV (LightGBM, F_timing: 0.630 vs 0.418).
- **Timing features still reveal broken rows.** With byte features removed, the timing features alone predict the broken flag with OOF AUC **0.998** (`01_EDA`, 8.4).
- **Bot and DDoS overlap in broken rows (`05_overlap`).** Duration alone gives the same Bot-vs-DDoS F1 as all 15 timing features (0.487 vs 0.495). Balancing only shifts the boundary (Bot recall 0.07 → 0.66, DDoS recall 0.95 → 0.58). Across sessions, Bot points have more DDoS than Bot neighbours.

---

## Method

### Cleaning: `src/preprocessing.clean(df, drop_duplicates=True)`

The notebooks, the experiments, the Streamlit demo and the Mininet test all call the same function. In this order, it:

1. Strips column names and creates `broken` (`Protocol == 0`) and `minute` (used for evaluation, not as features).
2. Drops ID / IP / port / `Protocol` / `Timestamp`, 14 constant columns and 3 exact duplicate columns.
3. Drops rows with inf / NaN (70 rows with duration 0). They are not filled with 0.
4. Clips negative duration / IAT values to 0. `Init Bwd Win Byts` is **not** clipped (−1 means "no information").
5. Removes duplicate rows (features + label). Conflicting rows (same features, different label) are **kept**, because they are removed only from training folds.
6. Adds `label_binary` (Benign = 0, attack = 1).

It returns the 59 feature columns (`FEATS`) plus `Label`, `label_binary`, `broken` and `minute`. All column lists (`FEATS`, `F_TIMING` (15), `F_FULL` (33), `ARTIFACT_COLS`, `TIMING_COLS`, `FEATURE_FAMILIES`) are fixed lists in `src/config.py`.

### Evaluation: `src/cv.py`

- **Session-grouped 3-fold CV** (`get_folds`). A session is a run of consecutive minutes of one class, and a session is never split between training and test. Each class's sessions are spread over the folds, so every class appears in every test fold. Every row is tested exactly once. There is no separate hold-out test set and no hyperparameter search.
- Every result is written by **`run_cv()`** as mean ± std over the folds and reported with three scores: **all rows**, **healthy subset** (Benign/DoS) and **broken subset** (5 classes).
- Samplers, scalers and PCA are fitted only on the training fold (`imblearn.pipeline.Pipeline`). Conflicting rows are dropped only from the training fold.
- The fixed experiment model is `LGBMClassifier(random_state=42, verbose=-1)` with default parameters. The experiments use **F_timing** as the main feature set, because it has no byte columns (consistent across experiments, closer to what Mininet traffic will look like), and **F_full** as the comparison set. The final evaluation then picks the best setup by the rules in `08_final_eval` (see [Results](#results)).

### Experiments

| Notebook | Question | Results file |
| --- | --- | --- |
| `01_EDA_ve_On_Isleme` | What is wrong with the data, and how do we split it? | — |
| `04_imbalance` | Do sampling / class weights / threshold tuning help? (E0–E9) | `results_imbalance.csv` |
| `05_overlap` | Why can't broken Bot and DDoS be separated? | `results_overlap.csv` |
| `06_features` | Which feature families matter? (ablation A–G, binary task) | `results_features.csv` |
| `07_formulation` | Does a different problem setup help? (OvR/OvO, PCA, subset models, hierarchical, 4 classes) | `results_formulation.csv` |
| `08_final_eval` | Final comparison: selected setups with grouped and random CV, confusion matrices | `results_final.csv` |
| `09_final_figures` | Combined table and presentation figures | `results_all.csv`, `figures/final_*.png` |

`notebooks/archive/` holds the first EDA and preprocessing notebooks. `03b` / `03c` are earlier experiments with the old random split, kept for reference only.

---

## Repository structure

```
iotshield/
├── data/          # dataset CSV (not in git)
├── notebooks/     # 01, 04–09 (see table above); archive/ = old notebooks
├── src/           # config.py (column lists), preprocessing.py (clean()), cv.py (folds, run_cv, metrics), features.py
├── models/        # saved models (.joblib, not in git)
├── app/           # Streamlit demo
├── mininet/       # topology and traffic scripts (separate Ryu env, see mininet/README.md)
├── reports/       # results_*.csv, results_all.csv, figures/
├── requirements.txt
└── README.md
```

---

## Setup

Use **Python 3.11–3.14** (the whole team should use the same version). Package versions in `requirements.txt` are pinned.

```bash
git clone https://github.com/<username>/iotshield.git
cd iotshield
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Then download the dataset CSV and save it as `data/ASEADOS_SDN_IoT.csv`.

## Running the experiments

Run the notebooks from the `notebooks/` folder (paths in `src/config.py` are relative to it). Each experiment notebook rewrites its own `reports/results_*.csv` from scratch, so it can be re-run safely.

```bash
# run one notebook end to end and save its outputs
jupyter nbconvert --to notebook --execute --inplace notebooks/04_imbalance.ipynb

# after the experiment notebooks: rebuild results_all.csv and the figures
jupyter nbconvert --to notebook --execute --inplace notebooks/09_final_figures.ipynb

# Streamlit demo (after a model is saved in models/)
streamlit run app/app.py
```

Note: when LightGBM is trained on resampled or filtered data (for example ENN in E7), scores can change by about ±0.01 between runs because of multi-threaded histogram building. This is smaller than the fold-to-fold std.

---

## Results

Session-grouped 3-fold CV, macro F1 (mean ± std over folds). Every row is in `reports/results_all.csv`, and the figures are in `reports/figures/final_*.png` (figure 6a: final table, 6b: confusion matrices).

### Final evaluation (`08_final_eval`)

| Setup | Task | Features | All rows | Healthy | Broken | Random CV (inflated) |
| --- | --- | --- | --- | --- | --- | --- |
| **Set B: LightGBM** (final 5-class model) | 5 classes | F_full | **0.499 ± 0.052** | 0.837 | 0.339 | 0.646 |
| E0: LightGBM (experiment reference) | 5 classes | F_timing | 0.418 ± 0.119 | 0.512 | 0.324 | 0.630 |
| E9: LightGBM + threshold tuning | 5 classes | F_timing | 0.430 ± 0.124 | 0.516 | 0.340 | 0.639 |
| Subset models, routed by `broken` ⚠️ | 5 classes | F_full / F_timing | 0.504 ± 0.045 | 0.842 | 0.343 | 0.650 |
| Bot + DDoS merged | 4 classes | F_timing | 0.533 ± 0.144 | 0.522 | 0.410 | 0.786 |
| Binary, LightGBM | Benign vs. Attack | F_full | 0.817 ± 0.058 | 0.840 | 0.653 | 0.931 |

- **Final 5-class model: Set B (LightGBM, F_full).** Set B, the feature sets A and G, subset routing and E9 are all within 0.01 of each other on the broken subset. Set B was chosen because it is a single model with no extra step and does not use the `broken` flag.
- ⚠️ The subset model routes rows by the `broken` flag, which is a recording artifact and may be meaningless on real traffic. Its gain over E0 also comes almost entirely from using F_full on healthy rows (a single F_full model scores 0.499).
- Rows with a different task (4 classes, binary) are not comparable with the 5-class rows.
- **Where the final model fails** (figure 6b, row-normalised):
  - Healthy rows: 37% of DoS flows are predicted as Benign.
  - Broken rows: 86% of Bot flows are predicted as DDoS (only 3% correct), and 50% of broken DoS flows are predicted as DDoS.
- **The drop from earlier results comes from the evaluation, not the model.** Our first notebooks reported about 0.65 (5 classes) and 0.93 (binary) for LightGBM from a single random split. With random CV, Set B gives almost the same (0.646 / 0.931). With session-grouped CV it gives 0.499 / 0.817.
- Prediction time is roughly 0.0004–0.002 ms per flow (batch prediction). It depends on machine load, so treat it as an order of magnitude.

### Other experiments

| Setup (5 classes, F_timing unless noted) | All rows | Healthy | Broken |
| --- | --- | --- | --- |
| Logistic regression (log1p + scaling) | 0.352 ± 0.057 | 0.581 | 0.254 |
| Hierarchical (Benign/Attack → type) | 0.423 ± 0.117 | 0.521 | 0.327 |
| Only `Flow Duration` | 0.258 ± 0.038 | 0.512 | 0.189 |

Without an imbalance method (`sampler = none`), Bot recall is at most 0.042 in every 5-class setup, because most Bot flows are predicted as DDoS. Class weights and oversampling (E1, E3–E6) raise Bot recall to 0.52–0.67, but they lower DDoS recall to 0.33–0.41, so the macro F1 does not improve.

---

## Known issues

These points update the "Known issues" and data-split parts of our proposal.

1. **Broken parsing.** 27.9% of the raw rows (`Protocol == 0`) were parsed incorrectly by CICFlowMeter in some recording sessions. Byte, header, flag, port and window fields are 0 / −1, and IP addresses look as if their 16-bit halves were swapped. Our hypothesis is that header fields were read at a shifted offset (for example a Linux cooked capture read as Ethernet). We have not verified this, because we do not have the PCAP files. All Bot, DDoS and Probe flows are affected. Byte features therefore act as a "broken?" flag, and even timing features predict the flag (AUC 0.998). We report every score on all rows, the healthy subset and the broken subset.
2. **Session mixing.** Each attack was recorded in a few short sessions (Bot: 3 sessions, DDoS: 4). A random split puts flows of the same session in both training and test and inflates macro F1 by about 0.21. DoS comes from two recording periods (2023 and 2025), and one 2025 session alone has 93,313 rows, so DoS results depend on the fold.
3. **Conflicting labels.** Some rows have identical features but different labels (7,951 rows in the F_timing space after `clean()`). This sets an upper bound on accuracy. These rows are removed only from training folds, never from test folds.
4. **Split.** The stratified 80/20 train/test split in the proposal is replaced by **session-grouped 3-fold cross-validation** (`src/cv.get_folds`). Results are reported as mean ± std, with no separate test set and no hyperparameter search.

---

## Citation and license

The dataset is published under **CC BY 4.0**. If you use it, cite:

> T. L. Yasarathna and N.-A. Le-Khac, "ASEADOS-SDN-IoT: A novel SDN-IoT network intrusion detection dataset and framework," *Internet of Things*, 2026. https://doi.org/10.1016/j.iot.2026.101891

This repository contains course project code only. The dataset belongs to its authors.
