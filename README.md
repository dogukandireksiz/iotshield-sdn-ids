# IoTShield: Machine Learning-Based Intrusion Detection for SDN-IoT Networks

Course project for **SE3513 Introduction to Machine Learning**, Muğla Sıtkı Koçman University.

We test whether **classical machine learning models** can detect attacks in SDN-IoT network traffic **accurately and quickly**. We compare four models on the ASEADOS-SDN-IoT dataset, in two settings:

- **Binary classification:** Benign vs. Attack
- **Multi-class classification:** Benign, DoS, DDoS, Botnet, Probe

We also build a small SDN network with **Mininet + Ryu**, generate our own traffic, and check how well the trained model works on a different network.

> **Status:** 🚧 In progress. EDA is done; preprocessing and modeling are next.

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

| Class | Flows | % |
| --- | --- | --- |
| Benign | 260,797 | 57.06 |
| DoS | 127,772 | 27.96 |
| DDoS | 51,465 | 11.26 |
| Botnet | 9,090 | 1.99 |
| Probe | 7,920 | 1.73 |

⚠️ The CSV is **not** stored in this repository (231 MB). Download it and save it as **`data/ASEADOS_SDN_IoT.csv`** (the notebooks and `src/config.py` expect this exact name).

⚠️ Label spellings in the CSV are `Dos` and `Prob` (not `DoS` / `Probe`). Use the constants in `src/config.py` instead of typing them.

### Key findings from EDA

- Strong class imbalance (Botnet and Probe < 2% each)
- 70 rows (0.02%) with missing or infinite values in `Flow Byts/s` and `Flow Pkts/s`
- 14 constant columns
- Negative values in `Flow Duration`
- Identifier columns (IPs, ports, timestamp) are strongly linked to specific classes → **data leakage risk**, so they are removed

---

## Method

1. **Preprocessing:** remove identifier and constant columns, invalid rows and duplicates; stratified 80/20 train/test split; scaling for Logistic Regression only
2. **Models:** Logistic Regression, Decision Tree, Random Forest, LightGBM (no deep learning)
3. **Class imbalance:** class weights vs. SMOTE (training set only)
4. **Evaluation:** macro F1 (main metric), accuracy, per-class precision/recall, confusion matrix, training time and prediction time per flow
5. **Demo:** Streamlit app that predicts the class of uploaded flows
6. **Extra test:** our own Mininet + Ryu traffic → CICFlowMeter → model

---

## Repository structure

```
iotshield/
├── data/          # dataset CSV (not in git); clean train/test in data/processed/
├── notebooks/     # 01_eda, 02_preprocessing, 03_models, 04_evaluation
├── src/           # config.py (shared constants), preprocessing.py (clean())
├── models/        # saved models (.joblib, not in git)
├── app/           # Streamlit demo
├── mininet/       # topology and traffic scripts (separate Ryu env, see mininet/README.md)
├── reports/       # results.csv (shared results table), figures/
├── requirements.txt
└── README.md
```

---

## Setup

Use **Python 3.10–3.12** (the whole team should use the same version). Package versions in `requirements.txt` are pinned.

```bash
git clone https://github.com/<username>/iotshield.git
cd iotshield
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Then download the dataset CSV and save it as `data/ASEADOS_SDN_IoT.csv`.

## Usage

```bash
# Run the notebooks in order
jupyter notebook notebooks/

# Run the demo (after a model is saved in models/)
streamlit run app/app.py
```

---

## Results

_Coming soon._ The final comparison table (macro F1, accuracy, training and prediction time for each model) will be added here.

---

## Citation and license

The dataset is published under **CC BY 4.0**. If you use it, cite:

> T. L. Yasarathna and N.-A. Le-Khac, "ASEADOS-SDN-IoT: A novel SDN-IoT network intrusion detection dataset and framework," *Internet of Things*, 2026. https://doi.org/10.1016/j.iot.2026.101891

This repository contains course project code only. The dataset belongs to its authors.