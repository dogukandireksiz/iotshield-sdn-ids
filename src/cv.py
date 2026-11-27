"""Ortak değerlendirme kodu (WP-0B).

Herkes aynı kat bölmesini (get_folds) ve aynı ölçüm fonksiyonunu (run_cv) kullanır.
Plan: docs/is_paketleri_v2.html, Bölüm 6. Kurallar: CLAUDE.md Bölüm 2.
"""
import os
import time

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import confusion_matrix, f1_score, recall_score
from sklearn.model_selection import StratifiedKFold

# Plan Bölüm 6 / CLAUDE.md Kural 1: 3 kat, shuffle, sabit tohum.
N_SPLITS = 3
RANDOM_STATE = 42

# Plan Bölüm 6: önceki dakikadan 1 dakikadan fazla boşluk varsa yeni oturum başlar.
SESSION_GAP_MINUTES = 1

# Sınıf sırası confusion matrix ve recall sütunları için sabit tutulur.
CLASSES = ["Benign", "Dos", "DDoS", "Bot", "Prob"]

# Sağlam alt kümede (broken == False) sadece bu iki sınıf var.
CLEAN_CLASSES = ["Benign", "Dos"]


def make_groups(df, label_col="Label", minute_col="minute"):
    """Her satıra bir oturum grubu verir (ör. "Bot_0", "Bot_1").

    Her sınıf içinde dakikalar sıralanır; önceki dakikadan SESSION_GAP_MINUTES'ten
    fazla boşluk varsa yeni oturum başlar. df ile aynı index'e sahip bir Series döndürür.
    """
    # clean() minute'u tam sayı verir (1970'ten beri geçen dakika), fark da dakika cinsinden.
    groups = pd.Series(index=df.index, dtype=object)

    for label in df[label_col].unique():
        rows = df[label_col] == label
        minutes = np.sort(df.loc[rows, minute_col].unique())

        # Plan Bölüm 6: ardışık dakikalar tek oturum sayılır; komşu dakikalar
        # farklı katlara düşerse 120 sn'lik akışlar sınırda sızıntı yapar.
        gaps = np.diff(minutes, prepend=minutes[0])
        new_session = gaps > SESSION_GAP_MINUTES
        session_ids = np.cumsum(new_session)

        minute_to_session = pd.Series(session_ids, index=minutes)
        session_of_row = df.loc[rows, minute_col].map(minute_to_session)
        groups[rows] = label + "_" + session_of_row.astype(str)

    return groups


def assign_sessions_to_folds(df, groups, label_col="Label"):
    """Her oturum grubunu bir kata (0, 1, 2) atar ve {grup: kat} sözlüğü döndürür.

    Her sınıfın oturumları büyükten küçüğe sıralanır; her oturum o sınıfta en az
    satırı olan kata gider. Eşitlikte kat RANDOM_STATE ile rastgele seçilir.
    """
    rng = np.random.RandomState(RANDOM_STATE)
    fold_of_group = {}

    for label in df[label_col].unique():
        session_sizes = groups[df[label_col] == label].value_counts()
        rows_in_fold = np.zeros(N_SPLITS)

        for group_name, n_rows in session_sizes.items():
            emptiest = np.flatnonzero(rows_in_fold == rows_in_fold.min())
            chosen_fold = rng.choice(emptiest)
            fold_of_group[group_name] = chosen_fold
            rows_in_fold[chosen_fold] += n_rows

    return fold_of_group


def get_folds(df, label_col="Label"):
    """Oturum gruplu kat bölmesini döndürür.

    (train_idx, test_idx) çiftlerinden oluşan bir liste döner; indeksler konumsaldır
    (df.iloc ile kullanılır). Aynı oturum hiçbir zaman iki tarafa bölünmez.
    """
    # Plan Bölüm 6 StratifiedGroupKFold diyordu, ama ham veride kat 1'de Bot,
    # kat 0'da DDoS kalmadı (log WP-0B Adım 2). Bot 3, DDoS 4 oturumlu olduğu için
    # oturumları sınıf içinde dengeli dağıtıyoruz: her sınıf her katın testinde olur.
    groups = make_groups(df, label_col=label_col)
    fold_of_group = assign_sessions_to_folds(df, groups, label_col=label_col)
    fold_of_row = groups.map(fold_of_group).to_numpy()

    folds = []
    for fold_no in range(N_SPLITS):
        test_idx = np.flatnonzero(fold_of_row == fold_no)
        train_idx = np.flatnonzero(fold_of_row != fold_no)
        folds.append((train_idx, test_idx))
    return folds


def get_random_folds(df, label_col="Label"):
    """Oturumlara bakmadan rastgele (sadece sınıf oranlı) kat bölmesi döndürür.

    get_folds ile aynı biçimde (train_idx, test_idx) listesi döner. Sadece
    "rastgele bölme skoru şişirir" karşılaştırması için kullanılır (Plan Bölüm 6).
    """
    splitter = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)

    folds = []
    for train_idx, test_idx in splitter.split(df, df[label_col]):
        folds.append((train_idx, test_idx))
    return folds


def print_fold_table(df, folds, label_col="Label"):
    """Her katın TEST kısmındaki sınıf sayılarını ve oturum sayılarını yazdırır.

    Kontrol için: her sınıf her katın testinde olmalı. Tabloyu (DataFrame) döndürür.
    """
    groups = make_groups(df, label_col=label_col)
    counts = {}
    sessions = {}
    for fold_no, (train_idx, test_idx) in enumerate(folds):
        test_labels = df[label_col].iloc[test_idx]
        test_groups = groups.iloc[test_idx]
        counts["fold_" + str(fold_no)] = test_labels.value_counts()
        sessions["fold_" + str(fold_no)] = test_groups.groupby(test_labels).nunique()

    count_table = pd.DataFrame(counts).fillna(0).astype(int)
    session_table = pd.DataFrame(sessions).fillna(0).astype(int)
    print("Test kısmındaki satır sayıları (sınıf × kat):")
    print(count_table)
    print("Test kısmındaki oturum sayıları (sınıf × kat):")
    print(session_table)
    return count_table


def is_multiclass(y_true):
    """Hedef 5 sınıflı Label mı (True), yoksa label_binary gibi başka bir hedef mi (False)?"""
    return set(pd.unique(y_true)).issubset(CLASSES)


def class_list(y_true):
    """Confusion matrix ve F1 için sabit sınıf sırası: 5 sınıf ya da ikili (0, 1)."""
    if is_multiclass(y_true):
        return CLASSES
    return [0, 1]


def bot_ddos_confusion(y_true, y_pred):
    """Gerçek Bot ve DDoS satırlarından birbirine karıştırılanların oranı (0–1).

    (Bot→DDoS + DDoS→Bot) / (gerçek Bot + gerçek DDoS). Hedef 5 sınıflı değilse NaN.
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    if not is_multiclass(y_true):
        return np.nan

    bot_as_ddos = np.sum((y_true == "Bot") & (y_pred == "DDoS"))
    ddos_as_bot = np.sum((y_true == "DDoS") & (y_pred == "Bot"))
    n_bot_ddos = np.sum((y_true == "Bot") | (y_true == "DDoS"))
    if n_bot_ddos == 0:
        return np.nan
    return (bot_as_ddos + ddos_as_bot) / n_bot_ddos


def make_confusion(y_true, y_pred):
    """Satır = gerçek sınıf, sütun = tahmin olan confusion matrix'i DataFrame olarak döndürür."""
    labels = class_list(y_true)
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    return pd.DataFrame(cm, index=labels, columns=labels)


def subset_macro_f1(y_true, y_pred, labels):
    """Sadece y_true içinde gerçekten bulunan sınıfların F1 ortalaması.

    Alt kümede hiç olmayan bir sınıf F1 = 0 sayılıp ortalamayı yapay olarak düşürmesin diye.
    """
    present = []
    for label in labels:
        if np.any(y_true == label):
            present.append(label)
    if len(present) == 0:
        return np.nan
    return f1_score(y_true, y_pred, labels=present, average="macro", zero_division=0)


def compute_metrics(y_true, y_pred, broken):
    """Tüm / sağlam / bozuk alt kümede macro F1, sınıf recall'ları ve bot_ddos_confusion.

    broken: her satır için True/False (Protocol == 0). Sözlük döndürür; anahtarlar
    run_cv'nin CSV sütunlarıyla aynıdır. İkili hedefte recall'lar ve bot_ddos NaN.
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    broken = np.asarray(broken, dtype=bool)
    labels = class_list(y_true)

    # Kural 3: her deney üç skorla. Sağlam alt kümede sadece Benign/Dos var,
    # bu yüzden sağlam F1 sadece bu iki sınıfın ortalaması (ikili hedefte 0/1).
    clean_labels = labels
    if is_multiclass(y_true):
        clean_labels = CLEAN_CLASSES

    metrics = {}
    metrics["macro_f1"] = subset_macro_f1(y_true, y_pred, labels)
    metrics["macro_f1_clean"] = subset_macro_f1(y_true[~broken], y_pred[~broken], clean_labels)
    metrics["macro_f1_broken"] = subset_macro_f1(y_true[broken], y_pred[broken], labels)

    recalls = recall_score(y_true, y_pred, labels=CLASSES, average=None, zero_division=0)
    for class_name, value in zip(CLASSES, recalls):
        # y_true'da hiç olmayan sınıfın recall'u ölçülemez: 0 değil NaN yazılır,
        # yoksa "model bu sınıfı hiç bulamadı" gibi okunur (ör. sadece Bot+DDoS alt kümesi).
        if is_multiclass(y_true) and np.any(y_true == class_name):
            metrics["recall_" + class_name] = value
        else:
            metrics["recall_" + class_name] = np.nan

    metrics["bot_ddos_confusion"] = bot_ddos_confusion(y_true, y_pred)
    return metrics


def drop_conflicts(train, feats, target="Label"):
    """Eğitim katından çelişkili satırları atar ve kalan satırları döndürür.

    Çelişkili satır: feats sütunlarında birebir aynı değerlere sahip olup farklı
    etiket taşıyan satırlar. Böyle bir değer grubunun bütün satırları atılır.
    """
    # Kural 4: çelişkiler clean() içinde değil, sadece eğitim katında atılır;
    # test katına dokunulmaz, çünkü gerçek hayatta da bu karışık akışlar gelecek.
    n_labels = train.groupby(feats, dropna=False)[target].transform("nunique")
    is_conflict = n_labels > 1
    return train[~is_conflict]


def folds_are_grouped(df, folds, label_col="Label"):
    """Katlarda hiçbir oturum hem eğitimde hem testte değilse True ("grouped").

    run_cv'nin CSV'ye "grouped" mı "random" mı yazacağını katların kendisinden anlaması için.
    """
    groups = make_groups(df, label_col=label_col)
    for train_idx, test_idx in folds:
        shared = set(groups.iloc[train_idx]) & set(groups.iloc[test_idx])
        if len(shared) > 0:
            return False
    return True


def run_one_fold(pipe, df, feats, train_idx, test_idx, target):
    """Tek kat: eğitimden çelişkileri at, fit, testte predict. (tahmin, fit sn, predict sn) döndürür."""
    train = drop_conflicts(df.iloc[train_idx], feats, target)
    test = df.iloc[test_idx]

    # Kural 4: sampler/scaler pipe içinde olduğu için sadece eğitim katında fit edilir.
    model = clone(pipe)
    start = time.perf_counter()
    model.fit(train[feats], train[target])
    fit_seconds = time.perf_counter() - start

    start = time.perf_counter()
    predictions = model.predict(test[feats])
    predict_seconds = time.perf_counter() - start

    print("  eğitim:", len(train), "satır (çelişki atılan:", len(train_idx) - len(train), ")",
          "| test:", len(test), "| fit:", round(fit_seconds, 1), "sn")
    return predictions, fit_seconds, predict_seconds


def append_row(row, out_csv):
    """Sonuç satırını out_csv'nin sonuna ekler; dosya yoksa başlıkla oluşturur."""
    write_header = not os.path.exists(out_csv)
    pd.DataFrame([row]).to_csv(out_csv, mode="a", header=write_header, index=False)
    print("CSV'ye eklendi:", out_csv)


def run_cv(pipe, df, feats, out_csv, experiment, sampler, feature_set,
           folds=None, target="Label", note=""):
    """Bir deneyi katlar üzerinde çalıştırır, out_csv'ye bir satır ekler.

    Kat başına macro F1 → ortalama ± std; diğer metrikler birleşik OOF tahminlerinden.
    (row sözlüğü, confusion matrix DataFrame, OOF tahmin Series) döndürür.
    """
    if folds is None:
        folds = get_folds(df)
    y_true = df[target].to_numpy()
    labels = class_list(y_true)
    oof = np.empty(len(df), dtype=object)
    fold_f1s = []
    fit_times = []
    predict_seconds_total = 0.0

    for fold_no, (train_idx, test_idx) in enumerate(folds):
        print("Kat", fold_no)
        predictions, fit_seconds, predict_seconds = run_one_fold(pipe, df, feats, train_idx, test_idx, target)
        oof[test_idx] = predictions
        fold_f1s.append(subset_macro_f1(y_true[test_idx], predictions, labels))
        fit_times.append(fit_seconds)
        predict_seconds_total += predict_seconds

    oof = oof.astype(y_true.dtype)
    metrics = compute_metrics(y_true, oof, df["broken"])
    row = {"experiment": experiment, "model": type(pipe.steps[-1][1]).__name__,
           "sampler": sampler, "feature_set": feature_set,
           "cv": "grouped" if folds_are_grouped(df, folds) else "random",
           "macro_f1_mean": np.mean(fold_f1s), "macro_f1_std": np.std(fold_f1s, ddof=1),
           "macro_f1_clean": metrics["macro_f1_clean"], "macro_f1_broken": metrics["macro_f1_broken"]}
    for class_name in CLASSES:
        row["recall_" + class_name] = metrics["recall_" + class_name]
    row["bot_ddos_confusion"] = metrics["bot_ddos_confusion"]
    row["fit_time_s"] = np.mean(fit_times)
    row["pred_ms_per_flow"] = predict_seconds_total / len(df) * 1000
    row["note"] = note

    print("Kat F1'leri:", np.round(fold_f1s, 4), "→", round(row["macro_f1_mean"], 4), "±", round(row["macro_f1_std"], 4))
    append_row(row, out_csv)
    return row, make_confusion(y_true, oof), pd.Series(oof, index=df.index, name="oof_pred")
