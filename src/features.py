"""Türetilmiş oran özellikleri (WP-B2, plan 10.2).

Oranlar sadece zamanlama sütunlarından (F_TIMING / TIMING_COLS) üretilir.
Plan: docs/is_paketleri_v2.html, Bölüm 10.
"""
# Plan 10.2: paydaya +1 eklenir, böylece süre/paket sayısı 0 olan satırlarda sıfıra bölme olmaz.
DENOMINATOR_OFFSET = 1

# Yeni sütunların adları; Set F = F_TIMING + DERIVED_COLS.
DERIVED_COLS = [
    "iat_per_duration",
    "idle_share",
    "active_idle_ratio",
    "iat_spread",
    "fwd_iat_share",
    "pkt_ratio",
]


def add_ratio_features(df):
    """Planın 6 oran özelliğini df'nin bir kopyasına ekler ve kopyayı döndürür.

    Girdi clean() çıktısı olmalı (negatif süre/IAT değerleri 0'a kırpılmış).
    Eklenen sütunlar: DERIVED_COLS.
    """
    df = df.copy()
    duration = df["Flow Duration"] + DENOMINATOR_OFFSET

    # Ortalama paket arası süre, akış süresinin ne kadarı?
    df["iat_per_duration"] = df["Flow IAT Mean"] / duration
    # Akışın ne kadarı boşta (idle) geçmiş?
    df["idle_share"] = df["Idle Mean"] / duration
    # Aktif ve boşta geçen sürelerin oranı.
    df["active_idle_ratio"] = df["Active Mean"] / (df["Idle Mean"] + DENOMINATOR_OFFSET)
    # Paket arası sürelerin yayılımı (en büyük − en küçük); bölme yok.
    df["iat_spread"] = df["Flow IAT Max"] - df["Flow IAT Min"]
    # İleri yöndeki paket arası sürelerin toplamı, akış süresinin ne kadarı?
    df["fwd_iat_share"] = df["Fwd IAT Tot"] / duration
    # İleri / geri paket sayısı oranı.
    df["pkt_ratio"] = df["Tot Fwd Pkts"] / (df["Tot Bwd Pkts"] + DENOMINATOR_OFFSET)
    return df
