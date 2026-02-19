from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from agent_config import MlConfig
from agent_db import fetch_recent_features


@dataclass(frozen=True)
class MlResult:
    anomaly_score: float
    is_anomaly: bool


def build_feature_vector(
    total_open_ports: int,
    unique_devices: int,
    new_device_count: int,
    new_port_count: int,
) -> List[int]:
    return [total_open_ports, unique_devices, new_device_count, new_port_count]


def maybe_score_anomaly(
    conn,
    config: MlConfig,
    feature_vector: List[int],
    scan_index: int,
) -> MlResult | None:
    if not config.enabled:
        return None

    history = fetch_recent_features(conn, limit=max(config.min_samples, 50))
    if len(history) < config.min_samples:
        return None

    model = _load_or_train_model(config, history, scan_index)
    score = float(model.decision_function([feature_vector])[0])
    is_anomaly = model.predict([feature_vector])[0] == -1
    return MlResult(anomaly_score=score, is_anomaly=is_anomaly)


def _load_or_train_model(
    config: MlConfig,
    history: List[Tuple[int, int, int, int]],
    scan_index: int,
) -> IsolationForest:
    if os.path.exists(config.model_path) and scan_index % config.retrain_every != 0:
        return joblib.load(config.model_path)

    model = IsolationForest(
        n_estimators=200,
        contamination=config.contamination,
        random_state=42,
    )
    data = np.array(history, dtype=float)
    model.fit(data)

    os.makedirs(os.path.dirname(config.model_path), exist_ok=True)
    joblib.dump(model, config.model_path)
    return model
