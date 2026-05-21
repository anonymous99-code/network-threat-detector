from random import sample

import pandas as pd
from sklearn.ensemble import IsolationForest

class TrafficMLModel:

    def __init__(self):
        self.model = IsolationForest(contamination=0.1)
        self.data = []

    def add_sample(self, port, risk):
        self.data.append([port, risk])

    def train(self):
        if len(self.data) < 20:
            return

        df = pd.DataFrame(self.data, columns=["port", "risk"])
        self.model.fit(df)

    def predict(self, port, risk):
        if len(self.data) < 20:
            return "UNKNOWN"

        sample = pd.DataFrame([{
        "port": port,
        "risk": risk
        }])

        prediction = self.model.predict(sample)

        return "ANOMALY" if prediction[0] == -1 else "NORMAL"
    