import os
import sys
import tempfile
import unittest

import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.gen3_model import FEATURE_SET_F, Gen3FModel, request_features
from ml.test_comprehensive import TESTS
from ml.train_final_gen3 import benign_threshold


def _tiny_model():
    """A LightGBM fitted on the 63 scenarios (labels from ALLOW/BLOCK) - enough to exercise the wrapper."""
    import lightgbm as lgb
    rows = [(m, u, b) for _, m, u, b, _ in TESTS]
    y = np.array([exp == "BLOCK" for exp, *_ in TESTS], dtype=int)
    X = np.array([[request_features(m, u, b)[c] for c in FEATURE_SET_F] for m, u, b in rows], dtype=np.float32)
    return lgb.LGBMClassifier(n_estimators=20, min_child_samples=2, verbose=-1).fit(X, y)


class Gen3ModelTests(unittest.TestCase):
    def test_feature_set_matches_the_selected_experiment_configuration(self):
        from ml.experiment_value_features import CONFIGS
        self.assertEqual(FEATURE_SET_F, CONFIGS["E_plus_query_body_entropy"][0])
        self.assertEqual(len(FEATURE_SET_F), 48)
        self.assertEqual(len(set(FEATURE_SET_F)), 48)

    def test_benign_threshold(self):
        p = np.linspace(0, 1, 1000)
        t = benign_threshold(p, np.ones(1000), 0.99)
        self.assertAlmostEqual(float((p < t).mean()), 0.99, places=3)
        self.assertGreaterEqual(float((p < t).mean()), 0.99)
        self.assertEqual(benign_threshold(np.array([0.3, 0.4]), np.ones(2), 0.0), 0.0)

    def test_wrapper_scores_and_predicts(self):
        wrapper = Gen3FModel(_tiny_model(), threshold=0.5, card={"feature_set": "x"})
        p = wrapper.score_request("GET", "/items?id=1'+UNION+SELECT+null--", "")
        self.assertTrue(0.0 <= p <= 1.0)
        out = wrapper.predict("GET", "/", "")
        self.assertEqual(set(out), {"attack_probability", "is_attack", "threshold", "feature_set"})

    def test_wrong_columns_are_refused(self):
        with self.assertRaises(ValueError):
            Gen3FModel(object(), 0.5, columns=FEATURE_SET_F[:-1])


class Gen3ApiTests(unittest.TestCase):
    def test_missing_artifact_fails_open(self):
        import ml.ml_api as api
        model, err = api.load_gen3_model(os.path.join(tempfile.gettempdir(), "no-such-gen3-model.joblib"))
        self.assertIsNone(model)
        self.assertIn("missing", err)

    def test_predict_gen3_endpoint(self):
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            self.skipTest("fastapi test client not installed")
        import ml.ml_api as api
        wrapper = Gen3FModel(_tiny_model(), threshold=0.5)
        client = TestClient(api.app)  # no context manager: startup would reload the (absent) artifacts
        old = api.gen3_model
        try:
            api.gen3_model = None
            self.assertEqual(client.post("/predict-gen3", json={"url": "/"}).status_code, 503)
            api.gen3_model = wrapper
            r = client.post("/predict-gen3", json={"url": "/search?q=<script>alert(1)</script>"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["mode"], "shadow")
            self.assertIn("attack_probability", r.json())
        finally:
            api.gen3_model = old


if __name__ == "__main__":
    unittest.main()
