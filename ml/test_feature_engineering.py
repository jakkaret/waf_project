import math
import unittest

from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS, extract_features_from_request


class FeatureEngineeringTests(unittest.TestCase):
    def test_feature_schema_is_numeric_and_finite(self):
        features = extract_features_from_request(
            url="/search?q=laptop&page=2&sort=asc",
            method="GET",
            body="",
        )
        self.assertEqual(set(features), set(EXTENDED_FEATURE_COLUMNS))
        self.assertTrue(all(isinstance(value, (int, float)) for value in features.values()))
        self.assertTrue(all(math.isfinite(float(value)) for value in features.values()))

    def test_mutation_and_obfuscation_signals(self):
        features = extract_features_from_request(
            url="/search?q=1/**/UNION/**/SELECT%20CHAR(65,66)",
            method="POST",
            body='{"user":{"$ne":null}}',
        )
        self.assertGreater(features["url_path_entropy"], 0.0)
        self.assertGreater(features["query_body_entropy"], 0.0)
        self.assertGreaterEqual(features["encoded_char_ratio"], 0.0)
        self.assertGreaterEqual(features["delimiter_count"], 4)
        self.assertGreaterEqual(features["comment_token_count"], 2)
        self.assertGreaterEqual(features["inline_function_count"], 1)
        self.assertGreaterEqual(features["json_operator_count"], 1)

    def test_form_encoding_is_decoded_before_signature_matching(self):
        features = extract_features_from_request(
            url="/search?q=1+UNION+SELECT+CHAR%2829%29",
            method="GET",
            body="id=1+OR+1%3D1",
        )
        self.assertGreaterEqual(features["keyword_matches"], 1)
        self.assertEqual(features["has_sql_operator"], 1)


    def test_suspicious_backup_path_marker_is_exposed(self):
        features = extract_features_from_request(
            url="/public/config.bak",
            method="GET",
            body="",
        )
        self.assertEqual(features["suspicious_path_marker_count"], 1)

    def test_restricted_file_probes_are_path_markers(self):
        for probe in ("/.env", "/laravel-app/.env.production.local", "/.env_backup",
                      "/dev/.git/config", "/home/ubuntu/.aws/credentials", "/wp-config.php"):
            features = extract_features_from_request(url=probe, method="GET", body="")
            self.assertGreaterEqual(features["suspicious_path_marker_count"], 1, probe)

    def test_ordinary_paths_are_not_restricted_file_probes(self):
        for path in ("/environment/overview", "/api/v1/envelopes", "/github/readme",
                     "/assets/js/app.js", "/.well-known/acme-challenge/abc123"):
            features = extract_features_from_request(url=path, method="GET", body="")
            self.assertEqual(features["suspicious_path_marker_count"], 0, path)

    def test_encoded_attack_token_is_distinguished_from_plain_encoding(self):
        features = extract_features_from_request(
            url="/search?q=%27+UNION+SELECT",
            method="GET",
            body="",
        )
        self.assertEqual(features["encoded_attack_token_count"], 1)


if __name__ == "__main__":
    unittest.main()
