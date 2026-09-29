import base64
import os
import sys
import unittest
from urllib.parse import parse_qsl

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.canonical import canonical_body, canonical_path, canonical_query, canonical_request, reveal_base64
from ml.gen3_model import FEATURE_SET_F, request_features

SQLI = "1' UNION SELECT username,password FROM users--"


class CanonicalFormTests(unittest.TestCase):
    def test_json_and_multipart_become_the_same_form_body(self):
        form = canonical_body(f"id={SQLI}")
        self.assertEqual(canonical_body('{"id": "' + SQLI + '"}'), form)
        mp = f'--X\r\nContent-Disposition: form-data; name="id"\r\n\r\n{SQLI}\r\n--X--\r\n'
        self.assertEqual(canonical_body(mp), form)

    def test_json_attack_gets_exactly_the_form_features(self):
        a = request_features("POST", "/api", f"id={SQLI}")
        b = request_features("POST", "/api", '{"id": "' + SQLI + '"}')
        self.assertEqual({c: a[c] for c in FEATURE_SET_F}, {c: b[c] for c in FEATURE_SET_F})

    def test_nested_json_keeps_leaf_keys_and_scalars(self):
        body = canonical_body('{"user": {"name": "a b", "tags": ["x", "y"], "age": 3, "ok": true, "n": null}}')
        self.assertEqual(parse_qsl(body), [("name", "a b"), ("tags", "x"), ("tags", "y"), ("age", "3"), ("ok", "true")])

    def test_base64_revealed_only_when_it_hides_an_attack(self):
        hidden = base64.b64encode(SQLI.encode()).decode()
        self.assertEqual(reveal_base64(hidden), SQLI)
        self.assertIn("UNION SELECT", canonical_query(f"id={hidden}").replace("+", " "))
        # tokens, IDs and JWT segments stay as they are
        for token in ("dGhpcyBpcyBqdXN0IGEgbm90ZQ==", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                      "a1b2c3d4e5f6a7b8c9d0", "550e8400e29b41d4a716446655440000"):
            self.assertEqual(reveal_base64(token), token)

    def test_single_encoding_undone_double_encoding_kept(self):
        self.assertEqual(canonical_query("q=hello%20world"), "q=hello+world")
        self.assertEqual(canonical_query("id=1%27"), "id=1'")
        self.assertEqual(canonical_query("id=1%2527"), "id=1%2527")

    def test_delimiters_inside_values_round_trip(self):
        q = canonical_query("next=%2Fa%3Fb%3Dc%26d%3De&x=1%2B1%23z")
        self.assertEqual(parse_qsl(q), [("next", "/a?b=c&d=e"), ("x", "1+1#z")])

    def test_thai_and_non_form_bodies(self):
        self.assertEqual(canonical_query("q=%E0%B8%AA%E0%B8%A7%E0%B8%B1%E0%B8%AA%E0%B8%94%E0%B8%B5"), "q=สวัสดี")
        xml = '<?xml version="1.0"?>\n<a b="1">x</a>'
        self.assertEqual(canonical_body(xml), xml)
        self.assertEqual(canonical_body("line one\nline=two"), "line one\nline=two")

    def test_binary_file_part_dropped_field_name_kept(self):
        mp = ('--B\r\nContent-Disposition: form-data; name="f"; filename="a.bin"\r\n\r\n'
              + "\x00\x01\x02\x03\x04\x05" * 20 + '\r\n--B--\r\n')
        self.assertEqual(canonical_body(mp), "f=")

    def test_path_base64_segment(self):
        seg = base64.urlsafe_b64encode(b"../../../../etc/passwd").decode().rstrip("=")
        p = canonical_path(f"/files/{seg}/view")
        self.assertIn("..%2F..%2F", p)
        self.assertEqual(canonical_path("/static/app.js"), "/static/app.js")

    def test_idempotent(self):
        for path, query, body in [("/a", "q=hello%20world&x=%2527", '{"k": "v v"}'),
                                  ("/b", "id=" + base64.b64encode(SQLI.encode()).decode(), ""),
                                  ("/c", "", f"id={SQLI}")]:
            once = canonical_request(path, query, body)
            self.assertEqual(canonical_request(*once), once)


if __name__ == "__main__":
    unittest.main()
