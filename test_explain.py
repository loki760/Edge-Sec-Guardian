"""Isolated mocked transport tests, never evidence of real Llama generation."""

import copy
import json
import unittest
from io import BytesIO
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError
from unittest.mock import MagicMock, patch

from explain import explain_prediction, LocalOnlyRedirectHandler


class ExplainTests(unittest.TestCase):
    def setUp(self):
        self.features = dict(proto="tcp", service="http", state="FIN", dur=0.1,
                             spkts=5, dpkts=4, sbytes=300, dbytes=600, rate=90,
                             id="SECRET_ID", label="SECRET_TRUTH",
                             attack_cat="SECRET_CATEGORY")
        self.prediction = dict(label=1, prediction="attack", attack_probability=0.8)
        self.patcher = patch("explain.build_opener")
        self.factory = self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.transport = self.factory.return_value.open

    def respond(self, value):
        response = MagicMock()
        response.read.return_value = value
        response.geturl.return_value = "http://localhost:11434/api/generate"
        self.transport.return_value.__enter__.return_value = response

    def test_success_and_request_contract(self):
        before = copy.deepcopy((self.features, self.prediction))
        self.respond(b'{"done":true,"response":" Mock unit prose. "}')
        self.assertEqual(explain_prediction(self.features, self.prediction),
                         "Mock unit prose.")
        request = self.transport.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(request.method, "POST")
        self.assertEqual(payload["model"], "llama3.2:1b")
        self.assertIs(payload["stream"], False)
        self.assertEqual(payload["options"], {"temperature": 0, "num_predict": 160})
        self.assertEqual(self.transport.call_args.kwargs["timeout"], 60)
        for secret in ("SECRET_ID", "SECRET_TRUTH", "SECRET_CATEGORY", "attack_cat"):
            self.assertNotIn(secret, payload["prompt"])
        self.assertIn('"attack_probability": 0.8', payload["prompt"])
        self.assertEqual(before, (self.features, self.prediction))

    def test_response_failures(self):
        for value in (b'no json', b'\xff', b'[]', b'null', b'{}',
                      b'{"done":false,"response":"partial"}',
                      b'{"done":1,"response":"partial"}',
                      b'{"done":true,"response":" "}',
                      b'{"done":true,"response":123}',
                      b'{"done":true,"error":"missing model"}'):
            with self.subTest(value=value):
                self.respond(value)
                with self.assertRaises(RuntimeError):
                    explain_prediction(self.features, self.prediction)

    def test_transport_failures(self):
        for error in (URLError("connection refused"), TimeoutError("timeout"),
                      IncompleteRead(b"partial", 50),
                      OSError("connection reset"),
                      HTTPError("local", 404, "missing model", {}, BytesIO())):
            with self.subTest(error=error):
                self.transport.side_effect = error
                with self.assertRaises(RuntimeError):
                    explain_prediction(self.features, self.prediction)

    def test_invalid_model_url_and_prediction_make_no_request(self):
        for arguments in ({"model": "llama3.2"},
                          {"base_url": "https://example.com"},
                          {"base_url": "http://localhost@other.example"}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                explain_prediction(self.features, self.prediction, **arguments)
        with self.assertRaises(ValueError):
            explain_prediction(self.features, dict(self.prediction, label=0))
        self.transport.assert_not_called()

    def test_host_url_and_custom_timeout(self):
        self.respond(b'{"done":true,"response":"Unit fixture"}')
        response = self.transport.return_value.__enter__.return_value
        response.geturl.return_value = "http://host.docker.internal:11434/api/generate"
        explain_prediction(self.features, self.prediction,
                           base_url="http://host.docker.internal:11434/", timeout=10)
        self.assertEqual(self.transport.call_args.kwargs["timeout"], 10)

    def test_redirects_are_refused(self):
        handler = LocalOnlyRedirectHandler()
        self.assertIsNone(handler.redirect_request(None, None, 302, "", {},
                                                  "https://example.com"))


if __name__ == "__main__":
    unittest.main()
