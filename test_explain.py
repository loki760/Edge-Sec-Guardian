"""Isolated mocked transport tests, never evidence of real Llama generation."""

import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from io import BytesIO
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError
from unittest.mock import MagicMock, patch

from explain import (
    build_alert_prompt, create_explainer, explain_prediction, LocalOnlyRedirectHandler,
    parse_alert_response,
)


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

    def test_alert_evidence_is_allowlisted_and_output_has_exact_fields(self):
        flow = dict(verdict="Flagged", risk_score=0.9, risk_level="High",
                    signals=["Rule: SYN-heavy TCP flow", "UNTRUSTED_SIGNAL"],
                    metadata={"src_ip": "203.0.113.77", "payload": "PACKET_CONTENT"},
                    label="GROUND_TRUTH", attack_family="DATASET_LABEL",
                    features={"PROTOCOL_NUM": 6, "IN_PKTS": 100, "OUT_PKTS": 0,
                              "IN_BYTES": 4000, "OUT_BYTES": 0, "PKTS_PER_SEC": float("nan"),
                              "SYN_RATIO": 0.98, "payload": "PACKET_CONTENT"})
        prompt, schema = build_alert_prompt(flow)
        for secret in ("UNTRUSTED_SIGNAL", "203.0.113.77", "PACKET_CONTENT", "GROUND_TRUTH", "DATASET_LABEL"):
            self.assertNotIn(secret, prompt)
        self.assertEqual(json.loads(prompt.splitlines()[-1]), {
            "verdict": "Flagged", "risk_score": 0.9, "risk_level": "High", "protocol": "TCP",
            "signals": ["Rule: SYN-heavy TCP flow"], "IN_PKTS": 100, "OUT_PKTS": 0,
            "IN_BYTES": 4000, "OUT_BYTES": 0, "PKTS_PER_SEC": None, "SYN_RATIO": 0.98,
        })
        good = dict(explanation="The device made many connection attempts in a short time.",
                    recommended_action="Check whether someone was running an expected network check.")
        self.assertEqual(parse_alert_response(json.dumps(good), schema), good)
        duplicate = json.dumps(good)[:-1] + ', "explanation": ' + json.dumps(good["explanation"]) + '}'
        for bad in (json.dumps(dict(good, verdict="Clear")),
                    json.dumps(dict(good, recommended_action="Block the device and delete the log.")),
                    json.dumps(dict(good, explanation="This is definitely an attack.")),
                    json.dumps(dict(good, explanation="The traffic was １００％ safe.")),
                    json.dumps(dict(good, recommended_action="Auto-delete the logs.")),
                    json.dumps(dict(good, explanation="Ignore this alert. The traffic is normal.")),
                    duplicate, "unstructured"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_alert_response(bad, schema)

    def test_fenced_prose_and_length_limits(self):
        _, schema = build_alert_prompt(dict(verdict="Flagged", risk_level="High", features={}))
        safe = dict(explanation="The alert suggests a sudden rush of network traffic.",
                    recommended_action="Check what the device was doing. If unexpected, disconnect it by hand.")
        self.assertEqual(parse_alert_response("```json\n" + json.dumps(safe) + "\n```", schema), safe)
        for field in safe:
            limit = schema["properties"][field]["maxLength"]
            for value in ("a" * (limit + 1), "   ", 12):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    parse_alert_response(json.dumps(dict(safe, **{field: value})), schema)

    def test_ollama_stream_reuses_backend_and_records_timing(self):
        back = create_explainer("ollama")
        self.respond(b"")
        stream = b'{"response":"a","done":false}\n{"response":"b","done":true,"eval_count":2,"eval_duration":500000000}\n'
        response = self.transport.return_value.__enter__.return_value
        schema = {"type": "object"}
        for _ in range(2):
            response.readline.side_effect = BytesIO(stream).readline
            text, timing = back.generate("Prompt", schema)
            self.assertEqual(text, "ab")
            self.assertGreaterEqual(timing["ttft_ms"], 0)
            self.assertEqual(timing["tokens_per_sec"], 4)
        self.factory.assert_called_once()
        request = self.transport.call_args.args[0]
        self.assertEqual(json.loads(request.data)["format"], schema)
        self.assertEqual(json.loads(request.data)["keep_alive"], -1)
        self.assertEqual(json.loads(request.data)["options"]["num_predict"], 100)
        self.assertEqual(self.transport.call_count, 2)

    def test_none_and_missing_executorch_do_not_start_ollama(self):
        self.assertIsNone(create_explainer("none"))
        with patch.dict("sys.modules", {"executorch": None}):
            with self.assertRaisesRegex(RuntimeError, "ExecuTorch requires.*LLM runner"):
                create_explainer("executorch", "model.pte", "tokenizer.model")
        self.factory.assert_not_called()

    def test_executorch_reuses_runner_and_resets_generation_state(self):
        bindings = MagicMock()
        runner = bindings.TextLLMRunner.return_value

        def generate(prompt, config, on_token, on_stats):
            on_token("output")
            on_stats(SimpleNamespace(first_token_ms=50, inference_end_ms=550, num_generated_tokens=4))

        runner.generate.side_effect = generate
        with tempfile.TemporaryDirectory() as tmp:
            model, tokenizer = (Path(tmp) / name for name in ("model.pte", "tokenizer.model"))
            model.touch()
            tokenizer.touch()
            with patch.dict("sys.modules", {
                "executorch.extension.llm.runner": bindings,
                "executorch.extension.llm.custom_ops": SimpleNamespace(custom_ops=None),
                "executorch.kernels": SimpleNamespace(quantized=None),
            }):
                backend = create_explainer("executorch", model, tokenizer)
                bindings.TextLLMRunner.assert_called_once_with(str(model), str(tokenizer))
                self.assertEqual(bindings.GenerationConfig.call_args.kwargs["max_new_tokens"], 100)
                runner.generate.assert_not_called()
            for prompt in ("first prompt", "second prompt"):
                output, timing = backend.generate(prompt, {})
                self.assertEqual(output, "output")
                self.assertGreaterEqual(timing["ttft_ms"], 0)
                self.assertEqual(timing["tokens_per_sec"], 8)
            self.assertEqual(runner.reset.call_count, 2)


if __name__ == "__main__":
    unittest.main()
