"""OpenAI-compatible transport with bounded retries and content-addressed caching."""
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from pathlib import Path
from collections import Counter

from .io import digest, read_json, write_json


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward the model Authorization header through an HTTP redirect."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LLMClient:
    def __init__(self, base_url, key_env="VULINSTRUCT_API_KEY", cache_dir="runs/api-cache",
                 max_calls=100, timeout=180, retries=2, max_output_tokens=4096, refresh_cache=False,
                 request_options=None, allow_http=False, stage_request_options=None,
                 stage_max_output_tokens=None):
        self.base_url = base_url.rstrip("/")
        url = urlsplit(self.base_url)
        if not url.hostname or url.username is not None or url.password is not None or url.query or url.fragment:
            raise ValueError("Endpoint must have a host and no credentials, query, or fragment")
        self.loopback = url.hostname in ('localhost', '127.0.0.1', '::1')
        if url.scheme != 'https' and not (url.scheme == 'http' and (self.loopback or allow_http)):
            raise ValueError("Use HTTPS or a loopback model server")
        if type(max_calls) is not int or max_calls < 0 or type(retries) is not int or retries < 0:
            raise ValueError("Request budget and retries must be non-negative integers")
        if type(max_output_tokens) is not int or max_output_tokens < 1 or timeout <= 0:
            raise ValueError("Token budget and timeout must be positive")
        self.opener = urllib.request.build_opener(NoRedirect())
        self.key = os.environ.get(key_env, "")
        self.cache_dir = Path(cache_dir)
        self.max_calls, self.timeout, self.retries = max_calls, timeout, retries
        self.max_output_tokens = max_output_tokens
        self.refresh_cache = refresh_cache
        self.request_options = request_options or {}
        self.stage_request_options = stage_request_options or {}
        self.stage_max_output_tokens = stage_max_output_tokens or {}
        for options in [self.request_options, *self.stage_request_options.values()]:
            if not isinstance(options, dict) or set(options) - {'thinking', 'reasoning_effort', 'response_format'}:
                raise ValueError('Unsupported request option; model/messages/token budget cannot be overridden')
        if any(type(n) is not int or n < 1 for n in self.stage_max_output_tokens.values()):
            raise ValueError('Stage token budgets must be positive integers')
        self.calls, self.cache_hits = 0, 0
        self.lock = threading.Lock()
        self.request_locks = {}
        self.tokens, self.stages, self.returned_models = Counter(), Counter(), set()

    def stats(self):
        with self.lock:
            return {'network_requests': self.calls, 'cache_hits': self.cache_hits,
                    'successful_network_tokens': dict(self.tokens), 'successful_network_stages': dict(self.stages),
                    'returned_model_ids': sorted(self.returned_models)}

    def ask(self, prompt, model, stage):
        body = {"model": model, "messages": [{"role": "user", "content": prompt}]}
        reasoning_model = bool(re.match(r"^(gpt-5|o[134])", model))
        body["max_completion_tokens" if reasoning_model else "max_tokens"] = self.stage_max_output_tokens.get(stage, self.max_output_tokens)
        if not reasoning_model:
            body["temperature"] = 0
        body.update(self.request_options)
        body.update(self.stage_request_options.get(stage, {}))
        fingerprint = digest({"endpoint": self.base_url, "request": body})
        # Paired functions can request identical domain evidence concurrently. One
        # request owns the cache fill; followers read exactly that saved response.
        # Without this, two stochastic responses race and the last writer silently
        # replaces the cache evidence used by an earlier completed sample.
        with self.lock:
            request_lock = self.request_locks.setdefault(fingerprint, threading.Lock())
        with request_lock:
            return self._ask_locked(body, fingerprint, model, stage)

    def _ask_locked(self, body, fingerprint, model, stage):
        path = self.cache_dir / (fingerprint + ".json")
        if path.exists() and not self.refresh_cache:
            cached = read_json(path)
            if cached.get("request_hash") != fingerprint or cached.get('request') != body:
                raise ValueError("Cache fingerprint mismatch")
            with self.lock:
                self.cache_hits += 1
            if cached.get('validation_error'):
                raise ValueError(cached['validation_error'])
            return cached["response"]
        if not self.key and not self.loopback:
            raise ValueError("API key environment variable is not set")
        for attempt in range(self.retries + 1):
            with self.lock:
                if self.calls >= self.max_calls:
                    raise RuntimeError("API call budget reached; completed requests are cached")
                self.calls += 1
            req = urllib.request.Request(self.base_url + "/chat/completions", data=json.dumps(body).encode(),
                                         headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"})
            started = time.monotonic()
            try:
                with self.opener.open(req, timeout=self.timeout) as response:
                    data = json.load(response)
                text = data["choices"][0]["message"].get("content")
                validation_error = None
                if data["choices"][0].get("finish_reason") == "length":
                    validation_error = "Model output truncated; increase max_output_tokens"
                elif not isinstance(text, str) or not text.strip():
                    validation_error = "Model returned no textual response"
                write_json(path, {"request_hash": fingerprint, "stage": stage, "model": model,
                                  "returned_model": data.get('model'), "elapsed_seconds": time.monotonic() - started,
                                  "response": text, "reasoning_present": bool(data['choices'][0]['message'].get('reasoning_content')),
                                  "finish_reason": data['choices'][0].get('finish_reason'),
                                  "validation_error": validation_error,
                                  "usage": data.get("usage"), "request": body})
                with self.lock:
                    self.stages[stage] += 1
                    if data.get('model'):
                        self.returned_models.add(data['model'])
                    for field in ('prompt_tokens', 'completion_tokens', 'total_tokens', 'prompt_cache_hit_tokens'):
                        if isinstance((data.get('usage') or {}).get(field), int):
                            self.tokens[field] += data['usage'][field]
                if validation_error:
                    raise ValueError(validation_error)
                return text
            except urllib.error.HTTPError as exc:
                if exc.code not in (408, 429, 500, 502, 503, 504) or attempt == self.retries:
                    raise RuntimeError("Model endpoint returned HTTP " + str(exc.code)) from None
            except (urllib.error.URLError, TimeoutError):
                if attempt == self.retries:
                    raise RuntimeError("Model endpoint unavailable after bounded retries") from None
            time.sleep(min(2 ** attempt, 8))
        raise RuntimeError("Unreachable retry state")
