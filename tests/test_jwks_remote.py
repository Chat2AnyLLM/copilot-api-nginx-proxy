import json
import time
import pytest
from unittest.mock import patch, Mock

import verifier


def test_fetch_remote_jwks_success(monkeypatch):
    jwks = {"keys":[{"kty":"RSA","kid":"k1","n":"AA","e":"AQAB"}]}
    mock_resp = Mock()
    mock_resp.raise_for_status = Mock()
    mock_resp.json.return_value = jwks
    with patch("verifier._requests.get", return_value=mock_resp):
        # set env vars for test
        monkeypatch.setenv("JWKS_URL", "https://example.com/jwks.json")
        # reload module-level variables in verifier
        verifier.JWKS_URL = "https://example.com/jwks.json"
        verifier._REMOTE_JWKS = None
        verifier._REMOTE_JWKS_FETCHED_AT = None
        res = verifier._fetch_remote_jwks()
        assert res == jwks
        assert verifier._REMOTE_JWKS == jwks


def test_fetch_remote_jwks_failure_uses_cached(monkeypatch):
    # set a cached value then simulate network failure
    jwks_cached = {"keys":[{"kty":"RSA","kid":"cached","n":"AA","e":"AQAB"}]}
    verifier._REMOTE_JWKS = jwks_cached
    verifier._REMOTE_JWKS_FETCHED_AT = time.time()
    with patch("verifier._requests.get", side_effect=Exception("netfail")):
        monkeypatch.setenv("JWKS_URL", "https://example.com/jwks.json")
        verifier.JWKS_URL = "https://example.com/jwks.json"
        res = verifier._fetch_remote_jwks()
        assert res == jwks_cached


def test_validate_rejects_bad_structure():
    with pytest.raises(ValueError):
        verifier._validate_jwks_structure({"notkeys": []})
    with pytest.raises(ValueError):
        verifier._validate_jwks_structure({"keys":[{"foo":"bar"}]})
