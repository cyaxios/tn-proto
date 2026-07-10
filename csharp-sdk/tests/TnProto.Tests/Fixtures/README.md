# Test fixtures

`jwe_*.json` are real RFC 7516 General JSON JWEs sealed by the repo's
normative Python cipher (`python/tn/cipher.py::_jwe_seal`, joserfc), consumed
by `JweSealedGroupCipherTests`. Regenerate from the repo root with:

    PYTHONPATH=python python csharp-sdk/tests/TnProto.Tests/Fixtures/make_jwe_fixtures.py
