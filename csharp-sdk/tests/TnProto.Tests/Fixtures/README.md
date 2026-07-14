# Test fixtures

`jwe_*.json` are real RFC 7516 General JSON JWEs sealed by the independent
Python/joserfc implementation and opened by the C# managed interoperability
tests. Regenerate from the repo root with:

    PYTHONPATH=python python csharp-sdk/tests/TnProto.Tests/Fixtures/make_jwe_fixtures.py
