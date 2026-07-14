using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using TnProto.Jwe;

namespace TnProto.Tests;

/// <summary>
/// The managed JWE cipher against real wire bytes: the committed
/// fixtures under <c>Fixtures/</c> are RFC 7516 General JSON JWEs sealed
/// by the repo's normative Python cipher (see
/// <c>Fixtures/README.md</c>), and the env-gated interop cases run whole
/// jwe ceremonies through the live Python SDK.
/// </summary>
public sealed class JweSealedGroupCipherTests
{
    // ------------------------------------------------------------------
    // committed fixtures
    // ------------------------------------------------------------------

    private sealed record JweFixture(byte[] Plaintext, byte[] Aad, byte[] Wire, JsonObject Raw)
    {
        public byte[] Key(string member)
        {
            var value = Raw[member]?.GetValue<string>()
                ?? throw new InvalidOperationException($"fixture member {member} missing");
            return Convert.FromBase64String(value);
        }
    }

    private static JweFixture LoadFixture(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", name);
        var raw = JsonNode.Parse(File.ReadAllText(path)) as JsonObject
            ?? throw new InvalidOperationException($"fixture {name} is not a JSON object");
        var aadB64 = raw["aad_b64"]?.GetValue<string>() ?? "";
        return new JweFixture(
            Convert.FromBase64String(raw["plaintext_b64"]!.GetValue<string>()),
            aadB64.Length == 0 ? [] : Convert.FromBase64String(aadB64),
            Encoding.UTF8.GetBytes(raw["jwe"]!.GetValue<string>()),
            raw);
    }

    // ------------------------------------------------------------------
    // cipher unit tests
    // ------------------------------------------------------------------

    [Fact]
    public void SingleRecipientFixtureOpens()
    {
        var fixture = LoadFixture("jwe_single_recipient.json");
        var cipher = new JweSealedGroupCipher(fixture.Key("reader_sk_b64"));

        Assert.Equal("jwe", cipher.Kind);
        Assert.Equal(fixture.Plaintext, cipher.Decrypt(fixture.Wire, []));
    }

    [Fact]
    public void EachRecipientKeyOpensItsOwnBlock()
    {
        var fixture = LoadFixture("jwe_two_recipients.json");

        // Recipient blocks are anonymous (no kid), so each key must find
        // its block by trial decryption; the second key proves the walk
        // moves past a block that is not its own.
        foreach (var member in new[] { "first_recipient_sk_b64", "second_recipient_sk_b64" })
        {
            var cipher = new JweSealedGroupCipher(fixture.Key(member));
            Assert.Equal(fixture.Plaintext, cipher.Decrypt(fixture.Wire, []));
        }
    }

    [Fact]
    public void WrongKeyThrows()
    {
        var fixture = LoadFixture("jwe_single_recipient.json");
        var cipher = new JweSealedGroupCipher(RandomNumberGenerator.GetBytes(32));

        var error = Assert.Throws<TnException>(() => cipher.Decrypt(fixture.Wire, []));
        Assert.Contains("opens", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RevokedKeyWalkOpensPreRotationBlob()
    {
        // The blob is sealed to the OLD reader key only; the cipher gets
        // [current, revoked] in trial order and must fall through to the
        // archived key — the pre-rotation read path.
        var fixture = LoadFixture("jwe_rotation_walk.json");
        var cipher = new JweSealedGroupCipher(
            fixture.Key("current_sk_b64"),
            fixture.Key("revoked_sk_b64"));

        Assert.Equal(fixture.Plaintext, cipher.Decrypt(fixture.Wire, []));
    }

    [Fact]
    public void AadBoundFixtureOpensOnlyWithExactAad()
    {
        var fixture = LoadFixture("jwe_aad_bound.json");
        var cipher = new JweSealedGroupCipher(fixture.Key("reader_sk_b64"));

        Assert.Equal(fixture.Plaintext, cipher.Decrypt(fixture.Wire, fixture.Aad));

        // One flipped marker byte fails, and so does binding no marker at
        // all while the wire carries the aad member.
        var wrong = (byte[])fixture.Aad.Clone();
        wrong[^1] ^= 0x01;
        var wrongError = Assert.Throws<TnException>(() => cipher.Decrypt(fixture.Wire, wrong));
        Assert.Contains("aad marker mismatch", wrongError.Message, StringComparison.Ordinal);

        var missingError = Assert.Throws<TnException>(() => cipher.Decrypt(fixture.Wire, []));
        Assert.Contains("aad marker mismatch", missingError.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void PlainFixtureRejectsUnexpectedAad()
    {
        // The other direction of the aad rule: the member is absent but
        // the caller binds a marker — the envelope must stay sealed.
        var fixture = LoadFixture("jwe_single_recipient.json");
        var cipher = new JweSealedGroupCipher(fixture.Key("reader_sk_b64"));

        var error = Assert.Throws<TnException>(() =>
            cipher.Decrypt(fixture.Wire, "{\"case\":\"A-17\"}"u8.ToArray()));
        Assert.Contains("aad marker mismatch", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("complete garbage, not json")]
    [InlineData("{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"iv\":\"AAAA")]
    [InlineData("[1,2,3]")]
    [InlineData("\"a json string\"")]
    [InlineData("{\"protected\":\"eyJlbmMiOiJBMjU2R0NNIn0\",\"iv\":\"AAAA\",\"ciphertext\":\"AAAA\"}")]
    [InlineData("{\"protected\":\"x\",\"iv\":\"x\",\"ciphertext\":\"x\",\"tag\":\"x\"}")]
    [InlineData("{\"protected\":\"x\",\"iv\":\"x\",\"ciphertext\":\"x\",\"tag\":\"x\",\"recipients\":{}}")]
    [InlineData("{\"protected\":\"x\",\"iv\":\"x\",\"ciphertext\":\"x\",\"tag\":\"x\",\"recipients\":[7]}")]
    [InlineData("{\"protected\":\"x\",\"iv\":\"x\",\"ciphertext\":\"x\",\"tag\":\"x\",\"recipients\":[{}]}")]
    [InlineData("{\"protected\":\"x\",\"iv\":\"x\",\"ciphertext\":\"x\",\"tag\":\"x\",\"aad\":7,\"recipients\":[]}")]
    [InlineData("{\"protected\":\"!!\",\"iv\":\"!!\",\"ciphertext\":\"!!\",\"tag\":\"!!\",\"recipients\":[]}")]
    public void MalformedCiphertextThrows(string wire)
    {
        // Mirrors _validate_jwe_general_json_shape: a malformed envelope
        // throws (the unseal seam swallows it per block) rather than
        // leaking a library TypeError/KeyError equivalent.
        var fixture = LoadFixture("jwe_single_recipient.json");
        var cipher = new JweSealedGroupCipher(fixture.Key("reader_sk_b64"));

        Assert.Throws<TnException>(() => cipher.Decrypt(Encoding.UTF8.GetBytes(wire), []));
    }

    [Fact]
    public void TruncatedRealEnvelopeThrows()
    {
        var fixture = LoadFixture("jwe_single_recipient.json");
        var cipher = new JweSealedGroupCipher(fixture.Key("reader_sk_b64"));

        Assert.Throws<TnException>(() =>
            cipher.Decrypt(fixture.Wire.AsSpan(0, fixture.Wire.Length / 2).ToArray(), []));
    }

    [Fact]
    public void CtorRejectsMissingOrMalformedKeys()
    {
        Assert.Throws<ArgumentException>(() => new JweSealedGroupCipher());
        Assert.Throws<ArgumentException>(() => new JweSealedGroupCipher(new byte[31]));
        Assert.Throws<ArgumentException>(
            () => new JweSealedGroupCipher(RandomNumberGenerator.GetBytes(32), new byte[33]));
    }

    // ------------------------------------------------------------------
    // keystore loader
    // ------------------------------------------------------------------

    [Fact]
    public void LoadGroupCiphersWalksCurrentAndRevokedKeys()
    {
        var fixture = LoadFixture("jwe_rotation_walk.json");
        var keystore = NewTempDir();
        // The post-rotation layout Python's tn.admin.rotate leaves
        // behind: a fresh mykey plus the prior reader key archived under
        // .revoked.<ts>.
        File.WriteAllBytes(Path.Combine(keystore, "default.jwe.mykey"), fixture.Key("current_sk_b64"));
        File.WriteAllBytes(
            Path.Combine(keystore, "default.jwe.mykey.revoked.1751900000"),
            fixture.Key("revoked_sk_b64"));
        // Non-key jwe siblings, other-cipher files, and a truncated key
        // never become (or break) groups.
        File.WriteAllBytes(Path.Combine(keystore, "default.jwe.sender"), RandomNumberGenerator.GetBytes(32));
        File.WriteAllText(Path.Combine(keystore, "default.jwe.recipients"), "[]");
        File.WriteAllBytes(Path.Combine(keystore, "other.btn.mykit"), RandomNumberGenerator.GetBytes(64));
        File.WriteAllBytes(Path.Combine(keystore, "corrupt.jwe.mykey"), new byte[31]);

        var ciphers = JweKeystore.LoadGroupCiphers(keystore);

        var cipher = Assert.Contains("default", ciphers);
        Assert.Single(ciphers);
        Assert.Equal("jwe", cipher.Kind);
        // The blob only the ARCHIVED key opens proves the loader queues
        // .revoked.<ts> keys behind the current one.
        Assert.Equal(fixture.Plaintext, cipher.Decrypt(fixture.Wire, []));
    }

    [Fact]
    public void LoadGroupCiphersSurvivesUnreadableCurrentKey()
    {
        var fixture = LoadFixture("jwe_rotation_walk.json");
        var keystore = NewTempDir();
        File.WriteAllBytes(Path.Combine(keystore, "default.jwe.mykey"), new byte[31]);
        File.WriteAllBytes(
            Path.Combine(keystore, "default.jwe.mykey.revoked.1751900000"),
            fixture.Key("revoked_sk_b64"));

        var ciphers = JweKeystore.LoadGroupCiphers(keystore);

        // The truncated current key is skipped silently; the archived key
        // still carries the group (that epoch's entries stay readable).
        var cipher = Assert.Contains("default", ciphers);
        Assert.Equal(fixture.Plaintext, cipher.Decrypt(fixture.Wire, []));
    }

    [Fact]
    public void LoadGroupCiphersMissingDirectoryIsEmpty()
    {
        var missing = Path.Combine(Path.GetTempPath(), "tn-csharp-jwe-nodir-" + Guid.NewGuid().ToString("N"));
        Assert.Empty(JweKeystore.LoadGroupCiphers(missing));
    }

    // ------------------------------------------------------------------
    // the UnsealAsync second-pass seam
    // ------------------------------------------------------------------

    [Fact]
    public async Task UnsealOpensJweBlockThroughManagedCipher()
    {
        var fixture = LoadFixture("jwe_single_recipient.json");
        await using var tn = await Tn.InitProjectAsync(
            "jwe_seam",
            new TnProjectOptions { ProjectDirectory = NewTempDir() });

        var result = await tn.UnsealAsync(
            EnvelopeWithJweBlock(fixture).ToJsonString(),
            new UnsealOptions
            {
                Verify = false,
                GroupCiphers = new Dictionary<string, ISealedGroupCipher>
                {
                    ["partners"] = new JweSealedGroupCipher(fixture.Key("reader_sk_b64")),
                },
            });

        var partners = Assert.Contains("partners", result.Plaintext);
        Assert.Equal("for the fixture reader", partners["body"]?.GetValue<string>());
        Assert.Equal("for the fixture reader", result.Fields["body"]?.GetValue<string>());
        Assert.Empty(result.HiddenGroups);
        Assert.Empty(result.SealedBlocks);
    }

    [Fact]
    public async Task UnsealKeepsJweBlockSealedOnWrongKey()
    {
        var fixture = LoadFixture("jwe_single_recipient.json");
        await using var tn = await Tn.InitProjectAsync(
            "jwe_seam",
            new TnProjectOptions { ProjectDirectory = NewTempDir() });

        var result = await tn.UnsealAsync(
            EnvelopeWithJweBlock(fixture).ToJsonString(),
            new UnsealOptions
            {
                Verify = false,
                GroupCiphers = new Dictionary<string, ISealedGroupCipher>
                {
                    ["partners"] = new JweSealedGroupCipher(RandomNumberGenerator.GetBytes(32)),
                },
            });

        // The wrong-key throw is swallowed by the seam: no crash, the
        // block simply stays sealed.
        Assert.Equal(["partners"], result.HiddenGroups);
        var block = Assert.Single(result.SealedBlocks);
        Assert.Equal("partners", block.Name);
        Assert.Empty(result.Plaintext);
        Assert.False(result.Fields.ContainsKey("body"));
    }

    private static JsonObject EnvelopeWithJweBlock(JweFixture fixture)
    {
        return new JsonObject
        {
            ["device_identity"] = "did:key:zTestPublisher",
            ["timestamp"] = "2026-07-09T00:00:00.000000Z",
            ["event_id"] = "00000000-0000-0000-0000-000000000000",
            ["event_type"] = "obj.memo.v1",
            ["level"] = "",
            ["sequence"] = 0,
            ["prev_hash"] = "",
            ["row_hash"] = "unverified",
            ["signature"] = "unverified",
            ["tn_sealed"] = 1,
            ["partners"] = new JsonObject
            {
                ["ciphertext"] = Convert.ToBase64String(fixture.Wire),
                ["field_hashes"] = new JsonObject { ["body"] = "tok" },
            },
        };
    }

    // ------------------------------------------------------------------
    // Python interop (env-gated, like InteropTests)
    // ------------------------------------------------------------------

    [Fact]
    public async Task PythonJweCeremonySealsCSharpOpensManaged()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var output = await RunPythonAsync(
            """
            import sys

            import tn

            tn.init(sys.argv[1], cipher="jwe")
            sealed = tn.seal(
                "obj.invoice.v1",
                receipt=False,
                aad={"case": "A-17"},
                amount=9800,
                customer="acme",
            )
            print("KEYSTORE=" + str(tn.current_config().keystore))
            print("SEALED=" + str(sealed))
            tn.flush_and_close()
            """,
            projectDir,
            Path.Combine(projectDir, "tn.yaml"));
        var keystore = ValueAfterPrefix(output, "KEYSTORE=");
        var sealedLine = ValueAfterPrefix(output, "SEALED=");

        await using var reader = await Tn.InitProjectAsync(
            "interop_jwe_reader",
            new TnProjectOptions { ProjectDirectory = NewTempDir() });

        // The fresh reader ceremony has no matching JWE private key, so this
        // first pass verifies the envelope while leaving the group sealed.
        var nativeOnly = await reader.UnsealAsync(sealedLine);
        Assert.True(nativeOnly.Valid.Signature);
        Assert.True(nativeOnly.Valid.RowHash);
        Assert.Equal(["default"], nativeOnly.HiddenGroups);

        // Second pass with the ceremony keystore's managed cipher. The
        // aad seal above makes this exercise the whole marker path: the
        // native walk reconstructs the bound bytes from the tn_aad echo
        // and the managed cipher matches them against the JWE aad member.
        var result = await reader.UnsealAsync(
            sealedLine,
            new UnsealOptions { GroupCiphers = JweKeystore.LoadGroupCiphers(keystore) });

        Assert.True(result.Valid.Signature);
        Assert.True(result.Valid.RowHash);
        Assert.Empty(result.HiddenGroups);
        Assert.Empty(result.SealedBlocks);
        Assert.Equal(9800, result.Fields["amount"]?.GetValue<int>());
        Assert.Equal("acme", result.Fields["customer"]?.GetValue<string>());
        var defaultPlaintext = Assert.Contains("default", result.Plaintext);
        Assert.Equal(9800, defaultPlaintext["amount"]?.GetValue<int>());
    }

    [Fact]
    public async Task PythonJweRotationCSharpOpensViaRevokedKeyWalk()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var output = await RunPythonAsync(
            """
            import sys

            import tn

            tn.init(sys.argv[1], cipher="jwe")
            pre = tn.seal("obj.invoice.v1", receipt=False, amount=1)
            tn.admin.rotate("default")
            post = tn.seal("obj.invoice.v1", receipt=False, amount=2)
            print("KEYSTORE=" + str(tn.current_config().keystore))
            print("PRE=" + str(pre))
            print("POST=" + str(post))
            tn.flush_and_close()
            """,
            projectDir,
            Path.Combine(projectDir, "tn.yaml"));
        var keystore = ValueAfterPrefix(output, "KEYSTORE=");

        // The rotation archived the pre-rotation reader key on disk.
        Assert.Contains(
            Directory.EnumerateFiles(keystore).Select(Path.GetFileName),
            name => name!.StartsWith("default.jwe.mykey.revoked.", StringComparison.Ordinal));

        await using var reader = await Tn.InitProjectAsync(
            "interop_jwe_reader",
            new TnProjectOptions { ProjectDirectory = NewTempDir() });
        var ciphers = JweKeystore.LoadGroupCiphers(keystore);

        // The pre-rotation object only opens through the revoked-key
        // walk; the post-rotation object proves the fresh mykey rides
        // first. One loaded cipher set serves both epochs.
        foreach (var (line, amount) in new[]
        {
            (ValueAfterPrefix(output, "PRE="), 1),
            (ValueAfterPrefix(output, "POST="), 2),
        })
        {
            var result = await reader.UnsealAsync(
                line,
                new UnsealOptions { GroupCiphers = ciphers });
            Assert.True(result.Valid.Signature);
            Assert.True(result.Valid.RowHash);
            Assert.Empty(result.HiddenGroups);
            Assert.Equal(amount, result.Fields["amount"]?.GetValue<int>());
        }
    }

    [Fact]
    public async Task PythonJweMixedObjectOpensManagedAlongsideNative()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var output = await RunPythonAsync(
            """
            import sys

            import yaml as _yaml

            import tn

            yaml_path = sys.argv[1]
            tn.init(yaml_path, cipher="jwe")
            tn.flush_and_close()

            with open(yaml_path, encoding="utf-8") as fh:
                doc = _yaml.safe_load(fh.read())
            doc["vault"]["enabled"] = False
            doc["ceremony"]["mode"] = "local"
            doc["public_fields"].append("memo")
            with open(yaml_path, "w", encoding="utf-8") as fh:
                fh.write(_yaml.safe_dump(doc, allow_unicode=True))

            tn.init(yaml_path)
            tn.admin.ensure_group(tn.current_config(), "partners", fields=["secret"])
            tn.flush_and_close()

            tn.init(yaml_path)
            sealed = tn.seal(
                "obj.mixed.v1",
                receipt=False,
                amount=5,
                secret="for partners only",
                memo="public note",
            )
            print("KEYSTORE=" + str(tn.current_config().keystore))
            print("SEALED=" + str(sealed))
            tn.flush_and_close()
            """,
            projectDir,
            Path.Combine(projectDir, "tn.yaml"));
        var keystore = ValueAfterPrefix(output, "KEYSTORE=");
        var sealedLine = ValueAfterPrefix(output, "SEALED=");

        await using var reader = await Tn.InitProjectAsync(
            "interop_jwe_reader",
            new TnProjectOptions { ProjectDirectory = NewTempDir() });
        var ciphers = JweKeystore.LoadGroupCiphers(keystore);
        Assert.True(ciphers.ContainsKey("default"));
        Assert.True(ciphers.ContainsKey("partners"));

        var result = await reader.UnsealAsync(
            sealedLine,
            new UnsealOptions { GroupCiphers = ciphers });

        // Signature/row-hash checks and the public field come from the
        // native pass; both jwe blocks open managed and merge in.
        Assert.True(result.Valid.Signature);
        Assert.True(result.Valid.RowHash);
        Assert.Equal("public note", result.Fields["memo"]?.GetValue<string>());
        Assert.Equal(5, result.Fields["amount"]?.GetValue<int>());
        Assert.Equal("for partners only", result.Fields["secret"]?.GetValue<string>());
        Assert.Empty(result.HiddenGroups);
        Assert.Contains("default", result.Plaintext);
        Assert.Contains("partners", result.Plaintext);
    }

    // ------------------------------------------------------------------
    // interop plumbing — mirrors InteropTests' private helpers,
    // duplicated so this slice does not edit that file
    // ------------------------------------------------------------------

    private const string InteropAllEnv = "TN_CSHARP_INTEROP";

    private const string PythonInteropEnv = "TN_CSHARP_INTEROP_PYTHON";

    private static string NewTempDir()
    {
        var path = Path.Combine(Path.GetTempPath(), "tn-csharp-jwe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static async Task<bool> PythonReadyAsync()
    {
        if (Environment.GetEnvironmentVariable(InteropAllEnv) != "1"
            && Environment.GetEnvironmentVariable(PythonInteropEnv) != "1")
        {
            return false;
        }

        var output = await RunPythonAsync(
            """
            import tn
            print("ok")
            """,
            Directory.GetCurrentDirectory());
        return output.Contains("ok", StringComparison.Ordinal);
    }

    private static Task<string> RunPythonAsync(string script, string workingDirectory, params string[] args)
    {
        var pythonPath = Path.Combine(FindRepoRoot(), "python");
        return RunProcessAsync("python", ["-", .. args], script, workingDirectory, pythonPath);
    }

    private static async Task<string> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> args,
        string stdin,
        string workingDirectory,
        string? pythonPath = null)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        foreach (var arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        if (pythonPath is not null)
        {
            psi.Environment["PYTHONPATH"] = pythonPath;
        }

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"failed to start {fileName}");
        await process.StandardInput.WriteAsync(stdin).ConfigureAwait(false);
        await process.StandardInput.DisposeAsync().ConfigureAwait(false);

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().ConfigureAwait(false);
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"{fileName} exited {process.ExitCode}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        }

        return stdout;
    }

    private static string ValueAfterPrefix(string output, string prefix)
    {
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith(prefix, StringComparison.Ordinal))
            {
                return trimmed[prefix.Length..].Trim();
            }
        }

        throw new InvalidOperationException($"no line starting with {prefix} found in output:\n{output}");
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "python"))
                && Directory.Exists(Path.Combine(directory.FullName, "csharp-sdk")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("could not locate tn-proto repository root");
    }
}
