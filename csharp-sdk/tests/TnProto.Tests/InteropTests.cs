using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using TnProto.Inbox;

namespace TnProto.Tests;

public sealed class InteropTests
{
    private const string InteropAllEnv = "TN_CSHARP_INTEROP";

    private const string PythonInteropEnv = "TN_CSHARP_INTEROP_PYTHON";

    private const string TypeScriptInteropEnv = "TN_CSHARP_INTEROP_TYPESCRIPT";

    private const string RustInteropEnv = "TN_CSHARP_INTEROP_RUST";

    [Fact]
    public async Task PythonEmitsCSharpReads()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var yamlPath = LastNonEmptyLine(await RunPythonAsync(
            """
            import tn

            tn.init("interop_py")
            tn.info("py.csharp_interop.created", marker="python-to-csharp")
            print(tn.current_config().yaml_path)
            tn.flush_and_close()
            """,
            projectDir));

        await using var tn = await Tn.InitAsync(yamlPath);
        var entries = await tn.ReadAsync(new ReadOptions { AllRuns = true });
        var entry = Assert.Single(entries.Where(e => e.EventType == "py.csharp_interop.created"));

        Assert.Equal("python-to-csharp", entry.GetString("marker"));
    }

    [Fact]
    public async Task CSharpEmitsPythonReads()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var yamlPath = Path.Combine(projectDir, ".tn", "interop_cs", "tn.yaml");

        await using (var tn = await Tn.InitProjectAsync(
            "interop_cs",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await tn.InfoAsync("cs.python_interop.created", new { marker = "csharp-to-python" });
            yamlPath = tn.YamlPath;
        }

        var output = await RunPythonAsync(
            """
            import json
            import sys

            import tn

            tn.init(sys.argv[1])
            rows = []
            for entry in tn.read(all_runs=True):
                rows.append({
                    "event_type": getattr(entry, "event_type", None),
                    "fields": getattr(entry, "fields", {}),
                })
            print(json.dumps(rows, sort_keys=True))
            tn.flush_and_close()
            """,
            projectDir,
            yamlPath);

        Assert.Contains("cs.python_interop.created", output, StringComparison.Ordinal);
        Assert.Contains("csharp-to-python", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TypeScriptEmitsCSharpReads()
    {
        if (!await TypeScriptReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var yamlPath = (await RunNodeAsync(
            """
            import { Tn } from "./dist/tn.js";
            import { join } from "node:path";

            const projectDir = process.argv[1];
            const tn = await Tn.init(join(projectDir, "tn.yaml"), {
              stdout: false,
            });
            tn.info("ts.csharp_interop.created", { marker: "typescript-to-csharp" });
            console.log(tn.yamlPath);
            await tn.close();
            """,
            projectDir)).Trim();

        await using var tn = await Tn.InitAsync(yamlPath);
        var entries = await tn.ReadAsync(new ReadOptions { AllRuns = true });
        var entry = Assert.Single(entries.Where(e => e.EventType == "ts.csharp_interop.created"));

        Assert.Equal("typescript-to-csharp", entry.GetString("marker"));
    }

    [Fact]
    public async Task CSharpEmitsTypeScriptReads()
    {
        if (!await TypeScriptReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        string yamlPath;

        await using (var tn = await Tn.InitProjectAsync(
            "interop_cs",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await tn.InfoAsync("cs.typescript_interop.created", new { marker = "csharp-to-typescript" });
            yamlPath = tn.YamlPath;
        }

        var output = await RunNodeAsync(
            """
            import { Tn } from "./dist/tn.js";

            const yamlPath = process.argv[1];
            const tn = await Tn.init(yamlPath, { stdout: false });
            const rows = Array.from(tn.read({ allRuns: true })).map((entry) => ({
              event_type: entry.event_type,
              fields: entry.fields ?? entry,
            }));
            console.log(JSON.stringify(rows));
            await tn.close();
            """,
            yamlPath);

        Assert.Contains("cs.typescript_interop.created", output, StringComparison.Ordinal);
        Assert.Contains("csharp-to-typescript", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CSharpAdminSnapshotPythonAbsorbs()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var producerDir = NewTempDir();
        var packagePath = Path.Combine(producerDir, "csharp-admin-snapshot.tnpkg");

        await using (var producer = await Tn.InitProjectAsync(
            "interop_cs",
            new TnProjectOptions { ProjectDirectory = producerDir }))
        {
            await producer.Admin.EnsureGroupAsync("payments", ["order_id", "amount"]);
            await producer.InfoAsync("cs.package.created", new { order_id = "CS-PY-100", amount = 42 });
            await producer.Packages.ExportAdminSnapshotAsync(packagePath);
        }

        var output = await RunPythonAsync(
            """
            import json
            import sys

            import tn

            tn.init("py_consumer")
            receipt = tn.pkg.absorb(sys.argv[1])
            print(json.dumps({
                "kind": getattr(receipt, "kind", None),
                "legacy_status": getattr(receipt, "legacy_status", None),
                "accepted_count": getattr(receipt, "accepted_count", None),
                "deduped_count": getattr(receipt, "deduped_count", None),
                "noop": getattr(receipt, "noop", None),
            }, sort_keys=True))
            tn.flush_and_close()
            """,
            producerDir,
            packagePath);

        var receipt = LastJsonObject(output);
        Assert.Equal("admin_log_snapshot", receipt["kind"]?.GetValue<string>());
        Assert.NotEqual("rejected", receipt["legacy_status"]?.GetValue<string>());
    }

    [Fact]
    public async Task PythonAdminSnapshotCSharpAbsorbs()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var packagePath = Path.Combine(projectDir, "python-admin-snapshot.tnpkg");

        await RunPythonAsync(
            """
            import sys

            import tn

            tn.init("py_producer")
            tn.info("py.package.created", marker="python-package-to-csharp")
            tn.pkg.export(sys.argv[1], kind="admin_log_snapshot")
            tn.flush_and_close()
            """,
            projectDir,
            packagePath);

        await using var consumer = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var receipt = await consumer.Packages.AbsorbAsync(packagePath);

        Assert.Equal("admin_log_snapshot", receipt.Kind);
        Assert.False(receipt.Rejected);
    }

    [Fact]
    public async Task CSharpAdminSnapshotTypeScriptAbsorbs()
    {
        if (!await TypeScriptReadyAsync())
        {
            return;
        }

        var producerDir = NewTempDir();
        var packagePath = Path.Combine(producerDir, "csharp-admin-snapshot.tnpkg");

        await using (var producer = await Tn.InitProjectAsync(
            "interop_cs",
            new TnProjectOptions { ProjectDirectory = producerDir }))
        {
            await producer.Admin.EnsureGroupAsync("payments", ["order_id", "amount"]);
            await producer.InfoAsync("cs.package.created", new { order_id = "CS-TS-100", amount = 42 });
            await producer.Packages.ExportAdminSnapshotAsync(packagePath);
        }

        var output = await RunNodeAsync(
            """
            import { Tn } from "./dist/tn.js";
            import { join } from "node:path";

            const pkgPath = process.argv[1];
            const projectDir = process.argv[2];
            const tn = await Tn.init(join(projectDir, "tn.yaml"), {
              stdout: false,
            });
            const receipt = await tn.pkg.absorb(pkgPath);
            console.log(JSON.stringify(receipt));
            await tn.close();
            """,
            packagePath,
            producerDir);

        var receipt = LastJsonObject(output);
        Assert.Equal("admin_log_snapshot", receipt["kind"]?.GetValue<string>());
        Assert.True(receipt["rejectedReason"] is null || receipt["rejectedReason"]!.GetValue<string>() is "");
    }

    [Fact]
    public async Task TypeScriptAdminSnapshotCSharpAbsorbs()
    {
        if (!await TypeScriptReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var packagePath = Path.Combine(projectDir, "typescript-admin-snapshot.tnpkg");

        await RunNodeAsync(
            """
            import { Tn } from "./dist/tn.js";
            import { join } from "node:path";

            const pkgPath = process.argv[1];
            const projectDir = process.argv[2];
            const tn = await Tn.init(join(projectDir, "tn.yaml"), {
              stdout: false,
            });
            tn.info("ts.package.created", { marker: "typescript-package-to-csharp" });
            await tn.pkg.export({ adminLogSnapshot: true }, pkgPath);
            await tn.close();
            """,
            packagePath,
            projectDir);

        await using var consumer = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var receipt = await consumer.Packages.AbsorbAsync(packagePath);

        Assert.Equal("admin_log_snapshot", receipt.Kind);
        Assert.False(receipt.Rejected);
    }

    [Fact]
    public async Task RustEmitsCSharpReads()
    {
        if (!await RustReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        await RunRustCliAsync("init", "interop_rs", "--project-dir", projectDir);
        var yamlPath = Path.Combine(projectDir, ".tn", "interop_rs", "tn.yaml");
        await RunRustCliAsync(
            "info",
            "rs.csharp_interop.created",
            "--yaml",
            yamlPath,
            "--fields",
            """{"marker":"rust-to-csharp"}""");

        await using var reopened = await Tn.InitAsync(yamlPath);
        var entries = await reopened.ReadAsync(new ReadOptions { AllRuns = true });
        var entry = Assert.Single(entries.Where(e => e.EventType == "rs.csharp_interop.created"));

        Assert.Equal("rust-to-csharp", entry.GetString("marker"));
    }

    [Fact]
    public async Task CSharpEmitsRustReads()
    {
        if (!await RustReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        string yamlPath;

        await using (var tn = await Tn.InitProjectAsync(
            "interop_cs",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await tn.InfoAsync("cs.rust_interop.created", new { marker = "csharp-to-rust" });
            yamlPath = tn.YamlPath;
        }

        var output = await RunRustCliAsync(
            "read",
            "--yaml",
            yamlPath,
            "--all-runs");

        Assert.Contains("cs.rust_interop.created", output, StringComparison.Ordinal);
        Assert.Contains("csharp-to-rust", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RustAdminSnapshotCSharpAbsorbs()
    {
        if (!await RustReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        await RunRustCliAsync("init", "interop_rs", "--project-dir", projectDir);
        var yamlPath = Path.Combine(projectDir, ".tn", "interop_rs", "tn.yaml");
        var packagePath = Path.Combine(projectDir, "rust-admin-snapshot.tnpkg");

        await RunRustCliAsync(
            "pkg",
            "export",
            "admin-snapshot",
            "--yaml",
            yamlPath,
            "--out",
            packagePath);

        await using var consumer = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var receipt = await consumer.Packages.AbsorbAsync(packagePath);

        Assert.Equal("admin_log_snapshot", receipt.Kind);
        Assert.False(receipt.Rejected);
    }

    [Fact]
    public async Task CSharpAdminSnapshotRustAbsorbs()
    {
        if (!await RustReadyAsync())
        {
            return;
        }

        var producerDir = NewTempDir();
        var consumerDir = NewTempDir();
        var packagePath = Path.Combine(producerDir, "csharp-admin-snapshot.tnpkg");

        await using (var producer = await Tn.InitProjectAsync(
            "interop_cs",
            new TnProjectOptions { ProjectDirectory = producerDir }))
        {
            await producer.Admin.EnsureGroupAsync("payments", ["order_id", "amount"]);
            await producer.InfoAsync("cs.package.rust", new { order_id = "CS-RS-100", amount = 42 });
            await producer.Packages.ExportAdminSnapshotAsync(packagePath);
        }

        await RunRustCliAsync("init", "interop_rs_consumer", "--project-dir", consumerDir);
        var yamlPath = Path.Combine(consumerDir, ".tn", "interop_rs_consumer", "tn.yaml");
        var output = await RunRustCliAsync(
            "pkg",
            "absorb",
            packagePath,
            "--yaml",
            yamlPath);

        Assert.Contains("kind: admin_log_snapshot", output, StringComparison.Ordinal);
        Assert.DoesNotContain("status: Rejected", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CSharpInvitePythonAccepts()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var invitePath = Path.Combine(projectDir, "tn-invite-csharp-python.zip");

        await using (var producer = await Tn.InitProjectAsync(
            "interop_cs",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await producer.Inbox.MintInviteAsync(
                "did:key:zPythonInviteRecipient",
                invitePath,
                new MintInvitationOptions
                {
                    FromEmail = "csharp@example.test",
                    InvitationId = "csharp-python",
                });
        }

        var output = await RunPythonAsync(
            """
            import json
            import sys
            from pathlib import Path

            import tn
            from tn import inbox

            tn.init("py_invite_consumer")
            yaml_path = tn.current_config().yaml_path
            tn.flush_and_close()

            result = inbox.accept(Path(sys.argv[1]), yaml_path=yaml_path)
            print(json.dumps({
                "group_name": result["group_name"],
                "from_email": result["from_email"],
                "kit_path": result["kit_path"],
                "kit_exists": Path(result["kit_path"]).exists(),
            }, sort_keys=True))
            """,
            projectDir,
            invitePath);

        var result = LastJsonObject(output);
        Assert.Equal("default", result["group_name"]?.GetValue<string>());
        Assert.Equal("csharp@example.test", result["from_email"]?.GetValue<string>());
        Assert.True(result["kit_exists"]?.GetValue<bool>());
    }

    [Fact]
    public async Task PythonInviteCSharpAccepts()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var invitePath = Path.Combine(projectDir, "tn-invite-python-csharp.zip");
        string recipientDid;

        await using (var consumer = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            recipientDid = consumer.Did;
        }

        await RunPythonAsync(
            """
            import sys

            import tn
            from tn.cli import main as cli_main

            tn.init("py_invite_producer")
            yaml_path = tn.current_config().yaml_path
            tn.flush_and_close()

            rc = cli_main([
                "invite",
                sys.argv[1],
                sys.argv[2],
                "--group",
                "default",
                "--yaml",
                str(yaml_path),
                "--from-email",
                "python@example.test",
            ])
            if rc != 0:
                raise SystemExit(rc)
            """,
            projectDir,
            recipientDid,
            invitePath);

        await using var reopened = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var accepted = await reopened.Inbox.AcceptAsync(invitePath);

        Assert.Equal("default", accepted.GroupName);
        Assert.Equal("python@example.test", accepted.FromEmail);
        Assert.True(File.Exists(accepted.KitPath));
    }

    [Fact]
    public async Task CSharpInviteTypeScriptAccepts()
    {
        if (!await TypeScriptReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var invitePath = Path.Combine(projectDir, "tn-invite-csharp-typescript.zip");

        await using (var producer = await Tn.InitProjectAsync(
            "interop_cs",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await producer.Inbox.MintInviteAsync(
                "did:key:zTypescriptInviteRecipient",
                invitePath,
                new MintInvitationOptions
                {
                    FromEmail = "csharp@example.test",
                    InvitationId = "csharp-typescript",
                });
        }

        var output = await RunNodeAsync(
            """
            import { Tn } from "./dist/tn.js";
            import { accept } from "./dist/cli/inbox_accept.js";
            import { existsSync } from "node:fs";
            import { join } from "node:path";

            const invitePath = process.argv[1];
            const projectDir = process.argv[2];
            const yamlPath = join(projectDir, "ts-invite-consumer", "tn.yaml");
            const tn = await Tn.init(yamlPath, { stdout: false });
            await tn.close();

            const result = await accept(invitePath, yamlPath, () => {});
            console.log(JSON.stringify({
              groupName: result.groupName,
              fromEmail: result.fromEmail,
              kitPath: result.kitPath,
              kitExists: existsSync(result.kitPath),
            }));
            """,
            invitePath,
            projectDir);

        var result = LastJsonObject(output);
        Assert.Equal("default", result["groupName"]?.GetValue<string>());
        Assert.Equal("csharp@example.test", result["fromEmail"]?.GetValue<string>());
        Assert.True(result["kitExists"]?.GetValue<bool>());
    }

    [Fact]
    public async Task TypeScriptInviteCSharpAccepts()
    {
        if (!await TypeScriptReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var invitePath = Path.Combine(projectDir, "tn-invite-typescript-csharp.zip");

        await RunNodeAsync(
            """
            import { createHash } from "node:crypto";
            import { readFileSync, writeFileSync } from "node:fs";
            import { join } from "node:path";
            import { Tn } from "./dist/tn.js";
            import { packTnpkg } from "./dist/core/tnpkg_archive.js";

            const invitePath = process.argv[1];
            const projectDir = process.argv[2];
            const yamlPath = join(projectDir, "ts-invite-producer", "tn.yaml");
            const tn = await Tn.init(yamlPath, { stdout: false });
            const cfg = tn.config();
            const kitPath = join(cfg.keystorePath, "default.btn.mykit");
            const kit = readFileSync(kitPath);
            const manifest = {
              group_name: "default",
              leaf_index: 9,
              kit_sha256: `sha256:${createHash("sha256").update(kit).digest("hex")}`,
              from_email: "typescript@example.test",
              from_account_did: tn.did,
              invitation_id: "typescript-csharp",
              provenance: "ts-sdk",
            };
            const zip = packTnpkg([
              { name: "manifest.json", data: new TextEncoder().encode(JSON.stringify(manifest)) },
              { name: "default.btn.mykit", data: kit },
            ]);
            writeFileSync(invitePath, zip);
            console.log(JSON.stringify({ invitePath, fromDid: tn.did }));
            await tn.close();
            """,
            invitePath,
            projectDir);

        await using var consumer = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var accepted = await consumer.Inbox.AcceptAsync(invitePath);

        Assert.Equal("default", accepted.GroupName);
        Assert.Equal("typescript@example.test", accepted.FromEmail);
        Assert.True(File.Exists(accepted.KitPath));
    }

    [Fact]
    public async Task CSharpInviteRustAccepts()
    {
        if (!await RustReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var invitePath = Path.Combine(projectDir, "tn-invite-csharp-rust.zip");

        await using (var producer = await Tn.InitProjectAsync(
            "interop_cs",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await producer.Inbox.MintInviteAsync(
                "did:key:zRustInviteRecipient",
                invitePath,
                new MintInvitationOptions
                {
                    FromEmail = "csharp@example.test",
                    InvitationId = "csharp-rust",
                });
        }

        await RunRustCliAsync("init", "interop_rs_consumer", "--project-dir", projectDir);
        var yamlPath = Path.Combine(projectDir, ".tn", "interop_rs_consumer", "tn.yaml");
        var output = await RunRustCliAsync(
            "inbox",
            "accept",
            invitePath,
            "--yaml",
            yamlPath);

        Assert.Contains("group: default", output, StringComparison.Ordinal);
        Assert.Contains("from: csharp@example.test", output, StringComparison.Ordinal);
        Assert.Contains("kit:", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RustInviteCSharpAccepts()
    {
        if (!await RustReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var invitePath = Path.Combine(projectDir, "tn-invite-rust-csharp.zip");
        string recipientDid;

        await using (var consumer = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            recipientDid = consumer.Did;
        }

        await RunRustCliAsync("init", "interop_rs_producer", "--project-dir", projectDir);
        var yamlPath = Path.Combine(projectDir, ".tn", "interop_rs_producer", "tn.yaml");
        await RunRustCliAsync(
            "inbox",
            "mint",
            recipientDid,
            invitePath,
            "--yaml",
            yamlPath,
            "--from-email",
            "rust@example.test",
            "--invitation-id",
            "rust-csharp");

        await using var reopened = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var accepted = await reopened.Inbox.AcceptAsync(invitePath);

        Assert.Equal("default", accepted.GroupName);
        Assert.Equal("rust@example.test", accepted.FromEmail);
        Assert.True(File.Exists(accepted.KitPath));
    }

    [Fact]
    public async Task CSharpSealedBundlePythonAbsorbs()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var packagePath = Path.Combine(projectDir, "csharp-sealed-kit-bundle.tnpkg");
        var consumerInfo = await RunPythonAsync(
            """
            import json
            import tn

            tn.init("py_sealed_consumer")
            print(json.dumps({
                "did": tn.current_config().device.device_identity,
                "yaml": str(tn.current_config().yaml_path),
            }, sort_keys=True))
            tn.flush_and_close()
            """,
            projectDir);
        var consumer = LastJsonObject(consumerInfo);
        var recipientDid = consumer["did"]!.GetValue<string>();
        var consumerYaml = consumer["yaml"]!.GetValue<string>();

        await using (var producer = await Tn.InitProjectAsync(
            "interop_cs_producer",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await producer.Packages.BundleForRecipientAsync(
                recipientDid,
                packagePath,
                new TnProto.Packages.BundleForRecipientOptions
                {
                    Groups = ["default"],
                    SealForRecipient = true,
                });
        }

        var output = await RunPythonAsync(
            """
            import json
            import sys
            from pathlib import Path

            import tn

            tn.init(sys.argv[1])
            receipt = tn.pkg.absorb(sys.argv[2])
            duplicate = tn.pkg.absorb(sys.argv[2])
            cfg = tn.current_config()
            print(json.dumps({
                "kind": getattr(receipt, "kind", None),
                "legacy_status": getattr(receipt, "legacy_status", None),
                "accepted_count": getattr(receipt, "accepted_count", None),
                "duplicate_deduped_count": getattr(duplicate, "deduped_count", None),
                "kit_exists": (Path(cfg.keystore) / "default.btn.mykit").exists(),
            }, sort_keys=True))
            tn.flush_and_close()
            """,
            projectDir,
            consumerYaml,
            packagePath);

        var receipt = LastJsonObject(output);
        Assert.Equal("kit_bundle", receipt["kind"]?.GetValue<string>());
        Assert.NotEqual("rejected", receipt["legacy_status"]?.GetValue<string>());
        Assert.True(receipt["accepted_count"]?.GetValue<ulong>() > 0);
        Assert.True(receipt["duplicate_deduped_count"]?.GetValue<ulong>() > 0);
        Assert.True(receipt["kit_exists"]?.GetValue<bool>());
    }

    [Fact]
    public async Task PythonSealedBundleCSharpAbsorbs()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var packagePath = Path.Combine(projectDir, "python-sealed-kit-bundle.tnpkg");
        string recipientDid;

        await using (var consumer = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            recipientDid = consumer.Did;
        }

        await RunPythonAsync(
            """
            import sys

            import tn

            tn.init("py_sealed_producer")
            tn.pkg.bundle_for_recipient(
                sys.argv[1],
                sys.argv[2],
                groups=["default"],
                seal_for_recipient=True,
            )
            tn.flush_and_close()
            """,
            projectDir,
            recipientDid,
            packagePath);

        await using var reopened = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var info = await reopened.Packages.InspectAsync(packagePath);
        Assert.True(info.Sealed);
        Assert.Equal(recipientDid, info.RecipientIdentity);

        var receipt = await reopened.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", receipt.Kind);
        Assert.True(receipt.Accepted);
        Assert.True(receipt.AcceptedCount > 0);
    }

    [Fact]
    public async Task CSharpSealedBundleTypeScriptAbsorbs()
    {
        if (!await TypeScriptReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var packagePath = Path.Combine(projectDir, "csharp-sealed-kit-bundle.tnpkg");
        var consumerInfo = await RunNodeAsync(
            """
            import { Tn } from "./dist/tn.js";
            import { join } from "node:path";

            const projectDir = process.argv[1];
            const tn = await Tn.init(join(projectDir, "ts-sealed-consumer", "tn.yaml"), {
              stdout: false,
            });
            console.log(JSON.stringify({ did: tn.did, yaml: tn.yamlPath }));
            await tn.close();
            """,
            projectDir);
        var consumer = LastJsonObject(consumerInfo);
        var recipientDid = consumer["did"]!.GetValue<string>();
        var consumerYaml = consumer["yaml"]!.GetValue<string>();

        await using (var producer = await Tn.InitProjectAsync(
            "interop_cs_producer",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            await producer.Packages.BundleForRecipientAsync(
                recipientDid,
                packagePath,
                new TnProto.Packages.BundleForRecipientOptions
                {
                    Groups = ["default"],
                    SealForRecipient = true,
                });
        }

        var output = await RunNodeAsync(
            """
            import { existsSync } from "node:fs";
            import { join } from "node:path";
            import { Tn } from "./dist/tn.js";

            const yamlPath = process.argv[1];
            const pkgPath = process.argv[2];
            const tn = await Tn.init(yamlPath, { stdout: false });
            const receipt = await tn.pkg.absorb(pkgPath);
            const duplicate = await tn.pkg.absorb(pkgPath);
            const cfg = tn.config();
            console.log(JSON.stringify({
              kind: receipt.kind,
              acceptedCount: receipt.acceptedCount,
              dedupedCount: receipt.dedupedCount,
              rejectedReason: receipt.rejectedReason ?? null,
              duplicateAcceptedCount: duplicate.acceptedCount,
              duplicateDedupedCount: duplicate.dedupedCount,
              kitExists: existsSync(join(cfg.keystorePath, "default.btn.mykit")),
            }));
            await tn.close();
            """,
            consumerYaml,
            packagePath);

        var receipt = LastJsonObject(output);
        Assert.Equal("kit_bundle", receipt["kind"]?.GetValue<string>());
        Assert.True(receipt["rejectedReason"] is null || receipt["rejectedReason"]!.GetValue<string>() is "");
        Assert.True(receipt["acceptedCount"]?.GetValue<ulong>() > 0);
        Assert.True(receipt["duplicateDedupedCount"]?.GetValue<ulong>() > 0);
        Assert.True(receipt["kitExists"]?.GetValue<bool>());
    }

    [Fact]
    public async Task TypeScriptSealedBundleCSharpAbsorbs()
    {
        if (!await TypeScriptReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var packagePath = Path.Combine(projectDir, "typescript-sealed-kit-bundle.tnpkg");
        string recipientDid;

        await using (var consumer = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            recipientDid = consumer.Did;
        }

        await RunNodeAsync(
            """
            import { Tn } from "./dist/tn.js";
            import { join } from "node:path";

            const outPath = process.argv[1];
            const projectDir = process.argv[2];
            const recipientDid = process.argv[3];
            const tn = await Tn.init(join(projectDir, "ts-sealed-producer", "tn.yaml"), {
              stdout: false,
            });
            await tn.pkg.bundleForRecipient({
              recipientDid,
              outPath,
              groups: ["default"],
              sealForRecipient: true,
            });
            console.log(outPath);
            await tn.close();
            """,
            packagePath,
            projectDir,
            recipientDid);

        await using var reopened = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var info = await reopened.Packages.InspectAsync(packagePath);
        Assert.True(info.Sealed);
        Assert.Equal(recipientDid, info.RecipientIdentity);

        var receipt = await reopened.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", receipt.Kind);
        Assert.True(receipt.Accepted);
        Assert.True(receipt.AcceptedCount > 0);
    }

    [Fact]
    public async Task CSharpSealedBundleRustAbsorbs()
    {
        if (!await RustReadyAsync())
        {
            return;
        }

        var producerDir = NewTempDir();
        var consumerDir = NewTempDir();
        var rustInit = await RunRustCliAsync("init", "interop_rs_consumer", "--project-dir", consumerDir);
        var recipientDid = ValueAfterPrefix(rustInit, "did:");
        var consumerYaml = Path.Combine(consumerDir, ".tn", "interop_rs_consumer", "tn.yaml");
        var packagePath = Path.Combine(producerDir, "csharp-sealed-kit-bundle.tnpkg");

        await using (var producer = await Tn.InitProjectAsync(
            "interop_cs_producer",
            new TnProjectOptions { ProjectDirectory = producerDir }))
        {
            await producer.Packages.BundleForRecipientAsync(
                recipientDid,
                packagePath,
                new TnProto.Packages.BundleForRecipientOptions
                {
                    Groups = ["default"],
                    SealForRecipient = true,
                });
        }

        var output = await RunRustCliAsync(
            "pkg",
            "absorb",
            packagePath,
            "--yaml",
            consumerYaml);

        Assert.Contains("kind: kit_bundle", output, StringComparison.Ordinal);
        Assert.Contains("status: Accepted", output, StringComparison.Ordinal);
        Assert.DoesNotContain("status: Rejected", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RustSealedBundleCSharpAbsorbs()
    {
        if (!await RustReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var packagePath = Path.Combine(projectDir, "rust-sealed-kit-bundle.tnpkg");
        string recipientDid;

        await using (var consumer = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            recipientDid = consumer.Did;
        }

        await RunRustCliAsync("init", "interop_rs_producer", "--project-dir", projectDir);
        var producerYaml = Path.Combine(projectDir, ".tn", "interop_rs_producer", "tn.yaml");
        await RunRustCliAsync(
            "pkg",
            "export",
            "bundle-for-recipient",
            "--yaml",
            producerYaml,
            "--recipient",
            recipientDid,
            "--out",
            packagePath,
            "--group",
            "default",
            "--seal-for-recipient");

        await using var reopened = await Tn.InitProjectAsync(
            "interop_cs_consumer",
            new TnProjectOptions { ProjectDirectory = projectDir });

        var info = await reopened.Packages.InspectAsync(packagePath);
        Assert.True(info.Sealed);
        Assert.Equal(recipientDid, info.RecipientIdentity);

        var receipt = await reopened.Packages.AbsorbAsync(packagePath);

        Assert.Equal("kit_bundle", receipt.Kind);
        Assert.True(receipt.Accepted);
        Assert.True(receipt.AcceptedCount > 0);
    }

    [Fact]
    public async Task PythonSealsCSharpUnseals()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var output = await RunPythonAsync(
            """
            import tn

            tn.init("interop_seal_py")
            sealed = tn.seal("obj.invoice.v1", receipt=False, amount=9800, customer="acme")
            print("YAML=" + str(tn.current_config().yaml_path))
            print("SEALED=" + str(sealed))
            tn.flush_and_close()
            """,
            projectDir);
        var yamlPath = ValueAfterPrefix(output, "YAML=");
        var sealedLine = ValueAfterPrefix(output, "SEALED=");

        // Same ceremony, C# side: the native walk opens the block with the
        // ceremony's own kit and the self-describing verify passes.
        await using var tn = await Tn.InitAsync(yamlPath);
        var result = await tn.UnsealAsync(sealedLine);

        Assert.True(result.Valid.Signature);
        Assert.True(result.Valid.RowHash);
        Assert.Empty(result.HiddenGroups);
        Assert.Equal(2, result.Fields.Count);
        Assert.Equal(9800, result.Fields["amount"]?.GetValue<int>());
        Assert.Equal("acme", result.Fields["customer"]?.GetValue<string>());
    }

    [Fact]
    public async Task CSharpSealsPythonUnseals()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var sealedPath = Path.Combine(projectDir, "sealed.json");
        string yamlPath;

        await using (var tn = await Tn.InitProjectAsync(
            "interop_seal_cs",
            new TnProjectOptions { ProjectDirectory = projectDir }))
        {
            var sealedObject = await tn.SealAsync(
                "obj.invoice.v1",
                new { amount = 4200, customer = "zenith" },
                new SealOptions { Receipt = false });
            // RawJson is the transport artifact — written verbatim.
            await File.WriteAllTextAsync(sealedPath, sealedObject.RawJson);
            yamlPath = tn.YamlPath;
        }

        var output = await RunPythonAsync(
            """
            import json
            import sys
            from pathlib import Path

            import tn

            tn.init(sys.argv[1])
            entry = tn.unseal(Path(sys.argv[2]))
            print(json.dumps(dict(entry.fields), sort_keys=True))
            tn.flush_and_close()
            """,
            projectDir,
            yamlPath,
            sealedPath);

        var fields = LastJsonObject(output);
        Assert.Equal(4200, fields["amount"]?.GetValue<int>());
        Assert.Equal("zenith", fields["customer"]?.GetValue<string>());
    }

    [Fact]
    public async Task PythonSealsCSharpUnsealsPublicContainers()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        // Public container values feed the row hash as Python str(value)
        // (repr rendering); a C# unseal recomputing that hash natively
        // proves the cross-impl rendering end to end.
        var projectDir = NewTempDir();
        var output = await RunPythonAsync(
            """
            import sys
            from pathlib import Path

            import yaml as _yaml

            import tn

            yaml_path = Path(sys.argv[1])
            tn.init(yaml_path, cipher="btn")
            tn.flush_and_close()

            doc = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            doc["vault"]["enabled"] = False
            doc["ceremony"]["mode"] = "local"
            doc["public_fields"].extend(["pv", "pv2"])
            yaml_path.write_text(_yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")

            tn.init(yaml_path)
            sealed = tn.seal(
                "obj.container.v1",
                receipt=False,
                pv=[1, 2, 3],
                pv2={"a": 1},
                amount=5,
            )
            print("SEALED=" + str(sealed))
            tn.flush_and_close()
            """,
            projectDir,
            Path.Combine(projectDir, "tn.yaml"));
        var sealedLine = ValueAfterPrefix(output, "SEALED=");

        await using var tn = await Tn.InitAsync(Path.Combine(projectDir, "tn.yaml"));
        var result = await tn.UnsealAsync(sealedLine);

        // row_hash true IS the container-rendering parity proof.
        Assert.True(result.Valid.Signature);
        Assert.True(result.Valid.RowHash);
        Assert.True(JsonNode.DeepEquals(
            result.Fields["pv"],
            new JsonArray(1, 2, 3)));
        Assert.True(JsonNode.DeepEquals(
            result.Fields["pv2"],
            new JsonObject { ["a"] = 1 }));
        Assert.Equal(5, result.Fields["amount"]?.GetValue<int>());
    }

    [Fact]
    public async Task CSharpUnsealForeignObjectReturnsPublicFrame()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var publisherDir = NewTempDir();
        var output = await RunPythonAsync(
            """
            import tn

            tn.init("interop_seal_a")
            sealed = tn.seal("obj.memo.v1", receipt=False, body="private")
            print("SEALED=" + str(sealed))
            tn.flush_and_close()
            """,
            publisherDir);
        var sealedLine = ValueAfterPrefix(output, "SEALED=");

        // A fresh, unrelated C# ceremony holds no fitting key: no
        // exception, verified public frame, block left sealed.
        await using var stranger = await Tn.InitProjectAsync(
            "interop_seal_b",
            new TnProjectOptions { ProjectDirectory = NewTempDir() });
        var result = await stranger.UnsealAsync(sealedLine);

        Assert.True(result.Valid.Signature);
        Assert.True(result.Valid.RowHash);
        Assert.Equal(["default"], result.HiddenGroups);
        Assert.False(result.Fields.ContainsKey("body"));
        var block = Assert.Single(result.SealedBlocks);
        Assert.Equal("default", block.Name);
    }

    [Fact]
    public async Task PythonSealsCSharpUnsealsAsRecipient()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var publisherDir = NewTempDir();
        var kitDir = Path.Combine(NewTempDir(), "recipient-keys");
        Directory.CreateDirectory(kitDir);

        var output = await RunPythonAsync(
            """
            import sys

            import tn

            tn.init("interop_seal_pub")
            tn.admin.add_recipient(
                "default",
                recipient_did="did:key:zCSharpRecipientStub",
                out_path=sys.argv[1],
                raw=True,
            )
            sealed = tn.seal("obj.invoice.v1", receipt=False, amount=7)
            print("SEALED=" + str(sealed))
            tn.flush_and_close()
            """,
            publisherDir,
            Path.Combine(kitDir, "default.btn.mykit"));
        var sealedLine = ValueAfterPrefix(output, "SEALED=");

        // Bring-your-own-kit: the C# ceremony is unrelated; only the kit
        // directory Python minted opens the named group.
        await using var recipient = await Tn.InitProjectAsync(
            "interop_seal_recipient",
            new TnProjectOptions { ProjectDirectory = NewTempDir() });
        var result = await recipient.UnsealAsync(
            sealedLine,
            new UnsealOptions { AsRecipient = kitDir, Group = "default" });

        Assert.True(result.Valid.Signature);
        Assert.True(result.Valid.RowHash);
        Assert.Empty(result.HiddenGroups);
        Assert.Equal(7, result.Fields["amount"]?.GetValue<int>());
    }

    [Fact]
    public async Task PythonSealsWithAadCSharpUnseals()
    {
        if (!await PythonReadyAsync())
        {
            return;
        }

        var projectDir = NewTempDir();
        var output = await RunPythonAsync(
            """
            import tn

            tn.init("interop_seal_aad")
            sealed = tn.seal(
                "obj.case.v1",
                receipt=False,
                aad={"case": "A-17"},
                note="sealed note",
            )
            print("YAML=" + str(tn.current_config().yaml_path))
            print("SEALED=" + str(sealed))
            tn.flush_and_close()
            """,
            projectDir);
        var yamlPath = ValueAfterPrefix(output, "YAML=");
        var sealedLine = ValueAfterPrefix(output, "SEALED=");

        await using var tn = await Tn.InitAsync(yamlPath);
        var result = await tn.UnsealAsync(sealedLine);

        // The tn_aad echo crossed implementations: C# reconstructed the
        // bound AAD bytes from it (the decrypt opened) and the echo fed
        // the recomputed row hash (verify passed).
        Assert.True(result.Valid.Signature);
        Assert.True(result.Valid.RowHash);
        Assert.Equal("sealed note", result.Fields["note"]?.GetValue<string>());
        var echo = result.Envelope["tn_aad"]?.GetValue<string>();
        Assert.NotNull(echo);
        var binding = JsonNode.Parse(echo) as JsonObject;
        Assert.Equal("A-17", binding?["default"]?["case"]?.GetValue<string>());
    }

    private static string NewTempDir()
    {
        var path = Path.Combine(Path.GetTempPath(), "tn-csharp-interop-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static async Task<bool> PythonReadyAsync()
    {
        if (!InteropEnabled(PythonInteropEnv))
        {
            return false;
        }

        try
        {
            var output = await RunPythonAsync(
                """
                import tn
                print("ok")
                """,
                Directory.GetCurrentDirectory());
            return output.Contains("ok", StringComparison.Ordinal);
        }
        catch
        {
            throw;
        }
    }

    private static async Task<bool> TypeScriptReadyAsync()
    {
        if (!InteropEnabled(TypeScriptInteropEnv))
        {
            return false;
        }

        try
        {
            var output = await RunNodeAsync(
                """
                import { Tn } from "./dist/tn.js";
                console.log(typeof Tn);
                """);
            return output.Contains("function", StringComparison.Ordinal)
                || output.Contains("object", StringComparison.Ordinal);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "TypeScript interop was explicitly enabled, but ts-sdk is not ready. Build ts-sdk before rerunning this slice.",
                ex);
        }
    }

    private static async Task<bool> RustReadyAsync()
    {
        if (!InteropEnabled(RustInteropEnv))
        {
            return false;
        }

        try
        {
            var output = await RunProcessAsync(
                "cargo",
                ["--version"],
                stdin: string.Empty,
                workingDirectory: FindRepoRoot());
            return output.Contains("cargo", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "Rust interop was explicitly enabled, but cargo/Rust setup is not ready.",
                ex);
        }
    }

    private static bool InteropEnabled(string languageEnv)
    {
        return Environment.GetEnvironmentVariable(InteropAllEnv) == "1"
            || Environment.GetEnvironmentVariable(languageEnv) == "1";
    }

    private static Task<string> RunPythonAsync(string script, string workingDirectory, params string[] args)
    {
        var repoRoot = FindRepoRoot();
        var pythonPath = Path.Combine(repoRoot, "python");
        var environment = new Dictionary<string, string?>
        {
            ["PYTHONPATH"] = pythonPath,
        };

        return RunProcessAsync("python", ["-", .. args], script, workingDirectory, environment);
    }

    private static Task<string> RunNodeAsync(string script, params string[] args)
    {
        var repoRoot = FindRepoRoot();
        var tsSdk = Path.Combine(repoRoot, "ts-sdk");
        return RunProcessAsync("node", ["--input-type=module", "--eval", script, .. args], string.Empty, tsSdk);
    }

    private static Task<string> RunRustCliAsync(params string[] args)
    {
        var repoRoot = FindRepoRoot();
        return RunProcessAsync(
            "cargo",
            ["run", "-p", "tn-proto", "--features", "cli", "--bin", "tn-proto", "--", .. args],
            stdin: string.Empty,
            workingDirectory: repoRoot);
    }

    private static async Task<string> RunRustProgramAsync(string mainRs, params string[] args)
    {
        var repoRoot = FindRepoRoot();
        var projectDir = NewTempDir();
        var srcDir = Path.Combine(projectDir, "src");
        Directory.CreateDirectory(srcDir);
        await File.WriteAllTextAsync(
            Path.Combine(projectDir, "Cargo.toml"),
            $$"""
            [package]
            name = "tn-csharp-rust-interop"
            version = "0.0.0"
            edition = "2021"

            [dependencies]
            tn-proto = { path = "{{Path.Combine(repoRoot, "rust-sdk").Replace("\\", "\\\\")}}" }
            """).ConfigureAwait(false);
        await File.WriteAllTextAsync(Path.Combine(srcDir, "main.rs"), mainRs).ConfigureAwait(false);

        return await RunProcessAsync(
            "cargo",
            ["run", "--quiet", "--", .. args],
            stdin: string.Empty,
            workingDirectory: projectDir).ConfigureAwait(false);
    }

    private static async Task<string> RunProcessAsync(
        string fileName,
        IReadOnlyList<string> args,
        string stdin,
        string workingDirectory,
        IReadOnlyDictionary<string, string?>? environment = null)
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

        if (environment is not null)
        {
            foreach (var (key, value) in environment)
            {
                psi.Environment[key] = value;
            }
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

    private static JsonObject LastJsonObject(string output)
    {
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        for (var i = lines.Length - 1; i >= 0; i--)
        {
            var line = lines[i];
            if (JsonNode.Parse(line) is JsonObject obj)
            {
                return obj;
            }
        }

        throw new InvalidOperationException($"no JSON object found in output:\n{output}");
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

    private static string LastNonEmptyLine(string output)
    {
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return lines.Length > 0
            ? lines[^1]
            : throw new InvalidOperationException($"no non-empty lines found in output:\n{output}");
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "python"))
                && Directory.Exists(Path.Combine(directory.FullName, "ts-sdk"))
                && Directory.Exists(Path.Combine(directory.FullName, "csharp-sdk")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("could not locate tn-proto repository root");
    }
}
