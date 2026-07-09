using System.Text.Json;
using System.Text.Json.Nodes;
using TnProto;
using TnProto.Account;
using TnProto.Discovery;
using TnProto.Firehose;
using TnProto.Inbox;
using TnProto.Packages;
using TnProto.Rotation;
using TnProto.Validation;
using TnProto.Vault;
using TnProto.Wallet;

namespace TnProto.Cli;

/// <summary>
/// Minimal command dispatcher for the preview C# CLI.
/// </summary>
public static class CliApp
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
    };

    /// <summary>
    /// Run the CLI with injectable output streams for tests.
    /// </summary>
    public static async Task<int> RunAsync(
        string[] args,
        TextWriter? output = null,
        TextWriter? error = null,
        CancellationToken cancellationToken = default)
    {
        output ??= Console.Out;
        error ??= Console.Error;

        if (args.Length == 0 || IsHelp(args[0]))
        {
            WriteUsage(output);
            return 0;
        }

        try
        {
            return args[0] switch
            {
                "init" => await RunInitAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "log" => await RunEmitAsync(args[1..], output, level: null, cancellationToken).ConfigureAwait(false),
                "info" => await RunEmitAsync(args[1..], output, level: TnLogLevel.Info, cancellationToken).ConfigureAwait(false),
                "read" => await RunReadAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "seal" => await RunSealAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "canonical" => await RunCanonicalAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "verify" => await RunVerifyAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "group" => await RunGroupAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "admin" => await RunAdminAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "rotate" => await RunRotateAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "bundle" => await RunBundleAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "compile" => await RunCompileAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "absorb" => await RunAbsorbAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "invite" => await RunInviteAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "inbox" => await RunInboxAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "account" => await RunAccountAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "bootstrap" => await RunBootstrapAsync(args[1..], output, error, cancellationToken).ConfigureAwait(false),
                "vault" => await RunVaultAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "wallet" => await RunWalletAsync(args[1..], output, error, cancellationToken).ConfigureAwait(false),
                "watch" => await RunWatchAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "show" => await RunShowAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "validate" => await RunValidateAsync(args[1..], output, error, cancellationToken).ConfigureAwait(false),
                "streams" => await RunStreamsAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
                "firehose" => await RunFirehoseAsync(args[1..], output, error, cancellationToken).ConfigureAwait(false),
                _ => UnknownCommand(args[0], error),
            };
        }
        catch (ArgumentException ex)
        {
            await error.WriteLineAsync(ex.Message).ConfigureAwait(false);
            return 2;
        }
        catch (TnException ex)
        {
            await error.WriteLineAsync(ex.Message).ConfigureAwait(false);
            return 1;
        }
        catch (FirehoseException ex)
        {
            await error.WriteLineAsync(ex.Message).ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task<int> RunFirehoseAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        if (Environment.GetEnvironmentVariable("TN_FIREHOSE_ENABLED") != "1")
        {
            await error.WriteLineAsync(
                "tn-dotnet firehose is gated; set TN_FIREHOSE_ENABLED=1 to enable firehose commands.")
                .ConfigureAwait(false);
            return 2;
        }

        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException(
                "Usage: tn-dotnet firehose stats <tenant> | firehose list <tenant> [--did <did>] | firehose get <tenant> <ceremony> <name> [--did <did>] [--out <path>]");
        }

        var baseUrl = Environment.GetEnvironmentVariable("TN_FIREHOSE_URL");
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            throw new ArgumentException("TN_FIREHOSE_URL is required for firehose commands.");
        }

        var token = Environment.GetEnvironmentVariable("TN_FIREHOSE_TOKEN");
        using var client = new FirehoseClient(new FirehoseClientOptions
        {
            BaseUrl = baseUrl,
            BearerToken = token,
        });

        return args[0] switch
        {
            "stats" => await RunFirehoseStatsAsync(client, args[1..], output, cancellationToken).ConfigureAwait(false),
            "list" => await RunFirehoseListAsync(client, args[1..], output, token, cancellationToken).ConfigureAwait(false),
            "get" => await RunFirehoseGetAsync(client, args[1..], output, token, cancellationToken).ConfigureAwait(false),
            _ => UnknownCommand($"firehose {args[0]}", error),
        };
    }

    private static async Task<int> RunFirehoseStatsAsync(
        FirehoseClient client,
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        if (args.Length != 1 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet firehose stats <tenant>");
        }

        var stats = await client.StatsAsync(args[0], cancellationToken).ConfigureAwait(false);
        await output.WriteLineAsync(stats.ToJsonString(JsonOptions)).ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunFirehoseListAsync(
        FirehoseClient client,
        string[] args,
        TextWriter output,
        string? token,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet firehose list <tenant> [--did <did>]");
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("TN_FIREHOSE_TOKEN is required for firehose list.");
        }

        var tenant = args[0];
        string? did = null;
        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--did":
                    did = RequireValue(args, ref i, "--did");
                    break;
                default:
                    throw new ArgumentException($"Unknown firehose list option: {args[i]}");
            }
        }

        var listing = await client.ListAsync(tenant, did, cancellationToken).ConfigureAwait(false);
        await output.WriteLineAsync(listing.ToJsonString(JsonOptions)).ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunFirehoseGetAsync(
        FirehoseClient client,
        string[] args,
        TextWriter output,
        string? token,
        CancellationToken cancellationToken)
    {
        if (args.Length < 3 || IsHelp(args[0]))
        {
            throw new ArgumentException(
                "Usage: tn-dotnet firehose get <tenant> <ceremony> <name> [--did <did>] [--out <path>]");
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("TN_FIREHOSE_TOKEN is required for firehose get.");
        }

        var tenant = args[0];
        var ceremony = args[1];
        var name = args[2];
        string? did = null;
        string? outPath = null;
        for (var i = 3; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--did":
                    did = RequireValue(args, ref i, "--did");
                    break;
                case "--out":
                    outPath = RequireValue(args, ref i, "--out");
                    break;
                default:
                    throw new ArgumentException($"Unknown firehose get option: {args[i]}");
            }
        }

        var bytes = await client.GetAsync(tenant, ceremony, name, did, cancellationToken).ConfigureAwait(false);
        if (outPath is not null)
        {
            var fullPath = Path.GetFullPath(outPath);
            var parent = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrEmpty(parent))
            {
                Directory.CreateDirectory(parent);
            }

            await File.WriteAllBytesAsync(fullPath, bytes, cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync($"Wrote {bytes.Length} bytes to {fullPath}").ConfigureAwait(false);
            return 0;
        }

        await Console.OpenStandardOutput().WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunSealAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        if (args.Length > 0 && IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet seal < seal-input.ndjson > envelope.ndjson");
        }

        if (args.Length > 0)
        {
            throw new ArgumentException($"Unknown seal option: {args[0]}");
        }

        string? line;
        while ((line = await Console.In.ReadLineAsync(cancellationToken).ConfigureAwait(false)) is not null)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                JsonNode.Parse(line);
            }
            catch (JsonException ex)
            {
                throw new ArgumentException($"tn-dotnet seal: invalid JSON on stdin: {ex.Message}", ex);
            }

            try
            {
                await output.WriteAsync(TnCrypto.SealEnvelopeRaw(line)).ConfigureAwait(false);
            }
            catch (TnException ex)
            {
                throw new ArgumentException($"tn-dotnet seal: {ex.Message}", ex);
            }
        }

        return 0;
    }

    private static async Task<int> RunWalletAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet wallet status --yaml <tn.yaml> [--json] | wallet link --yaml <tn.yaml> --vault <url> --project-id <id> [--json] | wallet unlink --yaml <tn.yaml> [--json] | wallet pull-prefs --yaml <tn.yaml> [--vault <url>] [--bearer <token>] [--json] | wallet stage-inbox --yaml <tn.yaml> [--vault <url>] [--bearer <token>] [--json] | wallet publish-group-keys --yaml <tn.yaml> [--vault <url>] [--bearer <token>] [--group <name>...] [--json] | wallet sync --yaml <tn.yaml> [--pull-only|--push-only] [--vault <url>] [--bearer <token>] [--group <name>...] [--no-group-keys] [--push-body --passphrase <value> [--project-id <id>] [--credential-id <id>]] [--json] | wallet restore --yaml <tn.yaml> --target-dir <dir> (--passphrase <value>|--use-cached-account-key [--account-id <id>]) [--vault <url>] [--bearer <token>] [--project-id <id>] [--credential-id <id>] [--overwrite] [--json] | wallet export-mnemonic [--identity <identity.json>] [--yes]");
        }

        return args[0] switch
        {
            "status" => await RunWalletStatusAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "link" => await RunWalletLinkAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "unlink" => await RunWalletUnlinkAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "pull-prefs" => await RunWalletPullPrefsAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "stage-inbox" => await RunWalletStageInboxAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "publish-group-keys" => await RunWalletPublishGroupKeysAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "sync" => await RunWalletSyncAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "restore" => await RunWalletRestoreAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "export-mnemonic" => await RunWalletExportMnemonicAsync(args[1..], output, error, cancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentException($"Unknown wallet command: {args[0]}"),
        };
    }

    private static async Task<int> RunWalletStatusAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseWalletStatusArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var status = await tn.Wallet.StatusAsync(cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                verdict = status.VerdictName,
                device_did = status.DeviceDid,
                yaml_path = status.YamlPath,
                account = new
                {
                    account_id = status.Account.AccountId,
                    account_bound = status.Account.AccountBound,
                    key_cached = status.Account.KeyCached,
                    verdict = status.Account.VerdictName,
                },
                vault = new
                {
                    state = status.Vault.StateName,
                    linked_vault = status.Vault.LinkedVault,
                    linked_project_id = status.Vault.LinkedProjectId,
                    vault_enabled = status.Vault.VaultEnabled,
                    autosync = status.Vault.Autosync,
                },
                pending_claim = status.PendingClaim is null
                    ? null
                    : new
                    {
                        vault_id = status.PendingClaim.VaultId,
                        expires_at = status.PendingClaim.ExpiresAt,
                        claim_url = status.PendingClaim.ClaimUrl,
                        expired = status.PendingClaim.Expired,
                    },
                warnings = status.Warnings,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"wallet:          {status.VerdictName}").ConfigureAwait(false);
            await output.WriteLineAsync($"device:          {status.DeviceDid}").ConfigureAwait(false);
            await output.WriteLineAsync($"account_bound:   {YesNo(status.Account.AccountBound)}").ConfigureAwait(false);
            await output.WriteLineAsync($"account_id:      {status.Account.AccountId ?? "(none)"}").ConfigureAwait(false);
            await output.WriteLineAsync($"key_cached:      {YesNo(status.Account.KeyCached)}").ConfigureAwait(false);
            await output.WriteLineAsync($"vault_state:     {status.Vault.StateName}").ConfigureAwait(false);
            await output.WriteLineAsync($"linked_vault:    {status.Vault.LinkedVault ?? "(none)"}").ConfigureAwait(false);
            await output.WriteLineAsync($"linked_project:  {status.Vault.LinkedProjectId ?? "(none)"}").ConfigureAwait(false);
            await output.WriteLineAsync($"pending_claim:   {status.PendingClaim?.VaultId ?? "(none)"}").ConfigureAwait(false);
            foreach (var warning in status.Warnings)
            {
                await output.WriteLineAsync($"warning:         {warning}").ConfigureAwait(false);
            }
        }

        return 0;
    }

    private static async Task<int> RunWalletLinkAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseWalletLinkArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Vault.LinkAsync(options.VaultBaseUrl, options.ProjectId, cancellationToken)
            .ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                state = result.StateName,
                yaml_path = result.YamlPath,
                linked_vault = result.LinkedVault,
                linked_project_id = result.LinkedProjectId,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"wallet linked: {result.LinkedVault}/projects/{result.LinkedProjectId}")
                .ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunWalletUnlinkAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseWalletUnlinkArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Vault.UnlinkAsync(cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                state = result.StateName,
                yaml_path = result.YamlPath,
                linked_vault = result.LinkedVault,
                linked_project_id = result.LinkedProjectId,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync("wallet unlinked").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunWalletPullPrefsAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseWalletPullPrefsArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Wallet.PullPrefsAsync(
            new WalletPullPrefsOptions
            {
                VaultBaseUrl = options.VaultBaseUrl,
                BearerToken = options.BearerToken,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                vault = result.VaultBaseUrl,
                default_new_ceremony_mode = result.DefaultNewCeremonyMode,
                prefs_version = result.PrefsVersion,
                state_path = result.StatePath,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"Pulled prefs from {result.VaultBaseUrl}:").ConfigureAwait(false);
            await output.WriteLineAsync($"  default_new_ceremony_mode: {result.DefaultNewCeremonyMode}").ConfigureAwait(false);
            await output.WriteLineAsync($"  prefs_version: {result.PrefsVersion}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunWalletStageInboxAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseWalletStageInboxArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Wallet.StageInboxAsync(
            new WalletStageInboxOptions
            {
                VaultBaseUrl = options.VaultBaseUrl,
                BearerToken = options.BearerToken,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                staged_paths = result.StagedPaths,
                skipped = result.Skipped,
                not_bound = result.NotBound,
                unauthorized = result.Unauthorized,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else if (result.NotBound)
        {
            await output.WriteLineAsync("wallet inbox not staged: local account is not bound to a vault account")
                .ConfigureAwait(false);
        }
        else if (result.Unauthorized)
        {
            await output.WriteLineAsync("wallet inbox not staged: vault account inbox was unauthorized")
                .ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"staged: {result.StagedPaths.Count} package(s); skipped: {result.Skipped}")
                .ConfigureAwait(false);
            foreach (var path in result.StagedPaths)
            {
                await output.WriteLineAsync(path).ConfigureAwait(false);
            }
        }

        return 0;
    }

    private static async Task<int> RunWalletPublishGroupKeysAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseWalletPublishGroupKeysArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Wallet.PublishGroupKeysAsync(
            new WalletPublishGroupKeysOptions
            {
                VaultBaseUrl = options.VaultBaseUrl,
                BearerToken = options.BearerToken,
                Groups = options.Groups.Count == 0 ? null : options.Groups,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                published = result.Published,
                requested_groups = result.RequestedGroups,
                snapshot = result.Snapshot is null
                    ? null
                    : new
                    {
                        stored_path = result.Snapshot.StoredPath,
                        byte_size = result.Snapshot.ByteSize,
                        manifest_signature_b64 = result.Snapshot.ManifestSignatureBase64,
                        head_row_hash = result.Snapshot.HeadRowHash,
                    },
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync(result.Published
                ? $"published group keys: {result.Snapshot?.StoredPath}"
                : "no group keys to publish").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunWalletSyncAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseWalletSyncArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Wallet.SyncAsync(
            new WalletSyncOptions
            {
                PullOnly = options.PullOnly,
                PushOnly = options.PushOnly,
                PublishGroupKeys = options.PublishGroupKeys,
                PushBody = options.PushBody,
                VaultBaseUrl = options.VaultBaseUrl,
                BearerToken = options.BearerToken,
                Groups = options.Groups.Count == 0 ? null : options.Groups,
                ProjectId = options.ProjectId,
                Passphrase = options.Passphrase,
                CredentialId = options.CredentialId,
            },
            cancellationToken).ConfigureAwait(false);
        var pull = result.Pull;
        var stage = pull?.Stage;

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                mode = options.PullOnly ? "pull_only" : options.PushOnly ? "push_only" : "sync",
                staged_paths = stage?.StagedPaths ?? [],
                stage_skipped = stage?.Skipped ?? 0,
                not_bound = stage?.NotBound ?? false,
                unauthorized = stage?.Unauthorized ?? false,
                absorbed_packages = pull?.AbsorbedPackageCount ?? 0,
                accepted_count = pull?.AcceptedCount ?? 0,
                deduped_count = pull?.DedupedCount ?? 0,
                conflict_count = pull?.ConflictCount ?? 0,
                rejected_count = pull?.RejectedCount ?? 0,
                rejected_paths = pull?.RejectedPaths ?? [],
                group_keys = result.GroupKeys is null
                    ? null
                    : new
                    {
                        published = result.GroupKeys.Published,
                        requested_groups = result.GroupKeys.RequestedGroups,
                        snapshot = result.GroupKeys.Snapshot is null
                            ? null
                            : new
                            {
                                stored_path = result.GroupKeys.Snapshot.StoredPath,
                                byte_size = result.GroupKeys.Snapshot.ByteSize,
                                manifest_signature_b64 = result.GroupKeys.Snapshot.ManifestSignatureBase64,
                                head_row_hash = result.GroupKeys.Snapshot.HeadRowHash,
                            },
                    },
                body_push = result.BodyPush is null
                    ? null
                    : new
                    {
                        project_id = result.BodyPush.ProjectId,
                        body_member_count = result.BodyPush.BodyMemberCount,
                        encrypted_len = result.BodyPush.EncryptedLength,
                        wrapped_key_created = result.BodyPush.WrappedKeyCreated,
                        if_match = result.BodyPush.IfMatch,
                    },
            }, JsonOptions)).ConfigureAwait(false);
        }
        else if (stage?.NotBound == true)
        {
            await output.WriteLineAsync("wallet sync skipped: local account is not bound to a vault account")
                .ConfigureAwait(false);
        }
        else if (stage?.Unauthorized == true)
        {
            await output.WriteLineAsync("wallet sync skipped: vault account inbox was unauthorized")
                .ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync(
                $"wallet sync: staged {stage?.StagedPaths.Count ?? 0}, absorbed {pull?.AbsorbedPackageCount ?? 0}, accepted {pull?.AcceptedCount ?? 0}, deduped {pull?.DedupedCount ?? 0}, rejected {pull?.RejectedCount ?? 0}, group_keys {(result.GroupKeys?.Published == true ? "published" : "skipped")}, body_push {(result.BodyPush is null ? "skipped" : "pushed")}")
                .ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunWalletRestoreAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseWalletRestoreArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Wallet.RestoreAsync(
            new WalletRestoreOptions
            {
                VaultBaseUrl = options.VaultBaseUrl,
                BearerToken = options.BearerToken,
                ProjectId = options.ProjectId,
                Passphrase = options.Passphrase,
                UseCachedAccountKey = options.UseCachedAccountKey,
                AccountId = options.AccountId,
                CredentialId = options.CredentialId,
                TargetDirectory = options.TargetDirectory,
                Overwrite = options.Overwrite,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                project_id = result.ProjectId,
                body_member_count = result.BodyMemberCount,
                total_body_bytes = result.TotalBodyBytes,
                body_member_names = result.BodyMemberNames,
                target_dir = result.TargetDirectory,
                yaml_path = result.YamlPath,
                keys_dir = result.KeysDirectory,
                written_paths = result.WrittenPaths,
                deduped_paths = result.DedupedPaths,
                skipped_members = result.SkippedMembers,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"restored project: {result.ProjectId}").ConfigureAwait(false);
            await output.WriteLineAsync($"target_dir:       {result.TargetDirectory}").ConfigureAwait(false);
            await output.WriteLineAsync($"yaml_path:        {result.YamlPath}").ConfigureAwait(false);
            await output.WriteLineAsync($"keys_dir:         {result.KeysDirectory}").ConfigureAwait(false);
            await output.WriteLineAsync($"written:          {result.WrittenPaths.Count}").ConfigureAwait(false);
            await output.WriteLineAsync($"deduped:          {result.DedupedPaths.Count}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunWalletExportMnemonicAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var options = ParseWalletExportMnemonicArgs(args);

        string mnemonic;
        try
        {
            mnemonic = await TnIdentity.ExportMnemonicAsync(options.IdentityPath, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (TnException ex) when (ex.Message.Contains("no mnemonic stored", StringComparison.OrdinalIgnoreCase))
        {
            await error.WriteLineAsync(
                "tn-dotnet: error: no mnemonic stored in identity.json. The identity was created without mnemonic persistence, so the recovery phrase was only shown once when it was created.")
                .ConfigureAwait(false);
            return 2;
        }

        if (!options.Yes)
        {
            await output.WriteLineAsync("ABOUT TO DISPLAY YOUR RECOVERY PHRASE.").ConfigureAwait(false);
            await output.WriteLineAsync("Anyone watching your screen can steal your identity.").ConfigureAwait(false);
            await output.WriteLineAsync("Re-run with --yes to confirm.").ConfigureAwait(false);
            return 2;
        }

        var bar = new string('=', 76);
        await output.WriteLineAsync().ConfigureAwait(false);
        await output.WriteLineAsync(bar).ConfigureAwait(false);
        await output.WriteLineAsync("  WRITE THIS DOWN NOW. You will NOT see it again without").ConfigureAwait(false);
        await output.WriteLineAsync("  explicit re-display, and without it you CANNOT recover").ConfigureAwait(false);
        await output.WriteLineAsync("  your TN identity if this machine is lost.").ConfigureAwait(false);
        await output.WriteLineAsync(bar).ConfigureAwait(false);
        await output.WriteLineAsync().ConfigureAwait(false);
        await output.WriteLineAsync($"  {mnemonic}").ConfigureAwait(false);
        await output.WriteLineAsync().ConfigureAwait(false);
        await output.WriteLineAsync(bar).ConfigureAwait(false);

        return 0;
    }

    private static async Task<int> RunVaultAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet vault status --yaml <tn.yaml> [--json] | vault claim-link --yaml <tn.yaml> --vault <url> [--project-name <name>] [--json] | vault connect --yaml <tn.yaml> --vault <url> [--bearer <token>] [--project-name <name>] [--json] | vault link --yaml <tn.yaml> --vault <url> --project-id <id> [--json] | vault unlink --yaml <tn.yaml> [--json]");
        }

        return args[0] switch
        {
            "status" => await RunVaultStatusAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "claim-link" => await RunVaultClaimLinkAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "connect" => await RunVaultConnectAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "link" => await RunVaultLinkAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "unlink" => await RunVaultUnlinkAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentException($"Unknown vault command: {args[0]}"),
        };
    }

    private static async Task<int> RunBootstrapAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet bootstrap api-key --vault <url> [--api-key <value>] [--dir <path>] [--project <name>] [--profile <name>] [--json]");
        }

        return args[0] switch
        {
            "api-key" => await RunBootstrapApiKeyAsync(args[1..], output, error, cancellationToken).ConfigureAwait(false),
            _ => UnknownCommand($"bootstrap {args[0]}", error),
        };
    }

    private static async Task<int> RunBootstrapApiKeyAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var options = ParseBootstrapApiKeyArgs(args);
        var apiKey = options.ApiKey ?? Environment.GetEnvironmentVariable("TN_API_KEY");
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new ArgumentException("tn-dotnet bootstrap api-key requires --api-key <value> or TN_API_KEY.");
        }

        var result = await TnApiKeyBootstrap.BootstrapAsync(
            new TnApiKeyBootstrapOptions
            {
                ApiKey = apiKey,
                VaultBaseUrl = options.VaultBaseUrl,
                ProjectName = options.ProjectName,
                ProjectDirectory = options.ProjectDirectory,
                Profile = options.Profile,
            },
            cancellationToken).ConfigureAwait(false);

        if (result is null)
        {
            await error.WriteLineAsync("api-key bootstrap failed; the key may be malformed, consumed, revoked, or not addressed to this bootstrap identity.").ConfigureAwait(false);
            return 1;
        }

        if (!result.Succeeded)
        {
            await error.WriteLineAsync($"api-key bootstrap failed: {result.Receipt.LegacyReason}").ConfigureAwait(false);
            await result.Project.DisposeAsync().ConfigureAwait(false);
            return 1;
        }

        await using var project = result.Project.ConfigureAwait(false);
        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(
                new
                {
                    succeeded = true,
                    did = result.ApiKey.Did,
                    vault = result.VaultBaseUrl,
                    kind = result.Kind,
                    yaml_path = result.Project.YamlPath,
                    project_directory = result.Project.ProjectDirectory,
                    receipt = new
                    {
                        kind = result.Receipt.Kind,
                        status = result.Receipt.Status,
                        accepted_count = result.Receipt.AcceptedCount,
                        deduped_count = result.Receipt.DedupedCount,
                        legacy_status = result.Receipt.LegacyStatus,
                        legacy_reason = result.Receipt.LegacyReason,
                    },
                },
                JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"bootstrapped {result.Kind ?? "bundle"} for {result.ApiKey.Did}").ConfigureAwait(false);
            await output.WriteLineAsync($"yaml: {result.Project.YamlPath}").ConfigureAwait(false);
            await output.WriteLineAsync($"status: {result.Receipt.Status} accepted={result.Receipt.AcceptedCount} deduped={result.Receipt.DedupedCount}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunVaultStatusAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseVaultStatusArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var state = await tn.Vault.LinkStateAsync(cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                state = state.StateName,
                yaml_path = state.YamlPath,
                linked_vault = state.LinkedVault,
                linked_project_id = state.LinkedProjectId,
                vault_enabled = state.VaultEnabled,
                autosync = state.Autosync,
                sync_interval_seconds = state.SyncIntervalSeconds,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"state:             {state.StateName}").ConfigureAwait(false);
            await output.WriteLineAsync($"linked_vault:      {state.LinkedVault ?? "(none)"}").ConfigureAwait(false);
            await output.WriteLineAsync($"linked_project_id: {state.LinkedProjectId ?? "(none)"}").ConfigureAwait(false);
            await output.WriteLineAsync($"autosync:          {YesNo(state.Autosync)}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunVaultLinkAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseVaultLinkArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Vault.LinkAsync(options.VaultBaseUrl, options.ProjectId, cancellationToken)
            .ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                state = result.StateName,
                yaml_path = result.YamlPath,
                linked_vault = result.LinkedVault,
                linked_project_id = result.LinkedProjectId,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"linked: {result.LinkedVault}/projects/{result.LinkedProjectId}")
                .ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunVaultConnectAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseVaultConnectArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Vault.ConnectAsync(
            new VaultConnectOptions
            {
                VaultBaseUrl = options.VaultBaseUrl,
                BearerToken = options.BearerToken,
                ProjectName = options.ProjectName,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                vault = result.VaultBaseUrl,
                project = new
                {
                    id = result.Project.Id,
                    name = result.Project.Name,
                    ceremony_id = result.Project.CeremonyId,
                },
                newly_linked = result.NewlyLinked,
                state = result.State.StateName,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync(
                $"connected: {result.VaultBaseUrl}/projects/{result.Project.Id}")
                .ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunVaultClaimLinkAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseVaultClaimLinkArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Vault.InitUploadAsync(
            new VaultInitUploadOptions
            {
                VaultBaseUrl = options.VaultBaseUrl,
                ProjectName = options.ProjectName,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                vault_id = result.VaultId,
                expires_at = result.ExpiresAt,
                claim_url = result.ClaimUrl,
                reused = result.Reused,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync(result.Reused
                ? $"claim link reused: {result.ClaimUrl}"
                : $"claim link: {result.ClaimUrl}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunVaultUnlinkAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseVaultStatusArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Vault.UnlinkAsync(cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                state = result.StateName,
                yaml_path = result.YamlPath,
                linked_vault = result.LinkedVault,
                linked_project_id = result.LinkedProjectId,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync("unlinked").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunAccountAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet account status --yaml <tn.yaml> [--json] | account connect <code> --yaml <tn.yaml> --vault <url> [--json] | account logout --yaml <tn.yaml> [--json]");
        }

        return args[0] switch
        {
            "status" or "whoami" => await RunAccountStatusAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "connect" => await RunAccountConnectAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "logout" => await RunAccountLogoutAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentException($"Unknown account command: {args[0]}"),
        };
    }

    private static async Task<int> RunAccountStatusAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseAccountStatusArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var status = await tn.Account.StatusAsync(cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                device_did = status.DeviceDid,
                account_id = status.AccountId,
                account_bound = status.AccountBound,
                vault = status.Vault,
                key_cached = status.KeyCached,
                verdict = status.VerdictName,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"device:        {status.DeviceDid}").ConfigureAwait(false);
            await output.WriteLineAsync($"account_id:    {status.AccountId ?? "(none)"}").ConfigureAwait(false);
            await output.WriteLineAsync($"account_bound: {YesNo(status.AccountBound)}").ConfigureAwait(false);
            await output.WriteLineAsync($"key_cached:    {YesNo(status.KeyCached)}").ConfigureAwait(false);
            await output.WriteLineAsync($"verdict:       {status.VerdictName}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunAccountConnectAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseAccountConnectArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Account.ConnectCodeAsync(
            options.Code,
            new AccountConnectOptions { VaultBaseUrl = options.VaultBaseUrl },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                account_id = result.AccountId,
                project_id = result.ProjectId,
                project_name = result.ProjectName,
                vault = result.Vault,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"connected account: {result.AccountId}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunAccountLogoutAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseAccountStatusArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Account.LogoutAsync(cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                was_bound = result.WasBound,
                account_id = result.AccountId,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync(result.WasBound
                ? $"logged out account: {result.AccountId}"
                : "no local account binding").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunShowAsync(string[] args, TextWriter output, CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet show env --yaml <tn.yaml> [--format human|json] | show profiles [--format human|json]");
        }

        return args[0] switch
        {
            "profiles" => RunShowProfiles(args[1..], output),
            "env" => await RunShowEnvAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentException($"Unknown show command: {args[0]}"),
        };
    }

    private static async Task<int> RunShowEnvAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseShowEnvArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var snapshot = tn.EnvironmentSnapshot();

        if (options.Format == "json")
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                ok = true,
                me = new
                {
                    did = snapshot.Did,
                },
                project = new
                {
                    name = snapshot.ProjectName,
                    directory = snapshot.ProjectDirectory,
                    yaml_path = snapshot.YamlPath,
                },
                logs = new
                {
                    path = snapshot.LogPath,
                },
            }, JsonOptions)).ConfigureAwait(false);
            return 0;
        }

        await output.WriteLineAsync("# tn show env - resolved runtime snapshot").ConfigureAwait(false);
        await output.WriteLineAsync($"device:             {snapshot.Did}").ConfigureAwait(false);
        await output.WriteLineAsync($"project.name:       {snapshot.ProjectName ?? "(none)"}").ConfigureAwait(false);
        await output.WriteLineAsync($"project.directory:  {snapshot.ProjectDirectory ?? "(none)"}").ConfigureAwait(false);
        await output.WriteLineAsync($"yaml.path:          {snapshot.YamlPath}").ConfigureAwait(false);
        await output.WriteLineAsync($"logs.path:          {snapshot.LogPath}").ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunValidateAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var options = ParseValidateArgs(args);
        var result = await TnValidator.ValidateProjectAsync(options.ProjectDirectory, cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                valid = result.Valid,
                project_directory = result.ProjectDirectory,
                tn_root = result.TnRoot,
                ceremony_names = result.CeremonyNames,
                warnings = result.Warnings.Select(issue => new
                {
                    message = issue.Message,
                    path = issue.Path,
                }),
                errors = result.Errors.Select(issue => new
                {
                    message = issue.Message,
                    path = issue.Path,
                }),
            }, JsonOptions)).ConfigureAwait(false);
            return result.Valid ? 0 : 1;
        }

        foreach (var warning in result.Warnings)
        {
            await error.WriteLineAsync($"WARNING: {warning.Message}").ConfigureAwait(false);
        }

        foreach (var validationError in result.Errors)
        {
            await error.WriteLineAsync($"ERROR: {validationError.Message}").ConfigureAwait(false);
        }

        if (!Directory.Exists(result.TnRoot))
        {
            await output.WriteLineAsync($"(no .tn/ directory at {result.ProjectDirectory} - nothing to validate)").ConfigureAwait(false);
        }
        else if (result.CeremonyNames.Count == 0)
        {
            await output.WriteLineAsync($"(no ceremonies under {result.TnRoot} - nothing to validate)").ConfigureAwait(false);
        }
        else if (result.Valid)
        {
            var suffix = result.CeremonyNames.Count == 1 ? "y" : "ies";
            await output.WriteLineAsync($"OK: {result.CeremonyNames.Count} ceremon{suffix} valid.").ConfigureAwait(false);
        }

        return result.Valid ? 0 : 1;
    }

    private static async Task<int> RunStreamsAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseStreamsArgs(args);
        var streams = await TnProjectDiscovery.ListStreamsAsync(options.ProjectDirectory, cancellationToken).ConfigureAwait(false);

        if (options.Format == "json")
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(streams.Select(stream => new
            {
                name = stream.Name,
                profile = stream.Profile,
                yaml_path = stream.YamlPath,
            }), JsonOptions)).ConfigureAwait(false);
            return 0;
        }

        var projectDirectory = Path.GetFullPath(options.ProjectDirectory ?? Environment.CurrentDirectory);
        var tnRoot = Path.Combine(projectDirectory, ".tn");
        if (streams.Count == 0)
        {
            await output.WriteLineAsync($"(no ceremonies found under {tnRoot})").ConfigureAwait(false);
            return 0;
        }

        var nameWidth = Math.Max("NAME".Length, streams.Max(stream => stream.Name.Length));
        var profileWidth = Math.Max("PROFILE".Length, streams.Max(stream => stream.Profile.Length));
        await output.WriteLineAsync($"{Pad("NAME", nameWidth)}  {Pad("PROFILE", profileWidth)}  YAML").ConfigureAwait(false);
        await output.WriteLineAsync($"{new string('-', nameWidth)}  {new string('-', profileWidth)}  ----").ConfigureAwait(false);
        foreach (var stream in streams)
        {
            await output.WriteLineAsync($"{Pad(stream.Name, nameWidth)}  {Pad(stream.Profile, profileWidth)}  {stream.YamlPath}").ConfigureAwait(false);
        }

        return 0;
    }

    private static ValidateOptions ParseValidateArgs(string[] args)
    {
        string? projectDirectory = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--project-dir":
                case "--dir":
                    projectDirectory = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown validate option: {args[i]}");
            }
        }

        return new ValidateOptions(projectDirectory, json);
    }

    private static AccountStatusOptions ParseAccountStatusArgs(string[] args)
    {
        string? yamlPath = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown account option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet account requires --yaml <tn.yaml>.");
        }

        return new AccountStatusOptions(yamlPath, json);
    }

    private static AccountConnectCliOptions ParseAccountConnectArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet account connect <code> --yaml <tn.yaml> --vault <url> [--json]");
        }

        var code = args[0];
        string? yamlPath = null;
        string? vaultBaseUrl = null;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown account connect option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet account connect requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new ArgumentException("tn-dotnet account connect requires --vault <url>.");
        }

        return new AccountConnectCliOptions(code, yamlPath, vaultBaseUrl, json);
    }

    private static BootstrapApiKeyCliOptions ParseBootstrapApiKeyArgs(string[] args)
    {
        string? apiKey = null;
        string? vaultBaseUrl = null;
        string? projectDirectory = null;
        var projectName = "bootstrap";
        var profile = TnProfile.Transaction;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--api-key":
                    apiKey = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--dir":
                    projectDirectory = RequireValue(args, ref i, args[i]);
                    break;
                case "--project":
                case "--project-name":
                    projectName = RequireValue(args, ref i, args[i]);
                    break;
                case "--profile":
                    profile = ParseProfile(RequireValue(args, ref i, args[i]));
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown bootstrap api-key option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new ArgumentException("tn-dotnet bootstrap api-key requires --vault <url>.");
        }

        if (string.IsNullOrWhiteSpace(projectName))
        {
            throw new ArgumentException("tn-dotnet bootstrap api-key requires a non-empty --project value.");
        }

        return new BootstrapApiKeyCliOptions(
            apiKey,
            vaultBaseUrl,
            projectDirectory,
            projectName,
            profile,
            json);
    }

    private static VaultStatusOptions ParseVaultStatusArgs(string[] args)
    {
        string? yamlPath = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown vault option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet vault requires --yaml <tn.yaml>.");
        }

        return new VaultStatusOptions(yamlPath, json);
    }

    private static WalletStatusOptions ParseWalletStatusArgs(string[] args)
    {
        string? yamlPath = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown wallet status option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet wallet status requires --yaml <tn.yaml>.");
        }

        return new WalletStatusOptions(yamlPath, json);
    }

    private static WalletLinkCliOptions ParseWalletLinkArgs(string[] args)
    {
        string? yamlPath = null;
        string? vaultBaseUrl = null;
        string? projectId = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--project-id":
                    projectId = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown wallet link option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet wallet link requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new ArgumentException("tn-dotnet wallet link requires --vault <url>.");
        }

        if (string.IsNullOrWhiteSpace(projectId))
        {
            throw new ArgumentException("tn-dotnet wallet link requires --project-id <id>.");
        }

        return new WalletLinkCliOptions(yamlPath, vaultBaseUrl, projectId, json);
    }

    private static WalletUnlinkCliOptions ParseWalletUnlinkArgs(string[] args)
    {
        string? yamlPath = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown wallet unlink option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet wallet unlink requires --yaml <tn.yaml>.");
        }

        return new WalletUnlinkCliOptions(yamlPath, json);
    }

    private static WalletPullPrefsCliOptions ParseWalletPullPrefsArgs(string[] args)
    {
        string? yamlPath = null;
        string? vaultBaseUrl = null;
        string? bearerToken = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--bearer":
                    bearerToken = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown wallet pull-prefs option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet wallet pull-prefs requires --yaml <tn.yaml>.");
        }

        return new WalletPullPrefsCliOptions(yamlPath, vaultBaseUrl, bearerToken, json);
    }

    private static WalletStageInboxCliOptions ParseWalletStageInboxArgs(string[] args)
    {
        string? yamlPath = null;
        string? vaultBaseUrl = null;
        string? bearerToken = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--bearer":
                    bearerToken = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown wallet stage-inbox option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet wallet stage-inbox requires --yaml <tn.yaml>.");
        }

        return new WalletStageInboxCliOptions(yamlPath, vaultBaseUrl, bearerToken, json);
    }

    private static WalletSyncCliOptions ParseWalletSyncArgs(string[] args)
    {
        string? yamlPath = null;
        string? vaultBaseUrl = null;
        string? bearerToken = null;
        string? projectId = null;
        string? passphrase = null;
        string? credentialId = null;
        var groups = new List<string>();
        var pullOnly = false;
        var pushOnly = false;
        var pushBody = false;
        var publishGroupKeys = true;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--bearer":
                    bearerToken = RequireValue(args, ref i, args[i]);
                    break;
                case "--pull-only":
                    pullOnly = true;
                    break;
                case "--push-only":
                    pushOnly = true;
                    break;
                case "--push-body":
                    pushBody = true;
                    break;
                case "--no-group-keys":
                    publishGroupKeys = false;
                    break;
                case "--group":
                    groups.Add(RequireValue(args, ref i, args[i]));
                    break;
                case "--project-id":
                    projectId = RequireValue(args, ref i, args[i]);
                    break;
                case "--passphrase":
                    passphrase = RequireValue(args, ref i, args[i]);
                    break;
                case "--credential-id":
                    credentialId = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown wallet sync option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet wallet sync requires --yaml <tn.yaml>.");
        }

        if (pullOnly && pushOnly)
        {
            throw new ArgumentException("tn-dotnet wallet sync cannot combine --pull-only and --push-only.");
        }

        if (!string.IsNullOrWhiteSpace(passphrase) && !pushBody)
        {
            throw new ArgumentException("tn-dotnet wallet sync requires --push-body when --passphrase is supplied.");
        }

        if (pushBody && string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("tn-dotnet wallet sync --push-body requires --passphrase <value>.");
        }

        return new WalletSyncCliOptions(
            yamlPath,
            vaultBaseUrl,
            bearerToken,
            pullOnly,
            pushOnly,
            publishGroupKeys,
            pushBody,
            groups,
            projectId,
            passphrase,
            credentialId,
            json);
    }

    private static WalletPublishGroupKeysCliOptions ParseWalletPublishGroupKeysArgs(string[] args)
    {
        string? yamlPath = null;
        string? vaultBaseUrl = null;
        string? bearerToken = null;
        var groups = new List<string>();
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--bearer":
                    bearerToken = RequireValue(args, ref i, args[i]);
                    break;
                case "--group":
                    groups.Add(RequireValue(args, ref i, args[i]));
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown wallet publish-group-keys option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet wallet publish-group-keys requires --yaml <tn.yaml>.");
        }

        return new WalletPublishGroupKeysCliOptions(yamlPath, vaultBaseUrl, bearerToken, groups, json);
    }

    private static WalletRestoreCliOptions ParseWalletRestoreArgs(string[] args)
    {
        string? yamlPath = null;
        string? vaultBaseUrl = null;
        string? bearerToken = null;
        string? projectId = null;
        string? passphrase = null;
        string? accountId = null;
        string? credentialId = null;
        string? targetDirectory = null;
        var useCachedAccountKey = false;
        var overwrite = false;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--bearer":
                    bearerToken = RequireValue(args, ref i, args[i]);
                    break;
                case "--project-id":
                    projectId = RequireValue(args, ref i, args[i]);
                    break;
                case "--passphrase":
                    passphrase = RequireValue(args, ref i, args[i]);
                    break;
                case "--use-cached-account-key":
                    useCachedAccountKey = true;
                    break;
                case "--account-id":
                    accountId = RequireValue(args, ref i, args[i]);
                    break;
                case "--credential-id":
                    credentialId = RequireValue(args, ref i, args[i]);
                    break;
                case "--target-dir":
                    targetDirectory = RequireValue(args, ref i, args[i]);
                    break;
                case "--overwrite":
                    overwrite = true;
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown wallet restore option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet wallet restore requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(targetDirectory))
        {
            throw new ArgumentException("tn-dotnet wallet restore requires --target-dir <dir>.");
        }

        if (useCachedAccountKey && !string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("tn-dotnet wallet restore accepts either --passphrase or --use-cached-account-key, not both.");
        }

        if (!useCachedAccountKey && string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException("tn-dotnet wallet restore requires --passphrase <value> or --use-cached-account-key.");
        }

        return new WalletRestoreCliOptions(
            yamlPath,
            vaultBaseUrl,
            bearerToken,
            projectId,
            passphrase,
            useCachedAccountKey,
            accountId,
            credentialId,
            targetDirectory,
            overwrite,
            json);
    }

    private static WalletExportMnemonicCliOptions ParseWalletExportMnemonicArgs(string[] args)
    {
        string? identityPath = null;
        var yes = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--identity":
                    identityPath = RequireValue(args, ref i, "--identity");
                    break;
                case "--yes":
                    yes = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown wallet export-mnemonic option: {args[i]}");
            }
        }

        return new WalletExportMnemonicCliOptions(identityPath ?? TnIdentity.DefaultIdentityPath(), yes);
    }

    private static VaultLinkCliOptions ParseVaultLinkArgs(string[] args)
    {
        string? yamlPath = null;
        string? vaultBaseUrl = null;
        string? projectId = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--project-id":
                    projectId = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown vault link option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet vault link requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new ArgumentException("tn-dotnet vault link requires --vault <url>.");
        }

        if (string.IsNullOrWhiteSpace(projectId))
        {
            throw new ArgumentException("tn-dotnet vault link requires --project-id <id>.");
        }

        return new VaultLinkCliOptions(yamlPath, vaultBaseUrl, projectId, json);
    }

    private static VaultConnectCliOptions ParseVaultConnectArgs(string[] args)
    {
        string? yamlPath = null;
        string? vaultBaseUrl = null;
        string? bearerToken = null;
        string? projectName = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--bearer":
                    bearerToken = RequireValue(args, ref i, args[i]);
                    break;
                case "--project-name":
                    projectName = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown vault connect option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet vault connect requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new ArgumentException("tn-dotnet vault connect requires --vault <url>.");
        }

        return new VaultConnectCliOptions(yamlPath, vaultBaseUrl, bearerToken, projectName, json);
    }

    private static VaultClaimLinkOptions ParseVaultClaimLinkArgs(string[] args)
    {
        string? yamlPath = null;
        string? vaultBaseUrl = null;
        string? projectName = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--vault":
                    vaultBaseUrl = RequireValue(args, ref i, args[i]);
                    break;
                case "--project-name":
                    projectName = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown vault claim-link option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet vault claim-link requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(vaultBaseUrl))
        {
            throw new ArgumentException("tn-dotnet vault claim-link requires --vault <url>.");
        }

        return new VaultClaimLinkOptions(yamlPath, vaultBaseUrl, projectName, json);
    }

    private static StreamsOptions ParseStreamsArgs(string[] args)
    {
        string? projectDirectory = null;
        var format = "human";

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--project-dir":
                case "--dir":
                    projectDirectory = RequireValue(args, ref i, args[i]);
                    break;
                case "--format":
                    format = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    format = "json";
                    break;
                default:
                    throw new ArgumentException($"Unknown streams option: {args[i]}");
            }
        }

        if (format is not "human" and not "json")
        {
            throw new ArgumentException("--format must be human or json.");
        }

        return new StreamsOptions(projectDirectory, format);
    }

    private static int RunShowProfiles(string[] args, TextWriter output)
    {
        var format = ParseShowProfilesArgs(args);
        var profiles = TnProfiles.All;

        if (format == "json")
        {
            output.WriteLine(JsonSerializer.Serialize(new
            {
                profiles = profiles.Select(profile => new
                {
                    name = profile.Name,
                    encrypts = profile.Encrypts,
                    signs = profile.Signs,
                    chains = profile.Chains,
                    flush = profile.Flush,
                    default_sink = profile.DefaultSink,
                    intended_use = profile.IntendedUse,
                    @default = profile.Default,
                    has_replay_surface = profile.HasReplaySurface,
                }),
            }, JsonOptions));
            return 0;
        }

        output.WriteLine("NAME          ENCRYPTS  SIGNS  CHAINS  FLUSH     SINK");
        output.WriteLine("------------  --------  -----  ------  --------  -------------");
        foreach (var profile in profiles)
        {
            var name = profile.Name + (profile.Default ? "*" : " ");
            output.WriteLine(
                $"{name.PadRight(12)}  " +
                $"{YesNo(profile.Encrypts).PadRight(8)}  " +
                $"{YesNo(profile.Signs).PadRight(5)}  " +
                $"{YesNo(profile.Chains).PadRight(6)}  " +
                $"{profile.Flush.PadRight(8)}  " +
                profile.DefaultSink);
        }

        output.WriteLine();
        output.WriteLine("* = catalog default (used when project creation omits a profile).");
        output.WriteLine();
        foreach (var profile in profiles)
        {
            output.WriteLine($"{profile.Name}: {profile.IntendedUse}");
            output.WriteLine();
        }

        return 0;
    }

    private static async Task<int> RunAdminAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet admin add-recipient <group> --yaml <tn.yaml> --out <kit.btn.mykit> [--recipient-did <did>] [--json]");
        }

        return args[0] switch
        {
            "add-recipient" => await RunAdminAddRecipientAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "revoke-recipient" => await RunAdminRevokeRecipientAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "rotate" => await RunAdminRotateAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "revoked-count" => await RunAdminRevokedCountAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentException($"Unknown admin command: {args[0]}"),
        };
    }

    private static async Task<int> RunRotateAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseRotateArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Rotation.RotateAsync(
            new RotateOptions
            {
                Groups = options.Groups,
                OutPath = options.OutPath,
                SealForRecipient = options.Seal,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                ok = true,
                rotated = result.Rotated.Select(group => new
                {
                    group = group.Group,
                    generation = group.Generation,
                }),
                artifacts = result.Artifacts.Select(artifact => artifact.Path),
                out_dir = result.OutDirectory,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else if (result.Artifacts.Count == 0)
        {
            await output.WriteLineAsync(
                $"rotated {result.Rotated.Count} group(s); no surviving recipients to bundle for")
                .ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync(
                $"rotated {result.Rotated.Count} group(s); emitted {result.Artifacts.Count} .tnpkg artifact(s) into {result.OutDirectory}")
                .ConfigureAwait(false);
            foreach (var artifact in result.Artifacts)
            {
                await output.WriteLineAsync($"-> {Path.GetFileName(artifact.Path)}").ConfigureAwait(false);
            }
        }

        return 0;
    }

    private static async Task<int> RunAdminRotateAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseAdminRotateArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Admin.RotateAsync(options.Group, cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                group = result.Group,
                generation = result.Generation,
                previous_kit_sha256 = result.PreviousKitSha256,
                new_kit_sha256 = result.NewKitSha256,
                rotated_at = result.RotatedAt,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync(
                $"rotated {result.Group} to generation {result.Generation}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunAdminRevokedCountAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseAdminRevokedCountArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var count = await tn.Admin.RevokedCountAsync(
            options.Group,
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                group = options.Group,
                revoked_count = count,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync(count.ToString()).ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunAdminRevokeRecipientAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseAdminRevokeRecipientArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Admin.RevokeRecipientAsync(
            options.Group,
            options.LeafIndex,
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                group = result.Group,
                leaf_index = result.LeafIndex,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"revoked recipient leaf {result.LeafIndex} from {result.Group}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunAdminAddRecipientAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseAdminAddRecipientArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Admin.AddRecipientAsync(
            options.Group,
            options.OutKitPath,
            options.RecipientDid,
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                group = result.Group,
                recipient_did = result.RecipientDid,
                leaf_index = result.LeafIndex,
                kit_path = result.KitPath,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"recipient leaf {result.LeafIndex} kit: {result.KitPath}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunGroupAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet group add <group> --yaml <tn.yaml> --field <name> [--field <name>...] [--json]");
        }

        return args[0] switch
        {
            "add" => await RunGroupAddAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentException($"Unknown group command: {args[0]}"),
        };
    }

    private static async Task<int> RunGroupAddAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseGroupAddArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Admin.EnsureGroupAsync(
            options.Group,
            options.Fields,
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                group = result.Group,
                fields = result.Fields,
                created = result.Created,
                changed = result.Changed,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            var state = result.Created ? "created" : result.Changed ? "updated" : "unchanged";
            await output.WriteLineAsync($"group {result.Group} {state}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunBundleAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseBundleArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Packages.BundleForRecipientAsync(
            options.RecipientDid,
            options.OutPath,
            new BundleForRecipientOptions
            {
                Groups = options.Groups.Count == 0 ? null : options.Groups,
                SealForRecipient = options.Seal,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                path = result.Path,
                recipient_did = result.RecipientDid,
                groups = result.Groups,
                sealed_for_recipient = options.Seal,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"bundle: {result.Path}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunCompileAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseCompileArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Packages.CompileEnrolmentAsync(
            new CompileEnrolmentOptions
            {
                Group = options.Group,
                RecipientDid = options.RecipientDid,
                OutPath = options.OutPath,
                SealForRecipient = options.Seal,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                path = result.Path,
                recipient_did = result.RecipientDid,
                groups = result.Groups,
                manifest_sha256 = result.ManifestSha256,
                package_sha256 = result.PackageSha256,
                sealed_for_recipient = options.Seal,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"compiled: {result.Path}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunAbsorbAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseAbsorbArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var receipt = await tn.Packages.AbsorbAsync(options.PackagePath, cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                kind = receipt.Kind,
                status = receipt.Status,
                accepted_count = receipt.AcceptedCount,
                deduped_count = receipt.DedupedCount,
                noop = receipt.IsNoOp,
                conflict_count = receipt.ConflictCount,
                legacy_status = receipt.LegacyStatus,
                legacy_reason = receipt.LegacyReason,
                replaced_kit_paths = receipt.ReplacedKitPaths,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync(
                $"absorbed {receipt.Kind}: {receipt.Status} accepted={receipt.AcceptedCount} deduped={receipt.DedupedCount} conflicts={receipt.ConflictCount}")
                .ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunInviteAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseInviteArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Inbox.MintInviteAsync(
            options.Recipient,
            options.OutPath,
            new MintInvitationOptions
            {
                Group = options.Group,
                FromEmail = options.FromEmail,
                ProjectId = options.ProjectId,
                ProjectName = options.ProjectName,
                Note = options.Note,
                InvitationId = options.InvitationId,
                Provenance = options.Provenance,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                path = result.Path,
                recipient_did = result.RecipientDid,
                group = result.Manifest.GroupName,
                from_email = result.Manifest.FromEmail,
                project_id = result.Manifest.ProjectId,
                project_name = result.Manifest.ProjectName,
                invitation_id = result.Manifest.InvitationId,
                note = result.Manifest.Note,
                provenance = result.Manifest.Provenance,
                kit_entry_name = result.KitEntryName,
                zip_len = result.ZipLength,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"invite: {result.Path}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunInboxAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet inbox list-local --yaml <tn.yaml> --dir <path> [--json]");
        }

        return args[0] switch
        {
            "list-local" => await RunInboxListLocalAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            "accept" => await RunInboxAcceptAsync(args[1..], output, cancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentException($"Unknown inbox command: {args[0]}"),
        };
    }

    private static async Task<int> RunInboxListLocalAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseInboxListLocalArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var paths = await tn.Inbox.ListLocalAsync(options.Directory, cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                directory = Path.GetFullPath(options.Directory),
                invites = paths,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            foreach (var path in paths)
            {
                await output.WriteLineAsync(path).ConfigureAwait(false);
            }
        }

        return 0;
    }

    private static async Task<int> RunInboxAcceptAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseInboxAcceptArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var result = await tn.Inbox.AcceptAsync(options.InvitePath, cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                kit_path = result.KitPath,
                backup_path = result.BackupPath,
                absorbed_at = result.AbsorbedAt,
                group_name = result.GroupName,
                from_email = result.FromEmail,
                leaf_index = result.LeafIndex,
                manifest = result.Info.Manifest.Raw,
                kit_entry_name = result.Info.KitEntryName,
                kit_len = result.Info.KitLength,
                kit_sha256_actual = result.Info.KitSha256Actual,
                kit_hash_verified = result.Info.KitHashVerified,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"accepted invite for {result.GroupName}: {result.KitPath}").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunWatchAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseWatchArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var watch = await tn.WatchAsync(
            new WatchOptions
            {
                FromBeginning = options.FromBeginning,
                EventType = options.EventType,
                EventTypePrefix = options.EventTypePrefix,
                PollInterval = TimeSpan.FromMilliseconds(options.PollMs),
                ReadOptions = new ReadOptions
                {
                    AllRuns = options.AllRuns,
                    Verify = options.Verify,
                },
            },
            cancellationToken).ConfigureAwait(false);

        var entries = new List<Entry>();
        var deadline = DateTimeOffset.UtcNow + TimeSpan.FromMilliseconds(options.TimeoutMs);

        while (true)
        {
            var remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining < TimeSpan.Zero)
            {
                remaining = TimeSpan.Zero;
            }

            var next = await watch.WaitForEntriesAsync(remaining, cancellationToken).ConfigureAwait(false);
            entries.AddRange(next);

            if (options.Limit is { } limit && entries.Count >= limit)
            {
                entries = entries.Take(limit).ToList();
                break;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                break;
            }
        }

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(entries.Select(entry => entry.Fields), JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            foreach (var entry in entries)
            {
                var prefix = entry.Sequence is { } sequence ? $"{sequence} " : string.Empty;
                await output.WriteLineAsync($"{prefix}{entry.EventType ?? "(unknown)"}").ConfigureAwait(false);
            }
        }

        return 0;
    }

    private static async Task<int> RunVerifyAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = await ParseJsonInputArgsAsync(
            args,
            "verify",
            "Usage: tn-dotnet verify (--json <envelope> | --file <path> | --stdin)",
            cancellationToken).ConfigureAwait(false);
        var result = TnCrypto.VerifyEnvelopeRaw(options.Json);
        await output.WriteLineAsync(JsonSerializer.Serialize(new
        {
            valid = result.Valid,
            signature = result.Signature,
            reason = result.Reason,
        }, JsonOptions)).ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunCanonicalAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = await ParseCanonicalArgsAsync(args, cancellationToken).ConfigureAwait(false);
        var result = options.Hex
            ? TnCanonical.BytesHexFromRaw(options.Json)
            : TnCanonical.JsonFromRaw(options.Json);
        await output.WriteLineAsync(result).ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunReadAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseReadArgs(args);
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var entries = await tn.ReadAsync(
            new ReadOptions
            {
                AllRuns = options.AllRuns,
                Verify = options.Verify,
            },
            cancellationToken).ConfigureAwait(false);

        var fields = entries.Select(entry => entry.Fields).ToArray();
        await output.WriteLineAsync(JsonSerializer.Serialize(fields, JsonOptions)).ConfigureAwait(false);
        return 0;
    }

    private static async Task<int> RunEmitAsync(
        string[] args,
        TextWriter output,
        TnLogLevel? level,
        CancellationToken cancellationToken)
    {
        var options = ParseEmitArgs(args, level is null ? "log" : "info");
        await using var tn = await Tn.InitAsync(options.YamlPath, cancellationToken).ConfigureAwait(false);
        var receipt = level is null
            ? await tn.LogAsync(options.EventType, options.Fields, cancellationToken: cancellationToken).ConfigureAwait(false)
            : await tn.EmitAsync(level.Value, options.EventType, options.Fields, cancellationToken: cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                emitted = receipt.Emitted,
                envelope = receipt.Envelope,
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync(receipt.Emitted ? $"emitted {options.EventType}" : "not emitted").ConfigureAwait(false);
        }

        return 0;
    }

    private static async Task<int> RunInitAsync(
        string[] args,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        var options = ParseInitArgs(args);
        await using var tn = await Tn.InitProjectAsync(
            options.Project,
            new TnProjectOptions
            {
                ProjectDirectory = options.ProjectDirectory,
                Profile = options.Profile,
            },
            cancellationToken).ConfigureAwait(false);

        if (options.Json)
        {
            await output.WriteLineAsync(JsonSerializer.Serialize(new
            {
                project = tn.ProjectName,
                yaml_path = tn.YamlPath,
                log_path = tn.LogPath,
                did = tn.Did,
                profile = options.Profile.ToTnName(),
            }, JsonOptions)).ConfigureAwait(false);
        }
        else
        {
            await output.WriteLineAsync($"initialized {tn.ProjectName}").ConfigureAwait(false);
            await output.WriteLineAsync($"yaml: {tn.YamlPath}").ConfigureAwait(false);
            await output.WriteLineAsync($"log: {tn.LogPath}").ConfigureAwait(false);
            await output.WriteLineAsync($"did: {tn.Did}").ConfigureAwait(false);
        }

        return 0;
    }

    private static InitOptions ParseInitArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet init <project> [--dir <path>] [--profile <name>] [--json]");
        }

        var project = args[0];
        string? projectDirectory = null;
        var profile = TnProfile.Transaction;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--dir":
                case "-d":
                    projectDirectory = RequireValue(args, ref i, args[i]);
                    break;
                case "--profile":
                case "-p":
                    profile = ParseProfile(RequireValue(args, ref i, args[i]));
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown init option: {args[i]}");
            }
        }

        return new InitOptions(project, projectDirectory, profile, json);
    }

    private static EmitOptions ParseEmitArgs(string[] args, string command)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException($"Usage: tn-dotnet {command} <event-type> --yaml <tn.yaml> [--fields <json>] [--json]");
        }

        var eventType = args[0];
        string? yamlPath = null;
        var fields = new JsonObject();
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--fields":
                case "-f":
                    fields = ParseFields(RequireValue(args, ref i, args[i]));
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown {command} option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException($"tn-dotnet {command} requires --yaml <tn.yaml>.");
        }

        return new EmitOptions(eventType, yamlPath, fields, json);
    }

    private static ReadCliOptions ParseReadArgs(string[] args)
    {
        if (args.Length > 0 && IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet read --yaml <tn.yaml> [--all-runs] [--verify]");
        }

        string? yamlPath = null;
        var allRuns = false;
        var verify = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--all-runs":
                    allRuns = true;
                    break;
                case "--verify":
                    verify = true;
                    break;
                case "--json":
                    break;
                default:
                    throw new ArgumentException($"Unknown read option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet read requires --yaml <tn.yaml>.");
        }

        return new ReadCliOptions(yamlPath, allRuns, verify);
    }

    private static GroupAddOptions ParseGroupAddArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet group add <group> --yaml <tn.yaml> --field <name> [--field <name>...] [--json]");
        }

        var group = args[0];
        string? yamlPath = null;
        var fields = new List<string>();
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--field":
                case "-f":
                    fields.Add(RequireValue(args, ref i, args[i]));
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown group add option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet group add requires --yaml <tn.yaml>.");
        }

        if (fields.Count == 0)
        {
            throw new ArgumentException("tn-dotnet group add requires at least one --field <name>.");
        }

        return new GroupAddOptions(group, yamlPath, fields, json);
    }

    private static AdminAddRecipientOptions ParseAdminAddRecipientArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet admin add-recipient <group> --yaml <tn.yaml> --out <kit.btn.mykit> [--recipient-did <did>] [--json]");
        }

        var group = args[0];
        string? yamlPath = null;
        string? outKitPath = null;
        string? recipientDid = null;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--out":
                case "-o":
                    outKitPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--recipient-did":
                    recipientDid = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown admin add-recipient option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet admin add-recipient requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(outKitPath))
        {
            throw new ArgumentException("tn-dotnet admin add-recipient requires --out <kit.btn.mykit>.");
        }

        return new AdminAddRecipientOptions(group, yamlPath, outKitPath, recipientDid, json);
    }

    private static AdminRevokeRecipientOptions ParseAdminRevokeRecipientArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet admin revoke-recipient <group> --yaml <tn.yaml> --leaf <index> [--json]");
        }

        var group = args[0];
        string? yamlPath = null;
        ulong? leafIndex = null;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--leaf":
                    var rawLeaf = RequireValue(args, ref i, args[i]);
                    if (!ulong.TryParse(rawLeaf, out var parsedLeaf))
                    {
                        throw new ArgumentException("--leaf must be a non-negative integer.");
                    }

                    leafIndex = parsedLeaf;
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown admin revoke-recipient option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet admin revoke-recipient requires --yaml <tn.yaml>.");
        }

        if (leafIndex is null)
        {
            throw new ArgumentException("tn-dotnet admin revoke-recipient requires --leaf <index>.");
        }

        return new AdminRevokeRecipientOptions(group, yamlPath, leafIndex.Value, json);
    }

    private static AdminRevokedCountOptions ParseAdminRevokedCountArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet admin revoked-count <group> --yaml <tn.yaml> [--json]");
        }

        var group = args[0];
        string? yamlPath = null;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown admin revoked-count option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet admin revoked-count requires --yaml <tn.yaml>.");
        }

        return new AdminRevokedCountOptions(group, yamlPath, json);
    }

    private static AdminRotateOptions ParseAdminRotateArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet admin rotate <group> --yaml <tn.yaml> [--json]");
        }

        var group = args[0];
        string? yamlPath = null;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown admin rotate option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet admin rotate requires --yaml <tn.yaml>.");
        }

        return new AdminRotateOptions(group, yamlPath, json);
    }

    private static RotateCliOptions ParseRotateArgs(string[] args)
    {
        string? positionalGroup = null;
        string? groupsCsv = null;
        string? yamlPath = null;
        string? outPath = null;
        var seal = false;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--groups":
                    groupsCsv = RequireValue(args, ref i, args[i]);
                    break;
                case "--out":
                case "-o":
                    outPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--seal":
                    seal = true;
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    if (args[i].StartsWith("-", StringComparison.Ordinal))
                    {
                        throw new ArgumentException($"Unknown rotate option: {args[i]}");
                    }

                    if (positionalGroup is not null)
                    {
                        throw new ArgumentException("tn-dotnet rotate accepts at most one positional group.");
                    }

                    positionalGroup = args[i];
                    break;
            }
        }

        if (positionalGroup is not null && groupsCsv is not null)
        {
            throw new ArgumentException("Pass either a positional <group> or --groups, not both.");
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet rotate requires --yaml <tn.yaml>.");
        }

        var groups = groupsCsv is not null
            ? groupsCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : positionalGroup is not null
                ? [positionalGroup]
                : null;

        return new RotateCliOptions(yamlPath, groups, outPath, seal, json);
    }

    private static BundleOptions ParseBundleArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet bundle --yaml <tn.yaml> --recipient-did <did> --out <bundle.tnpkg> [--group <name>...] [--seal] [--json]");
        }

        string? yamlPath = null;
        string? recipientDid = null;
        string? outPath = null;
        var groups = new List<string>();
        var seal = false;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--recipient-did":
                    recipientDid = RequireValue(args, ref i, args[i]);
                    break;
                case "--out":
                case "-o":
                    outPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--group":
                case "-g":
                    groups.Add(RequireValue(args, ref i, args[i]));
                    break;
                case "--seal":
                    seal = true;
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown bundle option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet bundle requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(recipientDid))
        {
            throw new ArgumentException("tn-dotnet bundle requires --recipient-did <did>.");
        }

        if (string.IsNullOrWhiteSpace(outPath))
        {
            throw new ArgumentException("tn-dotnet bundle requires --out <bundle.tnpkg>.");
        }

        return new BundleOptions(yamlPath, recipientDid, outPath, groups, seal, json);
    }

    private static CompileOptions ParseCompileArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet compile <group> --yaml <tn.yaml> --recipient-did <did> --out <bundle.tnpkg> [--seal] [--json]");
        }

        var group = args[0];
        string? yamlPath = null;
        string? recipientDid = null;
        string? outPath = null;
        var seal = false;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--recipient-did":
                    recipientDid = RequireValue(args, ref i, args[i]);
                    break;
                case "--out":
                case "-o":
                    outPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--seal":
                    seal = true;
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown compile option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet compile requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(recipientDid))
        {
            throw new ArgumentException("tn-dotnet compile requires --recipient-did <did>.");
        }

        if (string.IsNullOrWhiteSpace(outPath))
        {
            throw new ArgumentException("tn-dotnet compile requires --out <bundle.tnpkg>.");
        }

        return new CompileOptions(group, yamlPath, recipientDid, outPath, seal, json);
    }

    private static AbsorbOptions ParseAbsorbArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet absorb <package.tnpkg> --yaml <tn.yaml> [--json]");
        }

        var packagePath = args[0];
        string? yamlPath = null;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown absorb option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet absorb requires --yaml <tn.yaml>.");
        }

        return new AbsorbOptions(packagePath, yamlPath, json);
    }

    private static InviteOptions ParseInviteArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet invite <recipient> --yaml <tn.yaml> --out <tn-invite.zip> [--group <name>] [--from-email <email>] [--project-id <id>] [--project-name <name>] [--note <text>] [--invitation-id <id>] [--provenance <value>] [--json]");
        }

        var recipient = args[0];
        string? yamlPath = null;
        string? outPath = null;
        string? group = null;
        string? fromEmail = null;
        string? projectId = null;
        string? projectName = null;
        string? note = null;
        string? invitationId = null;
        string? provenance = null;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--out":
                case "-o":
                    outPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--group":
                case "-g":
                    group = RequireValue(args, ref i, args[i]);
                    break;
                case "--from-email":
                    fromEmail = RequireValue(args, ref i, args[i]);
                    break;
                case "--project-id":
                    projectId = RequireValue(args, ref i, args[i]);
                    break;
                case "--project-name":
                    projectName = RequireValue(args, ref i, args[i]);
                    break;
                case "--note":
                    note = RequireValue(args, ref i, args[i]);
                    break;
                case "--invitation-id":
                    invitationId = RequireValue(args, ref i, args[i]);
                    break;
                case "--provenance":
                    provenance = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown invite option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet invite requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(outPath))
        {
            throw new ArgumentException("tn-dotnet invite requires --out <tn-invite.zip>.");
        }

        return new InviteOptions(
            recipient,
            yamlPath,
            outPath,
            group,
            fromEmail,
            projectId,
            projectName,
            note,
            invitationId,
            provenance,
            json);
    }

    private static InboxListLocalOptions ParseInboxListLocalArgs(string[] args)
    {
        if (args.Length > 0 && IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet inbox list-local --yaml <tn.yaml> --dir <path> [--json]");
        }

        string? yamlPath = null;
        string? directory = null;
        var json = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--dir":
                case "-d":
                    directory = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown inbox list-local option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet inbox list-local requires --yaml <tn.yaml>.");
        }

        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new ArgumentException("tn-dotnet inbox list-local requires --dir <path>.");
        }

        return new InboxListLocalOptions(yamlPath, directory, json);
    }

    private static InboxAcceptOptions ParseInboxAcceptArgs(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet inbox accept <tn-invite.zip> --yaml <tn.yaml> [--json]");
        }

        var invitePath = args[0];
        string? yamlPath = null;
        var json = false;

        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown inbox accept option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet inbox accept requires --yaml <tn.yaml>.");
        }

        return new InboxAcceptOptions(invitePath, yamlPath, json);
    }

    private static WatchCliOptions ParseWatchArgs(string[] args)
    {
        if (args.Length > 0 && IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet watch --yaml <tn.yaml> [--from-beginning] [--event-type <type>] [--event-type-prefix <prefix>] [--timeout-ms <ms>] [--poll-ms <ms>] [--limit <n>] [--all-runs] [--verify] [--json]");
        }

        string? yamlPath = null;
        string? eventType = null;
        string? eventTypePrefix = null;
        var fromBeginning = false;
        var allRuns = false;
        var verify = false;
        var json = false;
        var timeoutMs = 30_000;
        var pollMs = 100;
        int? limit = null;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--from-beginning":
                    fromBeginning = true;
                    break;
                case "--event-type":
                    eventType = RequireValue(args, ref i, args[i]);
                    break;
                case "--event-type-prefix":
                    eventTypePrefix = RequireValue(args, ref i, args[i]);
                    break;
                case "--timeout-ms":
                    timeoutMs = ParseNonNegativeInt(RequireValue(args, ref i, args[i]), "--timeout-ms");
                    break;
                case "--poll-ms":
                    pollMs = ParsePositiveInt(RequireValue(args, ref i, args[i]), "--poll-ms");
                    break;
                case "--limit":
                    limit = ParsePositiveInt(RequireValue(args, ref i, args[i]), "--limit");
                    break;
                case "--all-runs":
                    allRuns = true;
                    break;
                case "--verify":
                    verify = true;
                    break;
                case "--json":
                    json = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown watch option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet watch requires --yaml <tn.yaml>.");
        }

        return new WatchCliOptions(
            yamlPath,
            fromBeginning,
            eventType,
            eventTypePrefix,
            timeoutMs,
            pollMs,
            limit,
            allRuns,
            verify,
            json);
    }

    private static int ParseNonNegativeInt(string value, string option)
    {
        if (!int.TryParse(value, out var parsed) || parsed < 0)
        {
            throw new ArgumentException($"{option} must be a non-negative integer.");
        }

        return parsed;
    }

    private static int ParsePositiveInt(string value, string option)
    {
        if (!int.TryParse(value, out var parsed) || parsed <= 0)
        {
            throw new ArgumentException($"{option} must be a positive integer.");
        }

        return parsed;
    }

    private static string ParseShowProfilesArgs(string[] args)
    {
        var format = "human";

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--format":
                    format = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    format = "json";
                    break;
                default:
                    throw new ArgumentException($"Unknown show profiles option: {args[i]}");
            }
        }

        if (format is not "human" and not "json")
        {
            throw new ArgumentException("--format must be human or json.");
        }

        return format;
    }

    private static ShowEnvOptions ParseShowEnvArgs(string[] args)
    {
        string? yamlPath = null;
        var format = "human";

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--yaml":
                case "-y":
                    yamlPath = RequireValue(args, ref i, args[i]);
                    break;
                case "--format":
                    format = RequireValue(args, ref i, args[i]);
                    break;
                case "--json":
                    format = "json";
                    break;
                default:
                    throw new ArgumentException($"Unknown show env option: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("tn-dotnet show env requires --yaml <tn.yaml>.");
        }

        if (format is not "human" and not "json")
        {
            throw new ArgumentException("--format must be human or json.");
        }

        return new ShowEnvOptions(yamlPath, format);
    }

    private static string YesNo(bool value)
    {
        return value ? "yes" : "no";
    }

    private static string Pad(string value, int width)
    {
        return value.Length >= width ? value : value.PadRight(width);
    }

    private static async Task<CanonicalOptions> ParseCanonicalArgsAsync(
        string[] args,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException("Usage: tn-dotnet canonical (--json <value> | --file <path> | --stdin) [--hex]");
        }

        var hex = false;
        var filtered = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--hex")
            {
                hex = true;
            }
            else
            {
                filtered.Add(args[i]);
            }
        }

        var input = await ParseJsonInputArgsAsync(
            filtered.ToArray(),
            "canonical",
            "Usage: tn-dotnet canonical (--json <value> | --file <path> | --stdin) [--hex]",
            cancellationToken).ConfigureAwait(false);
        return new CanonicalOptions(input.Json, hex);
    }

    private static async Task<JsonInputOptions> ParseJsonInputArgsAsync(
        string[] args,
        string command,
        string usage,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            throw new ArgumentException(usage);
        }

        string? json = null;
        string? file = null;
        var stdin = false;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--json":
                case "-j":
                    json = RequireValue(args, ref i, args[i]);
                    break;
                case "--file":
                    file = RequireValue(args, ref i, args[i]);
                    break;
                case "--stdin":
                    stdin = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown {command} option: {args[i]}");
            }
        }

        var sources = (json is null ? 0 : 1) + (file is null ? 0 : 1) + (stdin ? 1 : 0);
        if (sources != 1)
        {
            throw new ArgumentException($"{command} requires exactly one input source: --json, --file, or --stdin.");
        }

        if (file is not null)
        {
            json = await File.ReadAllTextAsync(Path.GetFullPath(file), cancellationToken).ConfigureAwait(false);
        }
        else if (stdin)
        {
            json = await Console.In.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        }

        return new JsonInputOptions(json ?? string.Empty);
    }

    private static JsonObject ParseFields(string fieldsJson)
    {
        if (string.IsNullOrWhiteSpace(fieldsJson))
        {
            throw new ArgumentException("Fields JSON must not be empty.");
        }

        JsonNode? node;
        try
        {
            node = JsonNode.Parse(fieldsJson);
        }
        catch (JsonException ex)
        {
            throw new ArgumentException($"Fields must be valid JSON: {ex.Message}", ex);
        }

        return node as JsonObject
            ?? throw new ArgumentException("Fields JSON must be an object.");
    }

    private static string RequireValue(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith("-", StringComparison.Ordinal))
        {
            throw new ArgumentException($"{option} requires a value.");
        }

        index++;
        return args[index];
    }

    private static TnProfile ParseProfile(string value)
    {
        return value.Trim().ToLowerInvariant() switch
        {
            "transaction" => TnProfile.Transaction,
            "audit" => TnProfile.Audit,
            "secure_log" or "secure-log" => TnProfile.SecureLog,
            "telemetry" => TnProfile.Telemetry,
            "stdout" => TnProfile.Stdout,
            _ => throw new ArgumentException($"Unknown profile: {value}"),
        };
    }

    private static bool IsHelp(string value)
    {
        return value is "-h" or "--help" or "help";
    }

    private static int UnknownCommand(string command, TextWriter error)
    {
        error.WriteLine($"Unknown command: {command}");
        error.WriteLine("Run 'tn-dotnet --help' for usage.");
        return 2;
    }

    private static void WriteUsage(TextWriter output)
    {
        output.WriteLine($"{CliInfo.CommandName} ({TnSdk.PackageName} {TnSdk.Status})");
        output.WriteLine();
        output.WriteLine("Usage:");
        output.WriteLine("  tn-dotnet init <project> [--dir <path>] [--profile <name>] [--json]");
        output.WriteLine("  tn-dotnet log <event-type> --yaml <tn.yaml> [--fields <json>] [--json]");
        output.WriteLine("  tn-dotnet info <event-type> --yaml <tn.yaml> [--fields <json>] [--json]");
        output.WriteLine("  tn-dotnet read --yaml <tn.yaml> [--all-runs] [--verify]");
        output.WriteLine("  tn-dotnet seal < seal-input.ndjson > envelope.ndjson");
        output.WriteLine("  tn-dotnet canonical (--json <value> | --file <path> | --stdin) [--hex]");
        output.WriteLine("  tn-dotnet verify (--json <envelope> | --file <path> | --stdin)");
        output.WriteLine("  tn-dotnet group add <group> --yaml <tn.yaml> --field <name> [--field <name>...] [--json]");
        output.WriteLine("  tn-dotnet admin add-recipient <group> --yaml <tn.yaml> --out <kit.btn.mykit> [--recipient-did <did>] [--json]");
        output.WriteLine("  tn-dotnet admin revoke-recipient <group> --yaml <tn.yaml> --leaf <index> [--json]");
        output.WriteLine("  tn-dotnet admin rotate <group> --yaml <tn.yaml> [--json]");
        output.WriteLine("  tn-dotnet admin revoked-count <group> --yaml <tn.yaml> [--json]");
        output.WriteLine("  tn-dotnet rotate [group] --yaml <tn.yaml> [--groups a,b] [--out <dir|bundle.tnpkg>] [--seal] [--json]");
        output.WriteLine("  tn-dotnet bundle --yaml <tn.yaml> --recipient-did <did> --out <bundle.tnpkg> [--group <name>...] [--seal] [--json]");
        output.WriteLine("  tn-dotnet compile <group> --yaml <tn.yaml> --recipient-did <did> --out <bundle.tnpkg> [--seal] [--json]");
        output.WriteLine("  tn-dotnet absorb <package.tnpkg> --yaml <tn.yaml> [--json]");
        output.WriteLine("  tn-dotnet invite <recipient> --yaml <tn.yaml> --out <tn-invite.zip> [--group <name>] [--from-email <email>] [--json]");
        output.WriteLine("  tn-dotnet inbox list-local --yaml <tn.yaml> --dir <path> [--json]");
        output.WriteLine("  tn-dotnet inbox accept <tn-invite.zip> --yaml <tn.yaml> [--json]");
        output.WriteLine("  tn-dotnet account status --yaml <tn.yaml> [--json]");
        output.WriteLine("  tn-dotnet account connect <code> --yaml <tn.yaml> --vault <url> [--json]");
        output.WriteLine("  tn-dotnet account logout --yaml <tn.yaml> [--json]");
        output.WriteLine("  tn-dotnet bootstrap api-key --vault <url> [--api-key <value>] [--dir <path>] [--project <name>] [--profile <name>] [--json]");
        output.WriteLine("  tn-dotnet vault status --yaml <tn.yaml> [--json]");
        output.WriteLine("  tn-dotnet vault claim-link --yaml <tn.yaml> --vault <url> [--project-name <name>] [--json]");
        output.WriteLine("  tn-dotnet vault connect --yaml <tn.yaml> --vault <url> [--bearer <token>] [--project-name <name>] [--json]");
        output.WriteLine("  tn-dotnet vault link --yaml <tn.yaml> --vault <url> --project-id <id> [--json]");
        output.WriteLine("  tn-dotnet vault unlink --yaml <tn.yaml> [--json]");
        output.WriteLine("  tn-dotnet wallet status --yaml <tn.yaml> [--json]");
        output.WriteLine("  tn-dotnet wallet link --yaml <tn.yaml> --vault <url> --project-id <id> [--json]");
        output.WriteLine("  tn-dotnet wallet unlink --yaml <tn.yaml> [--json]");
        output.WriteLine("  tn-dotnet wallet pull-prefs --yaml <tn.yaml> [--vault <url>] [--bearer <token>] [--json]");
        output.WriteLine("  tn-dotnet wallet stage-inbox --yaml <tn.yaml> [--vault <url>] [--bearer <token>] [--json]");
        output.WriteLine("  tn-dotnet wallet publish-group-keys --yaml <tn.yaml> [--vault <url>] [--bearer <token>] [--group <name>...] [--json]");
        output.WriteLine("  tn-dotnet wallet sync --yaml <tn.yaml> [--pull-only|--push-only] [--vault <url>] [--bearer <token>] [--group <name>...] [--no-group-keys] [--push-body --passphrase <value> [--project-id <id>] [--credential-id <id>]] [--json]");
        output.WriteLine("  tn-dotnet wallet restore --yaml <tn.yaml> --target-dir <dir> (--passphrase <value>|--use-cached-account-key [--account-id <id>]) [--vault <url>] [--bearer <token>] [--project-id <id>] [--credential-id <id>] [--overwrite] [--json]");
        output.WriteLine("  tn-dotnet wallet export-mnemonic [--identity <identity.json>] [--yes]");
        output.WriteLine("  tn-dotnet watch --yaml <tn.yaml> [--from-beginning] [--event-type <type>] [--event-type-prefix <prefix>] [--timeout-ms <ms>] [--limit <n>] [--json]");
        output.WriteLine("  tn-dotnet show env --yaml <tn.yaml> [--format human|json]");
        output.WriteLine("  tn-dotnet show profiles [--format human|json]");
        output.WriteLine("  tn-dotnet validate [--project-dir <path>] [--json]");
        output.WriteLine("  tn-dotnet streams [--project-dir <path>] [--format human|json]");
        output.WriteLine("  tn-dotnet firehose stats <tenant>");
        output.WriteLine("  tn-dotnet firehose list <tenant> [--did <did>]");
        output.WriteLine("  tn-dotnet firehose get <tenant> <ceremony> <name> [--did <did>] [--out <path>]");
    }

    private sealed record InitOptions(
        string Project,
        string? ProjectDirectory,
        TnProfile Profile,
        bool Json);

    private sealed record EmitOptions(
        string EventType,
        string YamlPath,
        JsonObject Fields,
        bool Json);

    private sealed record ReadCliOptions(
        string YamlPath,
        bool AllRuns,
        bool Verify);

    private sealed record GroupAddOptions(
        string Group,
        string YamlPath,
        IReadOnlyList<string> Fields,
        bool Json);

    private sealed record AdminAddRecipientOptions(
        string Group,
        string YamlPath,
        string OutKitPath,
        string? RecipientDid,
        bool Json);

    private sealed record AdminRevokeRecipientOptions(
        string Group,
        string YamlPath,
        ulong LeafIndex,
        bool Json);

    private sealed record AdminRevokedCountOptions(
        string Group,
        string YamlPath,
        bool Json);

    private sealed record AdminRotateOptions(
        string Group,
        string YamlPath,
        bool Json);

    private sealed record RotateCliOptions(
        string YamlPath,
        IReadOnlyList<string>? Groups,
        string? OutPath,
        bool Seal,
        bool Json);

    private sealed record BundleOptions(
        string YamlPath,
        string RecipientDid,
        string OutPath,
        IReadOnlyList<string> Groups,
        bool Seal,
        bool Json);

    private sealed record CompileOptions(
        string Group,
        string YamlPath,
        string RecipientDid,
        string OutPath,
        bool Seal,
        bool Json);

    private sealed record AbsorbOptions(
        string PackagePath,
        string YamlPath,
        bool Json);

    private sealed record InviteOptions(
        string Recipient,
        string YamlPath,
        string OutPath,
        string? Group,
        string? FromEmail,
        string? ProjectId,
        string? ProjectName,
        string? Note,
        string? InvitationId,
        string? Provenance,
        bool Json);

    private sealed record InboxListLocalOptions(
        string YamlPath,
        string Directory,
        bool Json);

    private sealed record InboxAcceptOptions(
        string InvitePath,
        string YamlPath,
        bool Json);

    private sealed record AccountStatusOptions(
        string YamlPath,
        bool Json);

    private sealed record AccountConnectCliOptions(
        string Code,
        string YamlPath,
        string VaultBaseUrl,
        bool Json);

    private sealed record BootstrapApiKeyCliOptions(
        string? ApiKey,
        string VaultBaseUrl,
        string? ProjectDirectory,
        string ProjectName,
        TnProfile Profile,
        bool Json);

    private sealed record VaultStatusOptions(
        string YamlPath,
        bool Json);

    private sealed record VaultLinkCliOptions(
        string YamlPath,
        string VaultBaseUrl,
        string ProjectId,
        bool Json);

    private sealed record VaultConnectCliOptions(
        string YamlPath,
        string VaultBaseUrl,
        string? BearerToken,
        string? ProjectName,
        bool Json);

    private sealed record VaultClaimLinkOptions(
        string YamlPath,
        string VaultBaseUrl,
        string? ProjectName,
        bool Json);

    private sealed record WalletStatusOptions(
        string YamlPath,
        bool Json);

    private sealed record WalletLinkCliOptions(
        string YamlPath,
        string VaultBaseUrl,
        string ProjectId,
        bool Json);

    private sealed record WalletUnlinkCliOptions(
        string YamlPath,
        bool Json);

    private sealed record WalletPullPrefsCliOptions(
        string YamlPath,
        string? VaultBaseUrl,
        string? BearerToken,
        bool Json);

    private sealed record WalletStageInboxCliOptions(
        string YamlPath,
        string? VaultBaseUrl,
        string? BearerToken,
        bool Json);

    private sealed record WalletSyncCliOptions(
        string YamlPath,
        string? VaultBaseUrl,
        string? BearerToken,
        bool PullOnly,
        bool PushOnly,
        bool PublishGroupKeys,
        bool PushBody,
        IReadOnlyList<string> Groups,
        string? ProjectId,
        string? Passphrase,
        string? CredentialId,
        bool Json);

    private sealed record WalletPublishGroupKeysCliOptions(
        string YamlPath,
        string? VaultBaseUrl,
        string? BearerToken,
        IReadOnlyList<string> Groups,
        bool Json);

    private sealed record WalletRestoreCliOptions(
        string YamlPath,
        string? VaultBaseUrl,
        string? BearerToken,
        string? ProjectId,
        string? Passphrase,
        bool UseCachedAccountKey,
        string? AccountId,
        string? CredentialId,
        string TargetDirectory,
        bool Overwrite,
        bool Json);

    private sealed record WalletExportMnemonicCliOptions(
        string IdentityPath,
        bool Yes);

    private sealed record WatchCliOptions(
        string YamlPath,
        bool FromBeginning,
        string? EventType,
        string? EventTypePrefix,
        int TimeoutMs,
        int PollMs,
        int? Limit,
        bool AllRuns,
        bool Verify,
        bool Json);

    private sealed record ShowEnvOptions(
        string YamlPath,
        string Format);

    private sealed record ValidateOptions(
        string? ProjectDirectory,
        bool Json);

    private sealed record StreamsOptions(
        string? ProjectDirectory,
        string Format);

    private sealed record CanonicalOptions(
        string Json,
        bool Hex);

    private sealed record JsonInputOptions(string Json);
}
