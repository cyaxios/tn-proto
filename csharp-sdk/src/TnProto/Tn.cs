using TnProto.Native;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TnProto;

/// <summary>
/// Main SDK handle for one loaded TN project.
/// </summary>
public sealed class Tn : IDisposable, IAsyncDisposable
{
    private TnNativeHandle _handle;
    private bool _disposed;

    private Tn(TnNativeHandle handle, string yamlPath, string logPath, string did, string? projectName, string? projectDirectory)
    {
        _handle = handle;
        YamlPath = Path.GetFullPath(yamlPath);
        LogPath = Path.GetFullPath(logPath);
        Did = did;
        ProjectName = projectName;
        ProjectDirectory = projectDirectory is null ? null : Path.GetFullPath(projectDirectory);
        Account = new Account.AccountClient(this);
        Admin = new Admin.AdminClient(this);
        Agents = new Agents.AgentsClient(this);
        Packages = new Packages.PackageClient(this);
        Inbox = new Inbox.InboxClient(this);
        Rotation = new Rotation.RotationClient(this);
        Vault = new Vault.VaultClient(this);
        Wallet = new Wallet.WalletClient(this);
    }

    /// <summary>
    /// Path to the loaded <c>tn.yaml</c>.
    /// </summary>
    public string YamlPath { get; }

    /// <summary>
    /// Path to the active TN log file.
    /// </summary>
    public string LogPath { get; }

    /// <summary>
    /// Active device DID for this project runtime.
    /// </summary>
    public string Did { get; }

    /// <summary>
    /// Project name when this handle was opened through project initialization.
    /// </summary>
    public string? ProjectName { get; }

    /// <summary>
    /// Directory that owns the project's <c>.tn</c> folder when known.
    /// </summary>
    public string? ProjectDirectory { get; }

    /// <summary>
    /// Account binding helpers for vault-backed workflows.
    /// </summary>
    public Account.AccountClient Account { get; }

    /// <summary>
    /// Administration helpers for groups and recipients.
    /// </summary>
    public Admin.AdminClient Admin { get; }

    /// <summary>
    /// Agent policy helpers riding the core <c>tn.agents</c> lifecycle.
    /// </summary>
    public Agents.AgentsClient Agents { get; }

    /// <summary>
    /// Package export and absorb helpers.
    /// </summary>
    public Packages.PackageClient Packages { get; }

    /// <summary>
    /// Local invitation inbox helpers.
    /// </summary>
    public Inbox.InboxClient Inbox { get; }

    /// <summary>
    /// Deploy-style group key rotation helpers.
    /// </summary>
    public Rotation.RotationClient Rotation { get; }

    /// <summary>
    /// Local vault link-state helpers.
    /// </summary>
    public Vault.VaultClient Vault { get; }

    /// <summary>
    /// High-level wallet status and sync helpers.
    /// </summary>
    public Wallet.WalletClient Wallet { get; }

    /// <summary>
    /// Return a safe read-only snapshot of the active TN runtime environment.
    /// </summary>
    public TnEnvironmentSnapshot EnvironmentSnapshot()
    {
        ThrowIfDisposed();
        return new TnEnvironmentSnapshot(
            Did,
            YamlPath,
            LogPath,
            ProjectName,
            ProjectDirectory);
    }

    /// <summary>
    /// Opens an existing TN project from a <c>tn.yaml</c> path.
    /// </summary>
    public static Task<Tn> InitAsync(string yamlPath, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(yamlPath))
        {
            throw new ArgumentException("YAML path must not be empty.", nameof(yamlPath));
        }

        var fullYamlPath = Path.GetFullPath(yamlPath);
        var handle = NativeBridge.Open(fullYamlPath);
        var nativeYamlPath = NativeBridge.YamlPath(handle);
        return Task.FromResult(new Tn(
            handle,
            nativeYamlPath,
            NativeBridge.LogPath(handle),
            NativeBridge.Did(handle),
            projectName: InferProjectName(nativeYamlPath),
            projectDirectory: InferProjectDirectory(nativeYamlPath)));
    }

    /// <summary>
    /// Creates or opens a TN project using the standard <c>.tn/&lt;project&gt;/tn.yaml</c> layout.
    /// </summary>
    public static Task<Tn> InitProjectAsync(
        string project,
        TnProjectOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(project))
        {
            throw new ArgumentException("Project name must not be empty.", nameof(project));
        }

        var projectDirectory = Path.GetFullPath(options?.ProjectDirectory ?? Environment.CurrentDirectory);
        var projectOptions = options ?? new TnProjectOptions();
        var profile = projectOptions.Profile.ToTnName();
        var handle = projectOptions.DevicePrivateBytes is null
            ? NativeBridge.InitProject(project, projectDirectory, profile)
            : NativeBridge.InitProject(project, projectDirectory, profile, projectOptions.DevicePrivateBytes);
        return Task.FromResult(new Tn(
            handle,
            NativeBridge.YamlPath(handle),
            NativeBridge.LogPath(handle),
            NativeBridge.Did(handle),
            project,
            projectDirectory));
    }

    /// <summary>
    /// Creates the standard project YAML path for a project directory and name.
    /// </summary>
    public static string ProjectYamlPath(string projectDirectory, string project)
    {
        if (string.IsNullOrWhiteSpace(projectDirectory))
        {
            throw new ArgumentException("Project directory must not be empty.", nameof(projectDirectory));
        }

        if (string.IsNullOrWhiteSpace(project))
        {
            throw new ArgumentException("Project name must not be empty.", nameof(project));
        }

        return Path.GetFullPath(Path.Combine(projectDirectory, ".tn", project, "tn.yaml"));
    }

    /// <summary>
    /// Emit a severity-less TN log event.
    /// </summary>
    /// <remarks>
    /// When <paramref name="aad"/> carries markers, they are merged over each
    /// group's configured default marker, bound as additional authenticated
    /// data into every sealed group body, and echoed under the public
    /// <c>tn_aad</c> envelope field. A null or empty map leaves the wire
    /// shape unchanged.
    /// </remarks>
    public Task<EmitReceipt> LogAsync<TFields>(
        string eventType,
        TFields fields,
        IReadOnlyDictionary<string, object?>? aad = null,
        CancellationToken cancellationToken = default)
    {
        return EmitAsync(level: null, eventType, fields, aad, cancellationToken);
    }

    /// <summary>
    /// Emit an info-level TN event.
    /// </summary>
    /// <remarks>
    /// See <see cref="LogAsync{TFields}"/> for the <paramref name="aad"/>
    /// marker semantics.
    /// </remarks>
    public Task<EmitReceipt> InfoAsync<TFields>(
        string eventType,
        TFields fields,
        IReadOnlyDictionary<string, object?>? aad = null,
        CancellationToken cancellationToken = default)
    {
        return EmitAsync(TnLogLevel.Info, eventType, fields, aad, cancellationToken);
    }

    /// <summary>
    /// Emit a debug-level TN event.
    /// </summary>
    /// <remarks>
    /// See <see cref="LogAsync{TFields}"/> for the <paramref name="aad"/>
    /// marker semantics.
    /// </remarks>
    public Task<EmitReceipt> DebugAsync<TFields>(
        string eventType,
        TFields fields,
        IReadOnlyDictionary<string, object?>? aad = null,
        CancellationToken cancellationToken = default)
    {
        return EmitAsync(TnLogLevel.Debug, eventType, fields, aad, cancellationToken);
    }

    /// <summary>
    /// Emit a warning-level TN event.
    /// </summary>
    /// <remarks>
    /// See <see cref="LogAsync{TFields}"/> for the <paramref name="aad"/>
    /// marker semantics.
    /// </remarks>
    public Task<EmitReceipt> WarningAsync<TFields>(
        string eventType,
        TFields fields,
        IReadOnlyDictionary<string, object?>? aad = null,
        CancellationToken cancellationToken = default)
    {
        return EmitAsync(TnLogLevel.Warning, eventType, fields, aad, cancellationToken);
    }

    /// <summary>
    /// Emit an error-level TN event.
    /// </summary>
    /// <remarks>
    /// See <see cref="LogAsync{TFields}"/> for the <paramref name="aad"/>
    /// marker semantics.
    /// </remarks>
    public Task<EmitReceipt> ErrorAsync<TFields>(
        string eventType,
        TFields fields,
        IReadOnlyDictionary<string, object?>? aad = null,
        CancellationToken cancellationToken = default)
    {
        return EmitAsync(TnLogLevel.Error, eventType, fields, aad, cancellationToken);
    }

    /// <summary>
    /// Emit a TN event at an explicit level.
    /// </summary>
    /// <remarks>
    /// See <see cref="LogAsync{TFields}"/> for the <paramref name="aad"/>
    /// marker semantics.
    /// </remarks>
    public Task<EmitReceipt> EmitAsync<TFields>(
        TnLogLevel level,
        string eventType,
        TFields fields,
        IReadOnlyDictionary<string, object?>? aad = null,
        CancellationToken cancellationToken = default)
    {
        return EmitAsync(level.ToTnName(), eventType, fields, aad, cancellationToken);
    }

    /// <summary>
    /// Read decrypted TN log entries.
    /// </summary>
    public Task<IReadOnlyList<Entry>> ReadAsync(
        ReadOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        var readOptions = options ?? new ReadOptions();
        var json = NativeBridge.Read(_handle, readOptions.AllRuns, readOptions.Verify);
        var node = JsonNode.Parse(json) as JsonArray
            ?? throw new TnException("native read returned non-array JSON");
        var entries = new List<Entry>(node.Count);

        foreach (var item in node)
        {
            if (item is not JsonObject obj)
            {
                throw new TnException("native read returned a non-object entry");
            }

            entries.Add(new Entry(obj));
        }

        return Task.FromResult<IReadOnlyList<Entry>>(entries);
    }

    /// <summary>
    /// Create a read-backed polling watcher.
    /// </summary>
    public async Task<PollingWatch> WatchAsync(
        WatchOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        var watchOptions = options ?? new WatchOptions();
        var cursor = 0;
        if (!watchOptions.FromBeginning)
        {
            var entries = await ReadAsync(watchOptions.ReadOptions, cancellationToken).ConfigureAwait(false);
            cursor = entries.Count;
        }

        return new PollingWatch(this, watchOptions, cursor);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _handle.Dispose();
        _disposed = true;
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    private Task<EmitReceipt> EmitAsync<TFields>(
        string? level,
        string eventType,
        TFields fields,
        IReadOnlyDictionary<string, object?>? aad,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(eventType))
        {
            throw new ArgumentException("Event type must not be empty.", nameof(eventType));
        }

        var fieldsJson = JsonSerializer.Serialize(fields);
        var receiptJson = aad is { Count: > 0 }
            ? NativeBridge.EmitWithAad(_handle, level, eventType, fieldsJson, JsonSerializer.Serialize(aad))
            : NativeBridge.Emit(_handle, level, eventType, fieldsJson);
        var receipt = JsonNode.Parse(receiptJson) as JsonObject
            ?? throw new TnException("native emit returned non-object JSON");
        var emitted = receipt["emitted"]?.GetValue<bool>()
            ?? throw new TnException("native emit receipt omitted emitted flag");
        var envelope = receipt["envelope"] as JsonObject;

        return Task.FromResult(new EmitReceipt(emitted, envelope));
    }

    internal TnNativeHandle NativeHandle => _handle;

    /// <summary>
    /// Close the current native runtime and open a fresh one over the same
    /// <c>tn.yaml</c>, exactly like a new <see cref="InitAsync"/> would.
    /// </summary>
    /// <remarks>
    /// Used by verbs that change on-disk ceremony inputs the core only
    /// reads at open time (for example the <c>.tn/config/agents.md</c>
    /// policy file, which the reopened runtime reloads and auto-publishes
    /// on hash change). The replacement handle is opened before the old
    /// one is disposed so a failed reopen leaves this instance usable.
    /// </remarks>
    internal void ReopenNativeHandle()
    {
        ThrowIfDisposed();

        var reopened = NativeBridge.Open(YamlPath);
        _handle.Dispose();
        _handle = reopened;
    }

    internal void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(Tn));
        }
    }

    private static string? InferProjectName(string yamlPath)
    {
        var yaml = new FileInfo(yamlPath);
        return yaml.Directory?.Name;
    }

    private static string? InferProjectDirectory(string yamlPath)
    {
        var yaml = new FileInfo(yamlPath);
        var projectDir = yaml.Directory;
        var tnDir = projectDir?.Parent;
        if (tnDir is null || !string.Equals(tnDir.Name, ".tn", StringComparison.Ordinal))
        {
            return null;
        }

        return tnDir.Parent?.FullName;
    }
}
