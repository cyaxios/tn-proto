using System.Text.Json.Nodes;
using TnProto.Native;

namespace TnProto.Agents;

/// <summary>
/// Agent policy helpers riding the core <c>tn.agents</c> lifecycle.
/// </summary>
/// <remarks>
/// The splice of policy text into emitted events and the
/// <c>tn.agents.policy_published</c> event both run inside the core
/// runtime. This client adds the authoring side: writing the
/// <c>.tn/config/agents.md</c> document and reading back what the core
/// loaded.
/// </remarks>
public sealed class AgentsClient
{
    private readonly Tn _tn;

    internal AgentsClient(Tn tn)
    {
        _tn = tn;
    }

    /// <summary>
    /// The agent policy document loaded by the active runtime, or null when
    /// the ceremony has no <c>.tn/config/agents.md</c>.
    /// </summary>
    public AgentsPolicyDocument? Current
    {
        get
        {
            _tn.ThrowIfDisposed();

            var json = NativeBridge.AgentPolicyDoc(_tn.NativeHandle);
            var node = JsonNode.Parse(json);
            if (node is null)
            {
                return null;
            }

            var doc = node as JsonObject
                ?? throw new TnException("native agent policy doc returned non-object JSON");
            return ParseDocument(doc);
        }
    }

    /// <summary>
    /// Write <paramref name="markdown"/> to the ceremony's
    /// <c>.tn/config/agents.md</c> and reload the runtime so the policy
    /// goes live.
    /// </summary>
    /// <remarks>
    /// The reloaded core re-parses the document, splices its templates
    /// into subsequent emits, and auto-emits
    /// <c>tn.agents.policy_published</c> on the admin surface when the
    /// content hash changed. Publish is all-or-nothing: when the core
    /// rejects the document (for example a section missing one of the five
    /// required subsections), the prior file state is restored and the
    /// running handle stays on the previous policy.
    /// </remarks>
    /// <returns>The policy document the core loaded.</returns>
    public async Task<AgentsPolicyDocument> PublishAsync(
        string markdown,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        if (string.IsNullOrWhiteSpace(markdown))
        {
            throw new ArgumentException("Policy markdown must not be empty.", nameof(markdown));
        }

        var policyPath = PolicyPath();
        Directory.CreateDirectory(Path.GetDirectoryName(policyPath)!);
        var previous = File.Exists(policyPath)
            ? await File.ReadAllTextAsync(policyPath, cancellationToken).ConfigureAwait(false)
            : null;

        await File.WriteAllTextAsync(policyPath, markdown, cancellationToken).ConfigureAwait(false);
        try
        {
            _tn.ReopenNativeHandle();
        }
        catch
        {
            // A document the core cannot load must not wedge future opens
            // of the ceremony; put the file back the way it was.
            if (previous is null)
            {
                File.Delete(policyPath);
            }
            else
            {
                await File.WriteAllTextAsync(policyPath, previous, CancellationToken.None).ConfigureAwait(false);
            }

            throw;
        }

        return Current
            ?? throw new TnException("agents policy publish did not load a policy document");
    }

    /// <summary>
    /// Absolute path of the ceremony's agent policy file
    /// (<c>&lt;yaml dir&gt;/.tn/config/agents.md</c>).
    /// </summary>
    private string PolicyPath()
    {
        var yamlDir = Path.GetDirectoryName(_tn.YamlPath)
            ?? throw new TnException("active tn.yaml path has no parent directory");
        return Path.Combine(yamlDir, ".tn", "config", "agents.md");
    }

    private static AgentsPolicyDocument ParseDocument(JsonObject doc)
    {
        var templatesNode = doc["templates"] as JsonObject
            ?? throw new TnException("native agent policy doc omitted templates");
        var templates = new Dictionary<string, AgentsPolicyTemplate>(StringComparer.Ordinal);

        foreach (var (eventType, node) in templatesNode)
        {
            var template = node as JsonObject
                ?? throw new TnException("native agent policy template is not an object");
            templates.Add(eventType, new AgentsPolicyTemplate(
                RequireString(template, "event_type"),
                RequireString(template, "instruction"),
                RequireString(template, "use_for"),
                RequireString(template, "do_not_use_for"),
                RequireString(template, "consequences"),
                RequireString(template, "on_violation_or_error"),
                RequireString(template, "content_hash"),
                RequireString(template, "version"),
                RequireString(template, "path")));
        }

        return new AgentsPolicyDocument(
            RequireString(doc, "version"),
            RequireString(doc, "schema"),
            RequireString(doc, "path"),
            RequireString(doc, "body"),
            RequireString(doc, "content_hash"),
            templates);
    }

    private static string RequireString(JsonObject obj, string key)
    {
        return obj[key]?.GetValue<string>()
            ?? throw new TnException($"native agent policy doc omitted {key}");
    }
}
