using TnProto.Packages;

namespace TnProto.Rotation;

/// <summary>
/// Deploy-style group key rotation helpers.
/// </summary>
public sealed class RotationClient
{
    private readonly Tn _tn;

    internal RotationClient(Tn tn)
    {
        _tn = tn;
    }

    /// <summary>
    /// Rotate one or more groups and emit replacement kit bundles for surviving recipients.
    /// </summary>
    public async Task<RotateResult> RotateAsync(
        RotateOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _tn.ThrowIfDisposed();

        var rotateOptions = options ?? new RotateOptions();
        var groups = NormalizeGroups(rotateOptions.Groups);
        var recipientGroups = await SnapshotRecipientGroupsAsync(groups, cancellationToken).ConfigureAwait(false);
        var rotated = new List<RotatedGroup>(groups.Count);

        foreach (var group in groups)
        {
            var result = await _tn.Admin.RotateAsync(group, cancellationToken).ConfigureAwait(false);
            rotated.Add(new RotatedGroup(result.Group, result.Generation));
        }

        if (recipientGroups.Count == 0)
        {
            return new RotateResult(rotated, [], null);
        }

        var (outDirectory, singleFile) = ResolveOutput(rotateOptions.OutPath, recipientGroups.Count);
        Directory.CreateDirectory(outDirectory);

        var artifacts = new List<RotationArtifact>(recipientGroups.Count);
        foreach (var (recipientDid, recipientGroupsForDid) in recipientGroups)
        {
            var path = singleFile ?? Path.Combine(outDirectory, SafeFileName(recipientDid) + ".tnpkg");
            var bundle = await _tn.Packages.BundleForRecipientAsync(
                recipientDid,
                path,
                new BundleForRecipientOptions
                {
                    Groups = recipientGroupsForDid,
                    SealForRecipient = rotateOptions.SealForRecipient,
                },
                cancellationToken).ConfigureAwait(false);
            artifacts.Add(new RotationArtifact(bundle.Path, bundle.RecipientDid, bundle.Groups));
        }

        return new RotateResult(rotated, artifacts, outDirectory);
    }

    private async Task<SortedDictionary<string, List<string>>> SnapshotRecipientGroupsAsync(
        IReadOnlyList<string> groups,
        CancellationToken cancellationToken)
    {
        var recipientGroups = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var group in groups)
        {
            var recipients = await _tn.Admin.RecipientsAsync(group, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            foreach (var recipient in recipients)
            {
                if (recipient.Revoked || string.IsNullOrWhiteSpace(recipient.RecipientIdentity))
                {
                    continue;
                }

                if (!recipientGroups.TryGetValue(recipient.RecipientIdentity, out var list))
                {
                    list = [];
                    recipientGroups.Add(recipient.RecipientIdentity, list);
                }

                list.Add(group);
            }
        }

        return recipientGroups;
    }

    private static IReadOnlyList<string> NormalizeGroups(IReadOnlyList<string>? groups)
    {
        var selected = groups is null or { Count: 0 } ? ["default"] : groups;
        return selected.Select(group =>
        {
            if (string.IsNullOrWhiteSpace(group))
            {
                throw new ArgumentException("Groups must not contain empty values.", nameof(groups));
            }

            return group;
        }).Distinct(StringComparer.Ordinal).ToArray();
    }

    private static (string OutDirectory, string? SingleFile) ResolveOutput(string? outPath, int recipientCount)
    {
        if (string.IsNullOrWhiteSpace(outPath))
        {
            return (Path.GetFullPath("rotated_" + DateTimeOffset.UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'")), null);
        }

        var fullPath = Path.GetFullPath(outPath);
        if (string.Equals(Path.GetExtension(fullPath), ".tnpkg", StringComparison.OrdinalIgnoreCase))
        {
            if (recipientCount > 1)
            {
                throw new ArgumentException(
                    $"--out {Path.GetFileName(fullPath)} is a single .tnpkg path but this rotation has {recipientCount} surviving recipients.");
            }

            return (Path.GetDirectoryName(fullPath) ?? Environment.CurrentDirectory, fullPath);
        }

        return (fullPath, null);
    }

    private static string SafeFileName(string value)
    {
        var chars = value.Select(ch =>
            char.IsAsciiLetterOrDigit(ch) || ch is '.' or '_' or '-' ? ch : '_').ToArray();
        return new string(chars);
    }
}
