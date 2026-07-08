namespace TnProto.Validation;

/// <summary>
/// Static project/YAML validation helpers.
/// </summary>
public static class TnValidator
{
    /// <summary>
    /// Validate the TN project directory rooted at <paramref name="projectDirectory" />.
    /// </summary>
    public static async Task<ValidationResult> ValidateProjectAsync(
        string? projectDirectory = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var fullProjectDirectory = Path.GetFullPath(projectDirectory ?? Environment.CurrentDirectory);
        var tnRoot = Path.Combine(fullProjectDirectory, ".tn");
        var issues = new List<ValidationIssue>();

        if (!Directory.Exists(tnRoot))
        {
            return new ValidationResult(fullProjectDirectory, tnRoot, [], issues);
        }

        var ceremonies = Directory
            .EnumerateDirectories(tnRoot)
            .Where(directory => File.Exists(Path.Combine(directory, "tn.yaml")))
            .Select(Path.GetFileName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Cast<string>()
            .Order(StringComparer.Ordinal)
            .ToArray();

        if (ceremonies.Length > 0 && !ceremonies.Contains("default", StringComparer.Ordinal))
        {
            issues.Add(new ValidationIssue(
                ValidationIssueSeverity.Warning,
                "no 'default' ceremony at .tn/default/. Named streams normally extend from it.",
                tnRoot));
        }

        foreach (var ceremony in ceremonies)
        {
            var yamlPath = Path.Combine(tnRoot, ceremony, "tn.yaml");
            var parsed = await ParsedYaml.ReadAsync(yamlPath, cancellationToken).ConfigureAwait(false);
            ValidateOne(parsed, yamlPath, issues);
        }

        return new ValidationResult(fullProjectDirectory, tnRoot, ceremonies, issues);
    }

    private static void ValidateOne(ParsedYaml doc, string yamlPath, List<ValidationIssue> issues)
    {
        if (doc.ParseError is not null)
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, $"{yamlPath}: read/parse failed: {doc.ParseError}", yamlPath));
            return;
        }

        var isStream = doc.TopLevel.Contains("extends");
        var requiredTop = isStream
            ? ["ceremony"]
            : new[] { "ceremony", "logs", "keystore", "device", "groups" };

        if (!isStream && doc.TopLevel.Contains("me") && !doc.TopLevel.Contains("device"))
        {
            issues.Add(new ValidationIssue(
                ValidationIssueSeverity.Error,
                $"{yamlPath}: legacy `me:` top-level block is no longer supported; use `device:`.",
                yamlPath));
        }

        foreach (var key in requiredTop)
        {
            if (!doc.TopLevel.Contains(key))
            {
                issues.Add(new ValidationIssue(
                    ValidationIssueSeverity.Error,
                    $"{yamlPath}: missing required top-level key '{key}'.",
                    yamlPath));
            }
        }

        ValidateSubkeys(doc, yamlPath, isStream, issues);
        ValidateProfile(doc, yamlPath, issues);
        ValidateGroupKits(doc, yamlPath, issues);
        ValidateDidConsistency(doc, yamlPath, issues);
    }

    private static void ValidateSubkeys(ParsedYaml doc, string yamlPath, bool isStream, List<ValidationIssue> issues)
    {
        if (doc.TopLevel.Contains("ceremony") && !doc.HasNestedKey("ceremony", "id"))
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, $"{yamlPath}: ceremony.id is required", yamlPath));
        }

        if (isStream)
        {
            return;
        }

        if (doc.TopLevel.Contains("logs") && !doc.HasNestedKey("logs", "path"))
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, $"{yamlPath}: logs.path is required", yamlPath));
        }

        if (doc.TopLevel.Contains("keystore") && !doc.HasNestedKey("keystore", "path"))
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, $"{yamlPath}: keystore.path is required", yamlPath));
        }

        if (doc.TopLevel.Contains("device") && !doc.HasNestedKey("device", "device_identity"))
        {
            issues.Add(new ValidationIssue(ValidationIssueSeverity.Error, $"{yamlPath}: device.device_identity is required", yamlPath));
        }
    }

    private static void ValidateProfile(ParsedYaml doc, string yamlPath, List<ValidationIssue> issues)
    {
        var profile = doc.GetNestedValue("ceremony", "profile");
        if (!string.IsNullOrWhiteSpace(profile) && !TnProfiles.IsKnown(profile))
        {
            issues.Add(new ValidationIssue(
                ValidationIssueSeverity.Error,
                $"{yamlPath}: unknown profile {profile}; catalog: {string.Join(", ", TnProfiles.AllNames())}",
                yamlPath));
        }
    }

    private static void ValidateGroupKits(ParsedYaml doc, string yamlPath, List<ValidationIssue> issues)
    {
        if (!doc.TopLevel.Contains("groups"))
        {
            return;
        }

        var keystorePath = doc.GetNestedValue("keystore", "path");
        if (string.IsNullOrWhiteSpace(keystorePath))
        {
            return;
        }

        var yamlDirectory = Path.GetDirectoryName(Path.GetFullPath(yamlPath)) ?? Environment.CurrentDirectory;
        var keystoreDirectory = Path.IsPathFullyQualified(keystorePath)
            ? keystorePath
            : Path.GetFullPath(Path.Combine(yamlDirectory, keystorePath));
        var ceremonyCipher = doc.GetNestedValue("ceremony", "cipher") ?? "btn";

        foreach (var group in doc.GroupNames)
        {
            var groupCipher = doc.GetGroupValue(group, "cipher") ?? ceremonyCipher;
            if (!string.Equals(groupCipher, "btn", StringComparison.Ordinal))
            {
                continue;
            }

            var kitPath = Path.Combine(keystoreDirectory, $"{group}.btn.mykit");
            if (!File.Exists(kitPath))
            {
                issues.Add(new ValidationIssue(
                    ValidationIssueSeverity.Error,
                    $"{yamlPath}: group '{group}' kit missing: {kitPath}.",
                    yamlPath));
            }
            else if (new FileInfo(kitPath).Length == 0)
            {
                issues.Add(new ValidationIssue(
                    ValidationIssueSeverity.Error,
                    $"{yamlPath}: group '{group}' kit is empty: {kitPath}.",
                    yamlPath));
            }
        }
    }

    private static void ValidateDidConsistency(ParsedYaml doc, string yamlPath, List<ValidationIssue> issues)
    {
        var yamlDid = doc.GetNestedValue("device", "device_identity");
        if (string.IsNullOrWhiteSpace(yamlDid))
        {
            return;
        }

        var yamlDirectory = Path.GetDirectoryName(Path.GetFullPath(yamlPath)) ?? Environment.CurrentDirectory;
        var rawKeystorePath = doc.GetNestedValue("keystore", "path") ?? "./keys";
        var keystoreDirectory = Path.IsPathFullyQualified(rawKeystorePath)
            ? rawKeystorePath
            : Path.GetFullPath(Path.Combine(yamlDirectory, rawKeystorePath));
        var localPublicPath = Path.Combine(keystoreDirectory, "local.public");

        if (!File.Exists(localPublicPath))
        {
            return;
        }

        string derivedDid;
        try
        {
            derivedDid = File.ReadAllText(localPublicPath).Trim();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            issues.Add(new ValidationIssue(
                ValidationIssueSeverity.Error,
                $"{yamlPath}: could not read keystore {localPublicPath}: {ex.Message}",
                yamlPath));
            return;
        }

        if (!string.IsNullOrWhiteSpace(derivedDid) && !string.Equals(yamlDid, derivedDid, StringComparison.Ordinal))
        {
            issues.Add(new ValidationIssue(
                ValidationIssueSeverity.Error,
                $"{yamlPath}: yaml device.device_identity does not match keys/local.public.",
                yamlPath));
        }
    }

    private sealed class ParsedYaml
    {
        private readonly Dictionary<string, Dictionary<string, string>> _nested = new(StringComparer.Ordinal);
        private readonly Dictionary<string, Dictionary<string, string>> _groups = new(StringComparer.Ordinal);

        private ParsedYaml()
        {
        }

        public HashSet<string> TopLevel { get; } = new(StringComparer.Ordinal);

        public IReadOnlyList<string> GroupNames => _groups.Keys.Order(StringComparer.Ordinal).ToArray();

        public string? ParseError { get; private init; }

        public bool HasNestedKey(string section, string key)
        {
            return _nested.TryGetValue(section, out var sectionValues) && sectionValues.ContainsKey(key);
        }

        public string? GetNestedValue(string section, string key)
        {
            return _nested.TryGetValue(section, out var sectionValues) &&
                sectionValues.TryGetValue(key, out var value)
                    ? value
                    : null;
        }

        public string? GetGroupValue(string group, string key)
        {
            return _groups.TryGetValue(group, out var groupValues) &&
                groupValues.TryGetValue(key, out var value)
                    ? value
                    : null;
        }

        public static async Task<ParsedYaml> ReadAsync(string yamlPath, CancellationToken cancellationToken)
        {
            try
            {
                var lines = await File.ReadAllLinesAsync(yamlPath, cancellationToken).ConfigureAwait(false);
                return Parse(lines);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return new ParsedYaml { ParseError = ex.Message };
            }
        }

        private static ParsedYaml Parse(IEnumerable<string> lines)
        {
            var parsed = new ParsedYaml();
            string? currentTop = null;
            string? currentGroup = null;

            foreach (var rawLine in lines)
            {
                var withoutComment = StripComment(rawLine);
                if (string.IsNullOrWhiteSpace(withoutComment))
                {
                    continue;
                }

                var indent = withoutComment.TakeWhile(char.IsWhiteSpace).Count();
                var trimmed = withoutComment.Trim();
                var separator = trimmed.IndexOf(':');
                if (separator <= 0)
                {
                    continue;
                }

                var key = Unquote(trimmed[..separator].Trim());
                var rawValue = trimmed[(separator + 1)..].Trim();
                if ((rawValue.StartsWith("[", StringComparison.Ordinal) && !rawValue.EndsWith("]", StringComparison.Ordinal)) ||
                    (rawValue.StartsWith("{", StringComparison.Ordinal) && !rawValue.EndsWith("}", StringComparison.Ordinal)))
                {
                    return new ParsedYaml { ParseError = $"malformed inline value for '{key}'" };
                }

                var value = CleanValue(rawValue);

                if (indent == 0)
                {
                    currentTop = key;
                    currentGroup = null;
                    parsed.TopLevel.Add(key);
                    if (!parsed._nested.ContainsKey(key))
                    {
                        parsed._nested[key] = new Dictionary<string, string>(StringComparer.Ordinal);
                    }

                    continue;
                }

                if (indent == 2 && currentTop is not null)
                {
                    parsed._nested[currentTop][key] = value;
                    if (currentTop == "groups")
                    {
                        currentGroup = key;
                        if (!parsed._groups.ContainsKey(currentGroup))
                        {
                            parsed._groups[currentGroup] = new Dictionary<string, string>(StringComparer.Ordinal);
                        }
                    }
                    else
                    {
                        currentGroup = null;
                    }
                    continue;
                }

                if (indent == 4 && currentTop == "groups" && currentGroup is not null)
                {
                    parsed._groups[currentGroup][key] = value;
                }
            }

            return parsed;
        }

        private static string StripComment(string line)
        {
            var quote = false;
            for (var i = 0; i < line.Length; i++)
            {
                if (line[i] == '"')
                {
                    quote = !quote;
                }
                else if (!quote && line[i] == '#')
                {
                    return line[..i];
                }
            }

            return line;
        }

        private static string CleanValue(string value)
        {
            return Unquote(value.Trim());
        }

        private static string Unquote(string value)
        {
            if (value.Length >= 2 && value[0] == '"' && value[^1] == '"')
            {
                return value[1..^1];
            }

            return value;
        }
    }
}
