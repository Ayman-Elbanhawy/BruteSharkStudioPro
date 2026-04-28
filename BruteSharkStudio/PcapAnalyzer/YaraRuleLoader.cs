// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// YARA Rule Loader & Compiler for BruteShark Studio.
// Loads YARA rules from .yar/.yara files and compiles them into
// the DetectionRuleEngine for realtime network traffic matching.
//
// YARA rule format reference: https://yara.readthedocs.io/
// This implements a subset of YARA syntax usable for network payload matching:
//   - rule <name> { strings: $a = "pattern" condition: $a }
//   - Hex strings: $a = { FF D8 FF E0 }
//   - Regex (limited): $a = /pattern/

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace PcapAnalyzer
{
    /// <summary>
    /// Parsed YARA rule suitable for network traffic matching.
    /// </summary>
    public class YaraRule
    {
        public string RuleName { get; set; }
        public string Description { get; set; }
        public string Category { get; set; }
        public string Severity { get; set; }
        public string MitreTechnique { get; set; }
        public List<string> StringPatterns { get; set; } = new List<string>();
        public List<string> HexPatterns { get; set; } = new List<string>();
        public List<string> RegexPatterns { get; set; } = new List<string>();
        public string RawCondition { get; set; }

        public override string ToString() => $"YARA: {RuleName} ({StringPatterns.Count} str, {HexPatterns.Count} hex)";
    }

    /// <summary>
    /// Loads and parses YARA rule files (.yar) into DetectionRuleEngine rules.
    /// Supports the core YARA syntax: rule blocks, strings section, condition section,
    /// meta section, and common string modifiers (nocase, wide, ascii).
    /// </summary>
    public class YaraRuleLoader
    {
        // Regex patterns for parsing YARA syntax
        private static readonly Regex RuleHeaderRegex = new Regex(
            @"^\s*rule\s+(\w+)\s*(?::\s*(\w+))?\s*\{",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex MetaFieldRegex = new Regex(
            @"^\s*(\w+)\s*=\s*""([^""]*)""",
            RegexOptions.Compiled);

        private static readonly Regex StringIdRegex = new Regex(
            @"^\s*\$(\w+)\s*=\s*(?:/([^/]+)/|""([^""]*)""|\{\s*([^}]+)\s*\})",
            RegexOptions.Compiled);

        private static readonly Regex ConditionRegex = new Regex(
            @"^\s*condition\s*:",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex SectionStartRegex = new Regex(
            @"^\s*(strings|meta|condition)\s*:",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>
        /// Load YARA rules from a .yar file and return parsed rules.
        /// </summary>
        public List<YaraRule> LoadFromFile(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"YARA rule file not found: {filePath}");

            string content = File.ReadAllText(filePath);
            return ParseRules(content);
        }

        /// <summary>
        /// Load YARA rules from a directory of .yar files.
        /// </summary>
        public List<YaraRule> LoadFromDirectory(string directoryPath)
        {
            var rules = new List<YaraRule>();
            if (!Directory.Exists(directoryPath)) return rules;

            foreach (var file in Directory.GetFiles(directoryPath, "*.yar", SearchOption.AllDirectories))
            {
                try
                {
                    rules.AddRange(LoadFromFile(file));
                }
                catch { /* skip malformed files */ }
            }
            foreach (var file in Directory.GetFiles(directoryPath, "*.yara", SearchOption.AllDirectories))
            {
                try
                {
                    rules.AddRange(LoadFromFile(file));
                }
                catch { }
            }

            return rules;
        }

        /// <summary>
        /// Convert parsed YARA rules into DetectionRuleEngine NetworkDetectionRules.
        /// </summary>
        public List<NetworkDetectionRule> ToDetectionRules(List<YaraRule> yaraRules)
        {
            var rules = new List<NetworkDetectionRule>();

            foreach (var yr in yaraRules)
            {
                var rule = new NetworkDetectionRule
                {
                    Name = yr.RuleName,
                    Description = yr.Description ?? $"YARA rule: {yr.RuleName}",
                    Category = yr.Category ?? "YARA",
                    Severity = yr.Severity ?? "Medium",
                    MitreTechnique = yr.MitreTechnique,
                    PayloadStringPatterns = yr.StringPatterns,
                    PayloadHexPatterns = yr.HexPatterns,
                    PayloadMatchAll = false // OR logic: any single pattern match = rule match
                };

                // Apply severity from meta
                if (string.IsNullOrEmpty(yr.Severity))
                    rule.Severity = InferSeverity(yr.RuleName);

                rules.Add(rule);
            }

            return rules;
        }

        /// <summary>
        /// Load YARA rules and register them directly with the detection engine.
        /// </summary>
        public int LoadAndRegister(string directoryPath, DetectionRuleEngine engine)
        {
            var yaraRules = LoadFromDirectory(directoryPath);
            var detectionRules = ToDetectionRules(yaraRules);

            foreach (var rule in detectionRules)
                engine.AddRule(rule);

            return detectionRules.Count;
        }

        private List<YaraRule> ParseRules(string content)
        {
            var rules = new List<YaraRule>();
            var lines = content.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            YaraRule currentRule = null;
            string currentSection = null;
            string multiLineHexBuffer = null;

            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];

                // Skip comments and empty lines
                string trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("//") || trimmed.StartsWith("#"))
                    continue;

                // Skip block comments
                if (trimmed.StartsWith("/*"))
                {
                    while (i < lines.Length && !lines[i].Trim().EndsWith("*/")) i++;
                    continue;
                }

                // Rule header: "rule Name : Tag {"
                var ruleMatch = RuleHeaderRegex.Match(trimmed);
                if (ruleMatch.Success)
                {
                    currentRule = new YaraRule
                    {
                        RuleName = ruleMatch.Groups[1].Value,
                        Category = ruleMatch.Groups[2].Success ? ruleMatch.Groups[2].Value : null
                    };
                    currentSection = null;
                    multiLineHexBuffer = null;
                    continue;
                }

                // End of rule block
                if (trimmed == "}" && currentRule != null)
                {
                    rules.Add(currentRule);
                    currentRule = null;
                    currentSection = null;
                    continue;
                }

                if (currentRule == null) continue;

                // Section headers
                var sectionMatch = SectionStartRegex.Match(trimmed);
                if (sectionMatch.Success)
                {
                    currentSection = sectionMatch.Groups[1].Value.ToLowerInvariant();
                    continue;
                }

                // Process based on current section
                switch (currentSection)
                {
                    case "meta":
                        var metaMatch = MetaFieldRegex.Match(trimmed);
                        if (metaMatch.Success)
                        {
                            string key = metaMatch.Groups[1].Value.ToLowerInvariant();
                            string value = metaMatch.Groups[2].Value;
                            ApplyMetaField(currentRule, key, value);
                        }
                        break;

                    case "strings":
                        // Handle multi-line hex patterns
                        if (trimmed.Contains("{") && !trimmed.Contains("}"))
                        {
                            multiLineHexBuffer = trimmed;
                            continue;
                        }
                        if (multiLineHexBuffer != null)
                        {
                            multiLineHexBuffer += " " + trimmed;
                            if (trimmed.Contains("}"))
                            {
                                ParseStringEntry(currentRule, multiLineHexBuffer);
                                multiLineHexBuffer = null;
                            }
                            continue;
                        }

                        ParseStringEntry(currentRule, trimmed);
                        break;

                    case "condition":
                        if (currentRule.RawCondition == null)
                            currentRule.RawCondition = trimmed;
                        else
                            currentRule.RawCondition += " " + trimmed;
                        break;
                }
            }

            return rules;
        }

        private void ParseStringEntry(YaraRule rule, string line)
        {
            var match = StringIdRegex.Match(line);
            if (!match.Success) return;

            if (match.Groups[2].Success)
            {
                // Regex pattern: /pattern/
                rule.RegexPatterns.Add(match.Groups[2].Value);
            }
            else if (match.Groups[3].Success)
            {
                // Quoted string pattern: "pattern"
                string pattern = match.Groups[3].Value;

                // Handle modifiers (nocase, wide, ascii)
                string restOfLine = line.Substring(match.Index + match.Length).Trim();
                if (restOfLine.Contains("nocase"))
                    rule.RegexPatterns.Add($"(?i){Regex.Escape(pattern)}");
                else
                    rule.StringPatterns.Add(pattern);

                // Wide modifier: add UTF-16 version
                if (restOfLine.Contains("wide"))
                {
                    var wideBytes = System.Text.Encoding.Unicode.GetBytes(pattern);
                    string wideHex = string.Join("", Array.ConvertAll(wideBytes, b => b.ToString("X2")));
                    rule.HexPatterns.Add(wideHex);
                }
            }
            else if (match.Groups[4].Success)
            {
                // Hex pattern: { FF D8 FF }
                string hexStr = match.Groups[4].Value.Trim();
                // Clean up hex string: remove spaces and wildcards
                hexStr = Regex.Replace(hexStr, @"[\s\[\]\(\)\?]", "");
                if (hexStr.Length >= 2 && hexStr.Length % 2 == 0)
                    rule.HexPatterns.Add(hexStr);
            }
        }

        private void ApplyMetaField(YaraRule rule, string key, string value)
        {
            switch (key)
            {
                case "description":
                case "desc":
                    rule.Description = value;
                    break;
                case "category":
                case "cat":
                    rule.Category = value;
                    break;
                case "severity":
                case "sev":
                case "priority":
                    rule.Severity = value.ToUpperInvariant();
                    break;
                case "mitre":
                case "mitre_technique":
                case "attack_id":
                    rule.MitreTechnique = value;
                    break;
                case "author":
                case "reference":
                case "date":
                    // Store these in description if not set
                    if (string.IsNullOrEmpty(rule.Description))
                        rule.Description = $"{key}: {value}";
                    break;
            }
        }

        private string InferSeverity(string ruleName)
        {
            string name = ruleName.ToUpperInvariant();
            if (name.Contains("MALWARE") || name.Contains("RANSOMWARE") || name.Contains("EXPLOIT"))
                return "Critical";
            if (name.Contains("C2") || name.Contains("BACKDOOR") || name.Contains("TROJAN"))
                return "High";
            if (name.Contains("SUSPICIOUS") || name.Contains("ANOMALY") || name.Contains("EXFIL"))
                return "Medium";
            if (name.Contains("INFO") || name.Contains("POLICY"))
                return "Low";
            return "Medium";
        }
    }
}
