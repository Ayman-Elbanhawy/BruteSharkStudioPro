// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// Comprehensive HTML Forensic Report Generator for BruteShark Studio.
// Produces a dark-themed, interactive report with collapsible sections,
// sortable tables, severity badges, search/filter, copy-to-clipboard,
// and timeline reconstruction — all self-contained (no external dependencies).

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web;

namespace CommonUi
{
    public static class FullHtmlReportGenerator
    {
        /// <summary>
        /// Generate and export a full HTML forensic report to the specified directory.
        /// </summary>
        /// <param name="directory">Output directory for the HTML file.</param>
        /// <param name="context">NetworkContext with all analysis results.</param>
        /// <param name="caseName">Optional case name for the report header.</param>
        /// <returns>Full path to the generated HTML file.</returns>
        public static string ExportFullHtmlReport(string directory, NetworkContext context, string caseName = null)
        {
            var html = GenerateHtmlReport(context, caseName);
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HHmmss");
            caseName = caseName ?? "BruteShark_Full_Report";
            var safeName = string.Join("_", caseName.Split(Path.GetInvalidFileNameChars()));
            var filePath = Exporting.GetUniqueFilePath(
                Path.Combine(directory, $"{safeName}_{timestamp}.html"));
            File.WriteAllText(filePath, html);
            return filePath;
        }

        private static string GenerateHtmlReport(NetworkContext context, string caseName)
        {
            var sb = new StringBuilder();
            var generated = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss UTC");
            caseName = caseName ?? $"BruteShark Forensic Report - {DateTime.Now:yyyy-MM-dd}";

            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"en\">");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset=\"UTF-8\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            sb.AppendLine($"<title>{HtmlEncode(caseName)}</title>");
            sb.AppendLine("<style>");
            sb.AppendLine(GetStyles());
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine("<div id=\"top\">");

            // ── Header ──────────────────────────────────────────────────────────
            sb.AppendLine("<div class=\"header\">");
            sb.AppendLine($"<h1>🔍 {HtmlEncode(caseName)}</h1>");
            sb.AppendLine($"<p>Generated: {generated} | BruteShark Studio</p>");
            sb.AppendLine("</div>");

            // ── Global Search / Filter ─────────────────────────────────────────
            sb.AppendLine("<div class=\"search-bar\">");
            sb.AppendLine("<input type=\"text\" id=\"globalSearch\" onkeyup=\"filterTables()\" placeholder=\"🔎 Search across all tables…\">");
            sb.AppendLine("<span class=\"search-hint\">Type to filter, click 🔗 to copy hash values</span>");
            sb.AppendLine("</div>");

            // ── Summary Stats ────────────────────────────────────────────────────
            int passwordCount = context.Passwords?.Count ?? 0;
            int hashCount = context.Hashes?.Count ?? 0;
            int connCount = context.Connections?.Count ?? 0;
            int dnsCount = context.DnsMappings?.Count ?? 0;
            int beaconCount = context.BeaconCount;
            int ja3Count = context.Ja3Count;
            int matchCount = context.DetectionMatches?.Count ?? 0;
            int criticalHigh = context.DetectionMatches?.Count(m => m.Severity == "Critical" || m.Severity == "High") ?? 0;
            int tlsCount = context.TlsCertificates?.Count ?? 0;
            int suspiciousTls = context.TlsCertificates?.Count(c => c.IsSuspicious) ?? 0;
            int sshCount = context.SshFingerprints?.Count ?? 0;
            int dhcpCount = context.DhcpLeases?.Count ?? 0;
            int httpCount = context.HttpTransactions?.Count ?? 0;
            int alertCount = context.PayloadAlerts?.Count ?? 0;
            int fileCount = context.NetworkFiles?.Count ?? 0;
            int voipCount = context.VoipCalls?.Count ?? 0;
            int arpCount = context.PayloadAlerts?.Count(a => a.AlertType.Contains("ARP") || a.Protocol == "ARP") ?? 0;

            sb.AppendLine("<div class=\"section\" id=\"summary\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('summaryBody')\">📊 Executive Summary <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"summaryBody\" class=\"section-body\">");
            sb.AppendLine("<table class=\"summary\">");
            AddSummaryRow(sb, "Credentials (Passwords)", passwordCount);
            AddSummaryRow(sb, "Authentication Hashes", hashCount);
            AddSummaryRow(sb, "Network Connections", connCount);
            AddSummaryRow(sb, "DNS Mappings", dnsCount);
            AddSummaryRow(sb, "Files Extracted", fileCount);
            AddSummaryRow(sb, "VoIP Calls", voipCount);
            AddSummaryRow(sb, "C2 Beacon Candidates", beaconCount);
            AddSummaryRow(sb, "JA3/JA3S Fingerprints", ja3Count);
            AddSummaryRow(sb, "TLS Certificates", tlsCount);
            AddSummaryBadgeRow(sb, "Suspicious TLS Certificates", suspiciousTls, suspiciousTls > 0 ? "Critical" : "Low");
            AddSummaryRow(sb, "SSH Fingerprints", sshCount);
            AddSummaryRow(sb, "HTTP Transactions", httpCount);
            AddSummaryRow(sb, "DHCP Leases", dhcpCount);
            AddSummaryRow(sb, "Payload Alerts / Anomalies", alertCount);
            AddSummaryRow(sb, "Detection Rule Matches", matchCount);
            AddSummaryBadgeRow(sb, "Critical / High Severity Matches", criticalHigh, criticalHigh > 0 ? "Critical" : "Low");
            sb.AppendLine("</table>");
            sb.AppendLine("</div></div>");

            // ── 1. Credentials Table (Passwords) ───────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"credentials\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('credBody')\">🔐 Credentials (Passwords) <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"credBody\" class=\"section-body\">");
            if (passwordCount > 0)
            {
                sb.AppendLine("<table id=\"credTable\"><thead><tr><th onclick=\"sortTable('credTable',0)\">Protocol</th><th onclick=\"sortTable('credTable',1)\">Username</th><th onclick=\"sortTable('credTable',2)\">Password</th><th onclick=\"sortTable('credTable',3)\">Source</th><th onclick=\"sortTable('credTable',4)\">Destination</th></tr></thead><tbody>");
                foreach (var pw in context.Passwords.Take(500))
                {
                    sb.AppendLine($"<tr><td>{HtmlEncode(pw.Protocol ?? "")}</td><td>{HtmlEncode(pw.Username ?? "")}</td><td><span class=\"credential\">{HtmlEncode(pw.Password ?? "")}</span></td><td>{HtmlEncode(pw.Source ?? "")}</td><td>{HtmlEncode(pw.Destination ?? "")}</td></tr>");
                }
                if (passwordCount > 500)
                    sb.AppendLine($"<tr><td colspan=\"5\"><em>… and {passwordCount - 500} more credentials</em></td></tr>");
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No cleartext credentials extracted.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 2. Extracted Hashes with Hashcat Format ─────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"hashes\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('hashBody')\">🔑 Extracted Hashes (Hashcat Format) <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"hashBody\" class=\"section-body\">");
            if (hashCount > 0)
            {
                sb.AppendLine("<table id=\"hashTable\"><thead><tr><th onclick=\"sortTable('hashTable',0)\">Type</th><th onclick=\"sortTable('hashTable',1)\">Username</th><th onclick=\"sortTable('hashTable',2)\">Hash (truncated)</th><th>Hashcat Format</th><th onclick=\"sortTable('hashTable',4)\">Source</th><th onclick=\"sortTable('hashTable',5)\">Destination</th></tr></thead><tbody>");
                foreach (var h in context.Hashes.Take(200))
                {
                    string hashTrunc = (h.Hash?.Length > 20) ? h.Hash.Substring(0, 20) + "…" : (h.Hash ?? "");
                    string username = (h is PcapAnalyzer.IDomainCredential dc) ? dc.GetUsername() : "";
                    string hashcatFmt = BruteForce.Utilities.ConvertToHashcatFormat(CommonUi.Casting.CastAnalyzerHashToBruteForceHash(h));
                    string hashcatEsc = HtmlEncode(hashcatFmt.Length > 60 ? hashcatFmt.Substring(0, 60) + "…" : hashcatFmt);
                    sb.AppendLine($"<tr><td>{HtmlEncode(h.HashType ?? "")}</td><td>{HtmlEncode(username)}</td><td><code onclick=\"copyToClipboard(this)\" title=\"Click to copy\">{HtmlEncode(hashTrunc)}</code></td><td><code class=\"hashcat\" onclick=\"copyToClipboard(this)\" title=\"Click to copy\">{hashcatEsc}</code></td><td>{HtmlEncode(h.Source ?? "")}</td><td>{HtmlEncode(h.Destination ?? "")}</td></tr>");
                }
                if (hashCount > 200)
                    sb.AppendLine($"<tr><td colspan=\"6\"><em>… and {hashCount - 200} more hashes</em></td></tr>");
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No authentication hashes extracted.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 3. Network Connections Summary ──────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"connections\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('connBody')\">🌐 Network Connections <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"connBody\" class=\"section-body\">");
            if (connCount > 0)
            {
                sb.AppendLine("<table id=\"connTable\"><thead><tr><th onclick=\"sortTable('connTable',0)\">Source</th><th onclick=\"sortTable('connTable',1)\">Src Port</th><th onclick=\"sortTable('connTable',2)\">Destination</th><th onclick=\"sortTable('connTable',3)\">Dest Port</th><th onclick=\"sortTable('connTable',4)\">Protocol</th></tr></thead><tbody>");
                foreach (var c in context.Connections.Take(200))
                {
                    sb.AppendLine($"<tr><td>{HtmlEncode(c.Source)}</td><td>{c.SrcPort}</td><td>{HtmlEncode(c.Destination)}</td><td>{c.DestPort}</td><td>{HtmlEncode(c.Protocol ?? "TCP")}</td></tr>");
                }
                if (connCount > 200)
                    sb.AppendLine($"<tr><td colspan=\"5\"><em>… and {connCount - 200} more connections</em></td></tr>");
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No network connections recorded.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 4. C2 Beacon Detection Results ──────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"beacons\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('beaconBody')\">🛰️ C2 Beacon Detection Results <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"beaconBody\" class=\"section-body\">");
            if (beaconCount > 0)
            {
                sb.AppendLine("<table id=\"beaconTable\"><thead><tr><th onclick=\"sortTable('beaconTable',0)\">Beacon Score</th><th onclick=\"sortTable('beaconTable',1)\">Pair Key</th><th onclick=\"sortTable('beaconTable',2)\">Probable C2 Server</th><th onclick=\"sortTable('beaconTable',3)\">Mean Interval</th><th onclick=\"sortTable('beaconTable',4)\">Jitter Ratio</th><th onclick=\"sortTable('beaconTable',5)\">Period</th><th onclick=\"sortTable('beaconTable',6)\">Protocol</th></tr></thead><tbody>");
                foreach (var b in context.BeaconResults.OrderByDescending(b => b.BeaconScore))
                {
                    string badge = b.BeaconScore >= 80 ? "critical" : (b.BeaconScore >= 60 ? "high" : "medium");
                    sb.AppendLine($"<tr><td><span class=\"badge badge-{badge}\">{b.BeaconScore:F0}%</span></td><td>{HtmlEncode(b.PairKey ?? "")}</td><td>{HtmlEncode(b.ProbableC2Server ?? "")}:{b.DestinationPort}</td><td>{b.MeanIntervalSeconds:F1}s</td><td>{b.JitterRatio:P1}</td><td>{b.ObservationPeriod.TotalHours:F1}h</td><td>{HtmlEncode(b.Protocol ?? "TCP")}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No C2 beacon patterns detected.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 5. JA3 Fingerprint Results ──────────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"ja3\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('ja3Body')\">🖐️ JA3 / JA3S Fingerprints <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"ja3Body\" class=\"section-body\">");
            if (ja3Count > 0)
            {
                sb.AppendLine("<table id=\"ja3Table\"><thead><tr><th onclick=\"sortTable('ja3Table',0)\">JA3 Hash</th><th onclick=\"sortTable('ja3Table',1)\">Source IP</th><th onclick=\"sortTable('ja3Table',2)\">Destination IP</th><th onclick=\"sortTable('ja3Table',3)\">Dest Port</th><th onclick=\"sortTable('ja3Table',4)\">Known Software</th><th onclick=\"sortTable('ja3Table',5)\">Malicious</th></tr></thead><tbody>");
                foreach (var j in context.Ja3Fingerprints)
                {
                    bool isMal = !string.IsNullOrEmpty(j.KnownSoftware);
                    string rowClass = isMal ? "critical" : "";
                    string malIcon = isMal ? "🔴 Yes" : "✅ No";
                    sb.AppendLine($"<tr class=\"{rowClass}\"><td><code class=\"hash-link\" onclick=\"copyToClipboard(this)\" title=\"Click to copy\">{HtmlEncode(j.Ja3Hash ?? "")}</code></td><td>{HtmlEncode(j.SourceIp ?? "")}</td><td>{HtmlEncode(j.DestinationIp ?? "")}</td><td>{j.DestinationPort}</td><td>{(string.IsNullOrEmpty(j.KnownSoftware) ? "<span class=\"unknown\">Unknown</span>" : $"<span class=\"badge badge-critical\">{HtmlEncode(j.KnownSoftware)}</span>")}</td><td>{malIcon}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No JA3 fingerprints extracted.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 6. Detection Matches (RuleMatch) ────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"detections\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('detBody')\">🚨 Detection Rule Matches <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"detBody\" class=\"section-body\">");
            if (matchCount > 0)
            {
                sb.AppendLine("<table id=\"detTable\"><thead><tr><th onclick=\"sortTable('detTable',0)\">Severity</th><th onclick=\"sortTable('detTable',1)\">Rule Name</th><th onclick=\"sortTable('detTable',2)\">Category</th><th onclick=\"sortTable('detTable',3)\">Source IP</th><th onclick=\"sortTable('detTable',4)\">Destination IP</th><th onclick=\"sortTable('detTable',5)\">Match Details</th></tr></thead><tbody>");
                foreach (var m in context.DetectionMatches.OrderByDescending(m => m.Severity == "Critical" ? 3 : m.Severity == "High" ? 2 : m.Severity == "Medium" ? 1 : 0))
                {
                    string rowClass = m.Severity?.ToLower() ?? "low";
                    sb.AppendLine($"<tr class=\"{rowClass}\"><td><span class=\"badge badge-{rowClass}\">{HtmlEncode(m.Severity ?? "")}</span></td><td>{HtmlEncode(m.RuleName ?? "")}</td><td>{HtmlEncode(m.Category ?? "")}</td><td>{HtmlEncode(m.SourceIp ?? "-")}</td><td>{HtmlEncode(m.DestinationIp ?? "-")}</td><td>{HtmlEncode(m.MatchDetails ?? "")}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No detection rule matches triggered.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 7. TLS Certificate Findings ─────────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"tls\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('tlsBody')\">📜 TLS Certificate Findings <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"tlsBody\" class=\"section-body\">");
            if (tlsCount > 0)
            {
                sb.AppendLine("<table id=\"tlsTable\"><thead><tr><th onclick=\"sortTable('tlsTable',0)\">Subject</th><th onclick=\"sortTable('tlsTable',1)\">Issuer</th><th onclick=\"sortTable('tlsTable',2)\">Not Before</th><th onclick=\"sortTable('tlsTable',3)\">Not After</th><th>Suspicious</th><th onclick=\"sortTable('tlsTable',5)\">Fingerprint</th><th onclick=\"sortTable('tlsTable',6)\">Server IP</th></tr></thead><tbody>");
                foreach (var t in context.TlsCertificates)
                {
                    string rowClass = t.IsSuspicious ? "critical" : "";
                    string suspIcon = t.IsSuspicious ? "🔴 Yes" : "✅ No";
                    sb.AppendLine($"<tr class=\"{rowClass}\"><td>{HtmlEncode(t.Subject ?? "")}</td><td>{HtmlEncode(t.Issuer ?? "")}</td><td>{t.NotBefore:yyyy-MM-dd HH:mm}</td><td>{t.NotAfter:yyyy-MM-dd HH:mm}</td><td>{suspIcon}</td><td><code class=\"hash-link\" onclick=\"copyToClipboard(this)\" title=\"Click to copy\">{HtmlEncode(t.Fingerprint ?? "")}</code></td><td>{HtmlEncode(t.ServerIp ?? "")}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No TLS certificates extracted.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 8. DNS Mappings ─────────────────────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"dns\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('dnsBody')\">📡 DNS Mappings <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"dnsBody\" class=\"section-body\">");
            if (dnsCount > 0)
            {
                sb.AppendLine("<table id=\"dnsTable\"><thead><tr><th onclick=\"sortTable('dnsTable',0)\">Query</th><th onclick=\"sortTable('dnsTable',1)\">Resolved To</th></tr></thead><tbody>");
                foreach (var d in context.DnsMappings.Take(200))
                {
                    sb.AppendLine($"<tr><td>{HtmlEncode(d.Query ?? "")}</td><td>{HtmlEncode(d.Destination ?? "")}</td></tr>");
                }
                if (dnsCount > 200)
                    sb.AppendLine($"<tr><td colspan=\"2\"><em>… and {dnsCount - 200} more mappings</em></td></tr>");
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No DNS mappings extracted.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 9. File Extraction Summary ──────────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"files\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('fileBody')\">📁 File Extraction Summary <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"fileBody\" class=\"section-body\">");
            if (fileCount > 0)
            {
                sb.AppendLine("<table id=\"fileTable\"><thead><tr><th onclick=\"sortTable('fileTable',0)\">Filename</th><th onclick=\"sortTable('fileTable',1)\">Extension</th><th onclick=\"sortTable('fileTable',2)\">Source</th><th onclick=\"sortTable('fileTable',3)\">Destination</th><th onclick=\"sortTable('fileTable',4)\">Size (bytes)</th></tr></thead><tbody>");
                foreach (var f in context.NetworkFiles.Take(200))
                {
                    string fn = !string.IsNullOrEmpty(f.Extention) ? $"{f.Source} - {f.Destination}.{f.Extention}" : $"{f.Source} - {f.Destination}";
                    sb.AppendLine($"<tr><td>{HtmlEncode(fn)}</td><td>{HtmlEncode(f.Extention ?? "")}</td><td>{HtmlEncode(f.Source ?? "")}</td><td>{HtmlEncode(f.Destination ?? "")}</td><td>{f.FileData?.Length ?? 0}</td></tr>");
                }
                if (fileCount > 200)
                    sb.AppendLine($"<tr><td colspan=\"5\"><em>… and {fileCount - 200} more files</em></td></tr>");
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No files extracted from network streams.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 10. VoIP Calls Summary ──────────────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"voip\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('voipBody')\">📞 VoIP Calls Summary <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"voipBody\" class=\"section-body\">");
            if (voipCount > 0)
            {
                sb.AppendLine("<table id=\"voipTable\"><thead><tr><th onclick=\"sortTable('voipTable',0)\">Caller (From)</th><th onclick=\"sortTable('voipTable',1)\">Callee (To)</th><th onclick=\"sortTable('voipTable',2)\">From Host</th><th onclick=\"sortTable('voipTable',3)\">To Host</th><th>RTP Stream</th></tr></thead><tbody>");
                foreach (var v in context.VoipCalls.Take(100))
                {
                    int rtpLen = v.RTPStream?.Length ?? 0;
                    string rtpInfo = rtpLen > 0 ? $"✅ {rtpLen} bytes" : "❌ None";
                    sb.AppendLine($"<tr><td>{HtmlEncode(v.From ?? "")}</td><td>{HtmlEncode(v.To ?? "")}</td><td>{HtmlEncode(v.FromHost ?? "")}</td><td>{HtmlEncode(v.ToHost ?? "")}</td><td>{rtpInfo}</td></tr>");
                }
                if (voipCount > 100)
                    sb.AppendLine($"<tr><td colspan=\"5\"><em>… and {voipCount - 100} more calls</em></td></tr>");
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No VoIP calls detected.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 11. Anomaly Detection Alerts (PayloadAlert) ─────────────────────
            sb.AppendLine("<div class=\"section\" id=\"alerts\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('alertBody')\">⚠️ Anomaly Detection Alerts <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"alertBody\" class=\"section-body\">");
            if (alertCount > 0)
            {
                sb.AppendLine("<table id=\"alertTable\"><thead><tr><th onclick=\"sortTable('alertTable',0)\">Alert Type</th><th onclick=\"sortTable('alertTable',1)\">Severity</th><th onclick=\"sortTable('alertTable',2)\">Source IP</th><th onclick=\"sortTable('alertTable',3)\">Destination IP</th><th onclick=\"sortTable('alertTable',4)\">Protocol</th><th>Details</th></tr></thead><tbody>");
                foreach (var a in context.PayloadAlerts.OrderByDescending(a => a.Severity == "CRITICAL" ? 3 : a.Severity == "HIGH" ? 2 : a.Severity == "MEDIUM" ? 1 : 0).Take(200))
                {
                    string sev = a.Severity?.ToLower() ?? "low";
                    string rowClass = sev == "critical" ? "critical" : sev == "high" ? "high" : sev == "medium" ? "medium" : "";
                    sb.AppendLine($"<tr class=\"{rowClass}\"><td>{HtmlEncode(a.AlertType ?? "")}</td><td><span class=\"badge badge-{sev}\">{HtmlEncode(a.Severity ?? "")}</span></td><td>{HtmlEncode(a.SourceIp ?? "-")}</td><td>{HtmlEncode(a.DestinationIp ?? "-")}</td><td>{HtmlEncode(a.Protocol ?? "")}</td><td>{HtmlEncode(a.Details ?? "")}</td></tr>");
                }
                if (alertCount > 200)
                    sb.AppendLine($"<tr><td colspan=\"6\"><em>… and {alertCount - 200} more alerts</em></td></tr>");
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No anomaly detection alerts triggered.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 12. SSH Fingerprint Detections ──────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"ssh\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('sshBody')\">🔑 SSH Fingerprint Detections <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"sshBody\" class=\"section-body\">");
            if (sshCount > 0)
            {
                sb.AppendLine("<table id=\"sshTable\"><thead><tr><th onclick=\"sortTable('sshTable',0)\">Server IP</th><th onclick=\"sortTable('sshTable',1)\">Port</th><th onclick=\"sortTable('sshTable',2)\">Key Type</th><th onclick=\"sortTable('sshTable',3)\">Key Fingerprint</th><th>Banner</th></tr></thead><tbody>");
                foreach (var s in context.SshFingerprints)
                {
                    bool keyChanged = s.Banner?.Contains("KEY CHANGED") ?? false;
                    string rowClass = keyChanged ? "critical" : "";
                    sb.AppendLine($"<tr class=\"{rowClass}\"><td>{HtmlEncode(s.ServerIp ?? "")}</td><td>{s.ServerPort}</td><td>{HtmlEncode(s.KeyType ?? "")}</td><td><code class=\"hash-link\" onclick=\"copyToClipboard(this)\" title=\"Click to copy\">{HtmlEncode(s.KeyFingerprint ?? "")}</code></td><td>{HtmlEncode(s.Banner ?? "")}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No SSH fingerprints detected.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 13. SMB Session Detections ──────────────────────────────────────
            var smbAlerts = context.PayloadAlerts?.Where(a => a.AlertType != null && a.AlertType.Contains("SMB")).ToList();
            sb.AppendLine("<div class=\"section\" id=\"smb\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('smbBody')\">🖥️ SMB Session Detections <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"smbBody\" class=\"section-body\">");
            if (smbAlerts != null && smbAlerts.Count > 0)
            {
                sb.AppendLine("<table id=\"smbTable\"><thead><tr><th onclick=\"sortTable('smbTable',0)\">Alert Type</th><th onclick=\"sortTable('smbTable',1)\">Severity</th><th>Details</th></tr></thead><tbody>");
                foreach (var a in smbAlerts)
                {
                    string sev = a.Severity?.ToLower() ?? "low";
                    sb.AppendLine($"<tr><td>{HtmlEncode(a.AlertType ?? "")}</td><td><span class=\"badge badge-{sev}\">{HtmlEncode(a.Severity ?? "")}</span></td><td>{HtmlEncode(a.Details ?? "")}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No SMB session detections recorded.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 14. DHCP Activity ───────────────────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"dhcp\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('dhcpBody')\">🌐 DHCP Activity <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"dhcpBody\" class=\"section-body\">");
            if (dhcpCount > 0)
            {
                sb.AppendLine("<table id=\"dhcpTable\"><thead><tr><th onclick=\"sortTable('dhcpTable',0)\">Server IP</th><th onclick=\"sortTable('dhcpTable',1)\">Client MAC</th><th onclick=\"sortTable('dhcpTable',2)\">Assigned IP</th><th onclick=\"sortTable('dhcpTable',3)\">Hostname</th><th>Vendor Class</th><th onclick=\"sortTable('dhcpTable',5)\">Timestamp</th></tr></thead><tbody>");
                foreach (var l in context.DhcpLeases.Take(100))
                {
                    sb.AppendLine($"<tr><td>{HtmlEncode(l.ServerIp ?? "")}</td><td>{HtmlEncode(l.ClientMac ?? "")}</td><td>{HtmlEncode(l.AssignedIp ?? "")}</td><td>{HtmlEncode(l.Hostname ?? "")}</td><td>{HtmlEncode(l.VendorClass ?? "")}</td><td>{l.Timestamp:yyyy-MM-dd HH:mm:ss}</td></tr>");
                }
                if (dhcpCount > 100)
                    sb.AppendLine($"<tr><td colspan=\"6\"><em>… and {dhcpCount - 100} more leases</em></td></tr>");
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No DHCP lease activity detected.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 15. ARP Spoofing Alerts ─────────────────────────────────────────
            var arpAlerts = context.PayloadAlerts?.Where(a => a.Protocol == "ARP" || (a.AlertType != null && (a.AlertType.Contains("ARP") || a.AlertType.Contains("Duplicate MAC") || a.AlertType.Contains("IP-MAC")))).ToList();
            sb.AppendLine("<div class=\"section\" id=\"arp\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('arpBody')\">🕸️ ARP Spoofing Alerts <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"arpBody\" class=\"section-body\">");
            if (arpAlerts != null && arpAlerts.Count > 0)
            {
                sb.AppendLine("<table id=\"arpTable\"><thead><tr><th onclick=\"sortTable('arpTable',0)\">Alert Type</th><th onclick=\"sortTable('arpTable',1)\">Severity</th><th onclick=\"sortTable('arpTable',2)\">Source IP</th><th onclick=\"sortTable('arpTable',3)\">Destination IP</th><th>Details</th></tr></thead><tbody>");
                foreach (var a in arpAlerts)
                {
                    string sev = a.Severity?.ToLower() ?? "low";
                    sb.AppendLine($"<tr><td>{HtmlEncode(a.AlertType ?? "")}</td><td><span class=\"badge badge-{sev}\">{HtmlEncode(a.Severity ?? "")}</span></td><td>{HtmlEncode(a.SourceIp ?? "-")}</td><td>{HtmlEncode(a.DestinationIp ?? "-")}</td><td>{HtmlEncode(a.Details ?? "")}</td></tr>");
                }
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No ARP spoofing alerts detected.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 16. HTTP Transactions ───────────────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"http\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('httpBody')\">🌍 HTTP Transactions <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"httpBody\" class=\"section-body\">");
            if (httpCount > 0)
            {
                sb.AppendLine("<table id=\"httpTable\"><thead><tr><th onclick=\"sortTable('httpTable',0)\">Method</th><th onclick=\"sortTable('httpTable',1)\">URL</th><th onclick=\"sortTable('httpTable',2)\">Status</th><th onclick=\"sortTable('httpTable',3)\">Source</th><th onclick=\"sortTable('httpTable',4)\">Destination</th><th>User-Agent</th></tr></thead><tbody>");
                foreach (var h in context.HttpTransactions.Take(200))
                {
                    string url = h.FullUrl ?? h.Uri ?? "";
                    string status = h.StatusCode > 0 ? $"{h.StatusCode} {h.StatusMessage ?? ""}" : (h.IsRequest ? $"{h.Method} REQUEST" : "");
                    string ua = h.UserAgent ?? "";
                    if (ua.Length > 80) ua = ua.Substring(0, 80) + "…";
                    sb.AppendLine($"<tr><td>{HtmlEncode(h.Method ?? "")}</td><td>{HtmlEncode(url.Length > 120 ? url.Substring(0, 120) + "…" : url)}</td><td>{HtmlEncode(status)}</td><td>{HtmlEncode(h.SourceIp ?? "")}</td><td>{HtmlEncode(h.DestinationIp ?? "")}</td><td>{HtmlEncode(ua)}</td></tr>");
                }
                if (httpCount > 200)
                    sb.AppendLine($"<tr><td colspan=\"6\"><em>… and {httpCount - 200} more transactions</em></td></tr>");
                sb.AppendLine("</tbody></table>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No HTTP transactions extracted.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── 17. Timeline of Events ──────────────────────────────────────────
            sb.AppendLine("<div class=\"section\" id=\"timeline\">");
            sb.AppendLine("<h2 class=\"collapsible\" onclick=\"toggleSection('timelineBody')\">📅 Timeline of Events <span class=\"toggle-icon\">▼</span></h2>");
            sb.AppendLine("<div id=\"timelineBody\" class=\"section-body\">");

            var timelineItems = new List<(DateTime time, string severity, string eventType, string description)>();

            // Add detection matches
            if (context.DetectionMatches != null)
                foreach (var m in context.DetectionMatches)
                    timelineItems.Add((m.Timestamp, m.Severity ?? "Info", "Detection Match", $"[{m.RuleName}] {m.MatchDetails}"));

            // Add payload alerts
            if (context.PayloadAlerts != null)
                foreach (var a in context.PayloadAlerts)
                    timelineItems.Add((a.Timestamp, a.Severity ?? "Info", a.AlertType ?? "Alert", a.Details ?? ""));

            // Add DHCP leases
            if (context.DhcpLeases != null)
                foreach (var l in context.DhcpLeases)
                    timelineItems.Add((l.Timestamp, "Info", "DHCP Lease", $"Client {l.ClientMac} assigned {l.AssignedIp}"));

            // Add beacons
            if (context.BeaconResults != null)
                foreach (var b in context.BeaconResults)
                    timelineItems.Add((DateTime.UtcNow - b.ObservationPeriod, "High", "Beacon Detected", $"{b.PairKey} → C2: {b.ProbableC2Server} (score {b.BeaconScore:F0}%)"));

            // Sort by timestamp descending
            timelineItems = timelineItems.OrderByDescending(t => t.time).Take(500).ToList();

            if (timelineItems.Count > 0)
            {
                sb.AppendLine("<div class=\"timeline\">");
                foreach (var item in timelineItems)
                {
                    string badge = item.severity?.ToLower() switch
                    {
                        "critical" => "badge-critical",
                        "high" => "badge-high",
                        "medium" => "badge-medium",
                        _ => "badge-info"
                    };
                    sb.AppendLine($"<div class=\"timeline-item\">");
                    sb.AppendLine($"<span class=\"timeline-time\">{item.time:yyyy-MM-dd HH:mm:ss}</span>");
                    sb.AppendLine($"<span class=\"badge {badge}\">{HtmlEncode(item.severity)}</span>");
                    sb.AppendLine($"<strong>{HtmlEncode(item.eventType)}</strong>");
                    sb.AppendLine($"<span>{HtmlEncode(item.description.Length > 150 ? item.description.Substring(0, 150) + "…" : item.description)}</span>");
                    sb.AppendLine("</div>");
                }
                sb.AppendLine("</div>");
            }
            else
            {
                sb.AppendLine("<p class=\"no-data\">No timestamped events available for timeline.</p>");
            }
            sb.AppendLine("</div></div>");

            // ── Footer ─────────────────────────────────────────────────────────
            sb.AppendLine("<div class=\"footer\">");
            sb.AppendLine("<p>Generated by <strong>BruteShark Studio</strong> — Network Forensic Analysis Tool</p>");
            sb.AppendLine($"<p>© {DateTime.Now.Year} Softwaremile.com — Ayman Elbanhawy</p>");
            sb.AppendLine("</div>");

            // ── JavaScript ─────────────────────────────────────────────────────
            sb.AppendLine("<script>");
            sb.AppendLine(GetJavaScript());
            sb.AppendLine("</script>");

            sb.AppendLine("</div></body></html>");
            return sb.ToString();
        }

        private static string HtmlEncode(string text)
        {
            return string.IsNullOrEmpty(text) ? "" : System.Web.HttpUtility.HtmlEncode(text);
        }

        private static void AddSummaryRow(StringBuilder sb, string label, object value)
        {
            sb.AppendLine($"<tr><td>{HtmlEncode(label)}</td><td><strong>{value}</strong></td></tr>");
        }

        private static void AddSummaryBadgeRow(StringBuilder sb, string label, object value, string severity)
        {
            string badge = severity?.ToLower() switch
            {
                "critical" => "badge-critical",
                "high" => "badge-high",
                "medium" => "badge-medium",
                _ => "badge-info"
            };
            sb.AppendLine($"<tr><td>{HtmlEncode(label)}</td><td><span class=\"badge {badge}\">{value}</span></td></tr>");
        }

        private static string GetStyles()
        {
            return @"
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #e0e0e0; line-height: 1.6; }
#top { max-width: 1400px; margin: 0 auto; padding: 0 10px; }

/* Header */
.header { background: linear-gradient(135deg, #16213e, #0f3460); padding: 30px 20px; text-align: center; border-bottom: 3px solid #e94560; margin-bottom: 10px; border-radius: 0 0 8px 8px; }
.header h1 { color: #e94560; font-size: 28px; word-break: break-word; }
.header p { color: #a0a0a0; margin-top: 5px; font-size: 13px; }

/* Search bar */
.search-bar { background: #16213e; padding: 12px 20px; margin: 10px 0; border-radius: 8px; display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.search-bar input { flex: 1; min-width: 200px; padding: 8px 14px; border: 1px solid #0f3460; border-radius: 6px; background: #1a1a3e; color: #e0e0e0; font-size: 14px; }
.search-bar input:focus { outline: none; border-color: #e94560; }
.search-hint { color: #666; font-size: 12px; }

/* Sections */
.section { background: #16213e; border-radius: 8px; margin: 12px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.3); overflow: hidden; }
.section h2.collapsible { padding: 14px 20px; margin: 0; font-size: 17px; color: #e94560; cursor: pointer; border-bottom: 1px solid #0f3460; display: flex; justify-content: space-between; align-items: center; user-select: none; }
.section h2.collapsible:hover { background: rgba(233, 69, 96, 0.08); }
.toggle-icon { font-size: 12px; transition: transform 0.2s; color: #888; }
.section-body { padding: 15px 20px; }
.section-body.collapsed { display: none; }

/* Tables */
table { width: 100%; border-collapse: collapse; }
th { background: #0f3460; color: #fff; padding: 10px 8px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; cursor: pointer; position: sticky; top: 0; z-index: 1; }
th:hover { background: #1a1a5e; }
th::after { content: ' ↕'; font-size: 10px; color: #888; }
td { padding: 8px; border-bottom: 1px solid #1a1a3e; font-size: 13px; word-break: break-word; }
tr:hover { background: rgba(233, 69, 96, 0.1); }
tr.critical { background: rgba(233, 69, 96, 0.15); }
tr.high { background: rgba(233, 69, 96, 0.08); }
tr.medium { background: rgba(255, 193, 7, 0.08); }

/* Badges */
.badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.3px; white-space: nowrap; }
.badge-critical { background: #e94560; color: #fff; }
.badge-high { background: #ff6b35; color: #fff; }
.badge-medium { background: #ffc107; color: #000; }
.badge-low { background: #4caf50; color: #fff; }
.badge-info { background: #2196f3; color: #fff; }

/* Code / Hash links */
code { background: #0f3460; padding: 2px 8px; border-radius: 4px; font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; word-break: break-all; }
code.hash-link, code.hashcat { cursor: pointer; transition: background 0.2s; }
code.hash-link:hover, code.hashcat:hover { background: #1a1a5e; }
code.hash-link:active, code.hashcat:active { background: #e94560; }
.credential { background: #3a1a1a; color: #ff6b6b; padding: 2px 8px; border-radius: 4px; font-family: monospace; }
.unknown { color: #666; font-style: italic; }
.no-data { color: #666; font-style: italic; text-align: center; padding: 20px; }

/* Summary table */
.summary { max-width: 600px; }
.summary td:first-child { width: 300px; font-weight: 500; }
.summary td:last-child { text-align: right; font-weight: bold; color: #4fc3f7; }

/* Timeline */
.timeline { border-left: 3px solid #e94560; padding-left: 20px; }
.timeline-item { padding: 8px 12px; margin: 6px 0; border-left: 2px solid #0f3460; position: relative; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.timeline-item::before { content: ''; position: absolute; left: -10px; top: 12px; width: 12px; height: 12px; background: #e94560; border-radius: 50%; }
.timeline-time { color: #888; font-size: 12px; font-family: monospace; min-width: 150px; }

/* Footer */
.footer { text-align: center; padding: 20px; color: #555; font-size: 12px; margin-top: 20px; border-top: 1px solid #0f3460; }

/* Print */
@media print {
body { background: #fff; color: #000; }
.header { background: #eee !important; color: #000; border-bottom: 2px solid #333; }
.header h1 { color: #000; }
.section { box-shadow: none; border: 1px solid #ccc; break-inside: avoid; }
th { background: #ddd !important; color: #000; }
.search-bar { display: none; }
.badge, .badge-critical, .badge-high, .badge-medium { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
code.hash-link { cursor: default; }
.timeline-item::before { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.no-data { color: #999; }
}

/* Responsive */
@media (max-width: 768px) {
th, td { font-size: 11px; padding: 6px 4px; }
.header h1 { font-size: 20px; }
.section h2.collapsible { font-size: 15px; }
.timeline-time { min-width: 100px; }
.summary { max-width: 100%; }
.search-bar { flex-direction: column; }
}
";
        }

        private static string GetJavaScript()
        {
            return @"
function toggleSection(id) {
    var el = document.getElementById(id);
    if (el) {
        el.classList.toggle('collapsed');
        var icon = el.parentElement.querySelector('.toggle-icon');
        if (icon) {
            icon.textContent = el.classList.contains('collapsed') ? '▶' : '▼';
        }
    }
    return false;
}

function filterTables() {
    var input = document.getElementById('globalSearch');
    var filter = input ? input.value.toLowerCase() : '';
    var tables = document.querySelectorAll('table');
    tables.forEach(function(table) {
        var rows = table.querySelectorAll('tbody tr');
        rows.forEach(function(row) {
            var text = row.textContent.toLowerCase();
            row.style.display = text.indexOf(filter) > -1 ? '' : 'none';
        });
    });
}

function sortTable(tableId, col) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var tbody = table.querySelector('tbody');
    if (!tbody) return;
    var rows = Array.from(tbody.querySelectorAll('tr')).filter(function(r) { return r.style.display !== 'none'; });
    var dir = table.getAttribute('data-sort-dir') || 'asc';
    dir = (dir === 'asc') ? 'desc' : 'asc';
    table.setAttribute('data-sort-dir', dir);
    
    rows.sort(function(a, b) {
        var cellA = a.cells[col] ? a.cells[col].textContent.trim() : '';
        var cellB = b.cells[col] ? b.cells[col].textContent.trim() : '';
        var numA = parseFloat(cellA.replace(/[^0-9.\-]/g,''));
        var numB = parseFloat(cellB.replace(/[^0-9.\-]/g,''));
        if (!isNaN(numA) && !isNaN(numB)) {
            return dir === 'asc' ? numA - numB : numB - numA;
        }
        return dir === 'asc' ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
    });
    
    rows.forEach(function(row) { tbody.appendChild(row); });
}

function copyToClipboard(el) {
    var text = el.textContent.trim();
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function() {
            var orig = el.innerHTML;
            el.innerHTML = '✅ Copied!';
            setTimeout(function() { el.innerHTML = orig; }, 1200);
        }).catch(function() {
            fallbackCopy(text, el);
        });
    } else {
        fallbackCopy(text, el);
    }
}

function fallbackCopy(text, el) {
    var ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    var orig = el.innerHTML;
    el.innerHTML = '✅ Copied!';
    setTimeout(function() { el.innerHTML = orig; }, 1200);
}
";
        }
    }
}
