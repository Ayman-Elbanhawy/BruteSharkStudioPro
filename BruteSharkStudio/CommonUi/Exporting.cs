using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace CommonUi
{
    public static class Exporting
    {
        public static string GetUniqueFilePath(string filePath)
        {
            string dir = Path.GetDirectoryName(filePath);
            string fileName = Path.GetFileNameWithoutExtension(filePath);
            string fileExt = Path.GetExtension(filePath);

            for (int i = 1; ; ++i)
            {
                if (!File.Exists(filePath))
                    return new FileInfo(filePath).FullName;

                filePath = Path.Combine(dir, fileName + " " + i + fileExt);
            }
        }

        public static string GetIndentdJson(IEnumerable<object> connections)
        {
            return JsonSerializer.Serialize(connections, new JsonSerializerOptions() { WriteIndented = true });
        }

        public static string ExportToFile(string dirPath, string fileName, IEnumerable<object> dataToExport)
        {
            var filePath = GetUniqueFilePath(Path.Combine(dirPath, fileName));
            File.WriteAllText(filePath, GetIndentdJson(dataToExport));
            return filePath;
        }

        public static string ExportNetworkMap(string dirPath, HashSet<PcapAnalyzer.NetworkConnection> connections)
        {
            return ExportToFile(dirPath, "BruteShark Network Map.json", connections);
        }

        public static string ExportNetworkNodesData(string dirPath, List<NetworkNode> networkNodes)
        {
            return ExportToFile(dirPath, "BruteShark Network Nodes Data.json", networkNodes);
        }

        public static string ExportFiles(string dirPath, HashSet<PcapAnalyzer.NetworkFile> networkFiles)
        {
            var extractedFilesDir = Path.Combine(dirPath, "Files");
            Directory.CreateDirectory(extractedFilesDir);

            foreach (var file in networkFiles)
            {
                var filePath = GetUniqueFilePath(Path.Combine(extractedFilesDir, $"{file.Source} - {file.Destination}.{file.Extention}"));
                File.WriteAllBytes(filePath, file.FileData);
            }

            return extractedFilesDir;
        }

        public static string ExportVoipCalls(string dirPath, HashSet<VoipCall> voipCalls )
        {
            var VoipCallsDir = Path.Combine(dirPath, "VoipCalls");
            Directory.CreateDirectory(VoipCallsDir);

            foreach (var call in voipCalls)
            {
                if (call.RTPStream.Length > 0)
                {
                    var filepath = GetUniqueFilePath(Path.Combine(VoipCallsDir, $"{call.ToFilename()}.media"));
                    File.WriteAllBytes(filepath, call.RTPStream);
                }
            }

            return VoipCallsDir;
        }

        public static string ExportDnsMappings(string dirPath, HashSet<PcapAnalyzer.DnsNameMapping> dnsMappings)
        {
            var filePath = GetUniqueFilePath(Path.Combine(dirPath, "BruteShark DNS Mappings.json"));

            File.WriteAllLines(
                filePath, 
                dnsMappings.Select(d => d.ToString()));
            
            return filePath;
        }

        // Phase 3: Export JA3 TLS fingerprints
        public static string ExportJa3Fingerprints(string dirPath, List<PcapAnalyzer.Ja3Fingerprint> fingerprints)
        {
            if (fingerprints == null || fingerprints.Count == 0)
                return null;

            var lines = new List<string>();
            lines.Add("# JA3 TLS Fingerprints - BruteShark Studio Export");
            lines.Add("# Format: JA3_Hash | Source_IP | Dest_IP:Port | Known_Software");
            lines.Add("# Timestamp: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));

            foreach (var f in fingerprints)
            {
                string known = string.IsNullOrEmpty(f.KnownSoftware) ? "" : $" | {f.KnownSoftware}";
                lines.Add($"{f.Ja3Hash} | {f.SourceIp} | {f.DestinationIp}:{f.DestinationPort}{known}");
            }

            var filePath = GetUniqueFilePath(Path.Combine(dirPath, "BruteShark JA3 Fingerprints.txt"));
            File.WriteAllLines(filePath, lines);
            return filePath;
        }

        // Phase 3: Export beacon detection results
        public static string ExportBeaconResults(string dirPath, List<PcapAnalyzer.BeaconResult> beacons)
        {
            if (beacons == null || beacons.Count == 0)
                return null;

            return ExportToFile(dirPath, "BruteShark Beacon Detections.json", beacons);
        }

        // Phase 3: Export detection rule matches
        public static string ExportRuleMatches(string dirPath, List<PcapAnalyzer.RuleMatch> matches)
        {
            if (matches == null || matches.Count == 0)
                return null;

            var lines = new List<string>();
            lines.Add("# Detection Rule Matches - BruteShark Studio Export");
            lines.Add($"# Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            lines.Add("# Severity | Category | Rule | Source -> Target | MITRE | Details");

            foreach (var m in matches)
            {
                lines.Add($"{m.Severity} | {m.Category} | {m.RuleName} | " +
                    $"{m.SourceIp ?? "-"}:{m.SourcePort} -> {m.DestinationIp ?? "-"}:{m.DestinationPort} | " +
                    $"{m.MitreTechnique ?? "-"} | {m.MatchDetails}");
            }

            var filePath = GetUniqueFilePath(Path.Combine(dirPath, "BruteShark Detection Matches.txt"));
            File.WriteAllLines(filePath, lines);
            return filePath;
        }

        // Enterprise: Export SSH fingerprints
        public static string ExportSshFingerprints(string dirPath, List<PcapAnalyzer.SshServerFingerprint> fingerprints)
        {
            if (fingerprints == null || fingerprints.Count == 0)
                return null;

            return ExportToFile(dirPath, "BruteShark SSH Fingerprints.json", fingerprints.Cast<object>());
        }

        // Enterprise: Export DHCP leases
        public static string ExportDhcpLeases(string dirPath, List<PcapAnalyzer.DhcpLease> leases)
        {
            if (leases == null || leases.Count == 0)
                return null;

            return ExportToFile(dirPath, "BruteShark DHCP Leases.json", leases.Cast<object>());
        }

        // Enterprise: Export HTTP transactions
        public static string ExportHttpTransactions(string dirPath, List<PcapAnalyzer.HttpTransaction> transactions)
        {
            if (transactions == null || transactions.Count == 0)
                return null;

            return ExportToFile(dirPath, "BruteShark HTTP Transactions.json", transactions.Cast<object>());
        }

        // Enterprise: Export Payload Alerts
        public static string ExportPayloadAlerts(string dirPath, List<PcapAnalyzer.PayloadAlert> alerts)
        {
            if (alerts == null || alerts.Count == 0)
                return null;

            return ExportToFile(dirPath, "BruteShark Payload Alerts.json", alerts.Cast<object>());
        }

        // Enterprise: Export TLS Certificates
        public static string ExportTlsCertificates(string dirPath, List<PcapAnalyzer.TlsCertificate> certs)
        {
            if (certs == null || certs.Count == 0)
                return null;

            var lines = new List<string>();
            lines.Add("# TLS Certificates - BruteShark Studio Export");
            lines.Add($"# Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            lines.Add("# Subject | Issuer | Serial | Not_Before | Not_After | Server_IP:Port | Fingerprint | Suspicious");

            foreach (var c in certs)
            {
                lines.Add($"{c.Subject} | {c.Issuer} | {c.SerialNumber} | {c.NotBefore:yyyy-MM-dd HH:mm} | {c.NotAfter:yyyy-MM-dd HH:mm} | " +
                    $"{c.ServerIp}:{c.ServerPort} | {c.Fingerprint} | {c.IsSuspicious}");
            }

            var path = GetUniqueFilePath(Path.Combine(dirPath, "BruteShark TLS Certificates.txt"));
            File.WriteAllLines(path, lines);
            return path;
        }

        // Enterprise: Export DNS Exfiltration Alerts
        public static string ExportDnsExfilAlerts(string dirPath, List<PcapAnalyzer.DnsExfilAlert> alerts)
        {
            if (alerts == null || alerts.Count == 0)
                return null;

            return ExportToFile(dirPath, "BruteShark DNS Exfil Alerts.json", alerts.Cast<object>());
        }

        public static string ReplaceInvalidFileNameChars(string filename, char newChar)
        {
            return string.Join(newChar.ToString(), filename.Split(Path.GetInvalidFileNameChars()));
        }

    }
}
