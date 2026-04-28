// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// IOC & STIX Export module for BruteShark Studio.
// Exports Indicators of Compromise in STIX 2.0, MISP JSON, and CSV formats
// for SIEM integration and threat intelligence sharing.
//
// Formats supported:
//   - STIX 2.0 Bundle JSON (for TAXII/Cortex/ThreatConnect)
//   - MISP event JSON (for MISP threat sharing platform)
//   - CSV (for Splunk/ELK/SIEM ingestion)
//   - OpenIOC 1.1 XML (for FireEye/Mandiant)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace CommonUi
{
    /// <summary>
    /// Represents a single Indicator of Compromise (IOC).
    /// </summary>
    public class Indicator
    {
        public string Type { get; set; }       // "ipv4", "domain", "url", "hash-sha256", "hash-md5", "email", "file"
        public string Value { get; set; }
        public string Context { get; set; }    // Where/how was this found
        public string Severity { get; set; }   // "HIGH", "MEDIUM", "LOW"
        public string Category { get; set; }   // "C2", "Malware", "Phishing", "Exfiltration"
        public DateTime FirstSeen { get; set; }
        public string SourceHost { get; set; }  // Which host contacted this indicator
        public string MitreTechnique { get; set; }

        public override string ToString() => $"[{Severity}] {Type}:{Value} ({Category})";
    }

    /// <summary>
    /// IOC extractor and multi-format exporter for BruteShark Studio.
    /// </summary>
    public static class IocExporter
    {
        /// <summary>
        /// Extract IOCs from analysis results in NetworkContext.
        /// </summary>
        public static List<Indicator> ExtractIocs(NetworkContext context)
        {
            var iocs = new List<Indicator>();

            // IPs from connections (external IPs are potential IOCs)
            foreach (var conn in context.Connections)
            {
                if (!IsPrivateIp(conn.Destination))
                {
                    iocs.Add(new Indicator
                    {
                        Type = "ipv4",
                        Value = conn.Destination,
                        Context = $"{conn.Protocol} connection from {conn.Source}:{conn.SrcPort}",
                        Severity = GetPortSeverity(conn.DestPort),
                        Category = GetPortCategory(conn.DestPort),
                        SourceHost = conn.Source
                    });
                }
            }

            // DNS queries as domain IOCs
            foreach (var dns in context.DnsMappings)
            {
                string domain = dns.Query?.TrimEnd('.');
                if (!string.IsNullOrWhiteSpace(domain) && !IsPrivateIp(dns.Destination))
                {
                    iocs.Add(new Indicator
                    {
                        Type = "domain",
                        Value = domain,
                        Context = $"DNS query resolved to {dns.Destination}",
                        Severity = domain.Length > 52 ? "HIGH" : "MEDIUM",
                        Category = domain.Length > 52 ? "Exfiltration" : "Reconnaissance",
                        SourceHost = dns.Destination
                    });
                }

                // External IP from DNS
                if (!IsPrivateIp(dns.Destination))
                {
                    iocs.Add(new Indicator
                    {
                        Type = "ipv4",
                        Value = dns.Destination,
                        Context = $"DNS resolution for {domain}",
                        Severity = "MEDIUM",
                        Category = "Reconnaissance",
                        SourceHost = domain
                    });
                }
            }

            // Malicious JA3 fingerprints as IOCs
            foreach (var ja3 in context.Ja3Fingerprints.Where(j => !string.IsNullOrEmpty(j.KnownSoftware)))
            {
                iocs.Add(new Indicator
                {
                    Type = "hash-md5", // JA3 is MD5
                    Value = ja3.Ja3Hash,
                    Context = $"Malicious TLS fingerprint: {ja3.KnownSoftware} from {ja3.SourceIp}",
                    Severity = "CRITICAL",
                    Category = "Malware",
                    SourceHost = ja3.SourceIp
                });
            }

            // C2 servers from beacon detections
            foreach (var beacon in context.BeaconResults)
            {
                if (!string.IsNullOrWhiteSpace(beacon.ProbableC2Server) && !IsPrivateIp(beacon.ProbableC2Server))
                {
                    iocs.Add(new Indicator
                    {
                        Type = "ipv4",
                        Value = beacon.ProbableC2Server,
                        Context = $"C2 beacon candidate (score: {beacon.BeaconScore:F0}%, interval: {beacon.MeanIntervalSeconds:F1}s)",
                        Severity = beacon.BeaconScore >= 75 ? "CRITICAL" : "HIGH",
                        Category = "C2",
                        SourceHost = beacon.PairKey?.Split(new[] { "<->" }, StringSplitOptions.None).FirstOrDefault()
                    });
                }
            }

            return iocs;
        }

        /// <summary>
        /// Export IOCs in STIX 2.0 Bundle JSON format.
        /// </summary>
        public static string ExportStixJson(List<Indicator> iocs)
        {
            var bundle = new Dictionary<string, object>
            {
                ["type"] = "bundle",
                ["id"] = $"bundle--{Guid.NewGuid()}",
                ["spec_version"] = "2.0",
                ["objects"] = new List<object>()
            };

            var objects = (List<object>)bundle["objects"];

            foreach (var ioc in iocs)
            {
                var indicator = new Dictionary<string, object>
                {
                    ["type"] = "indicator",
                    ["id"] = $"indicator--{Guid.NewGuid()}",
                    ["created"] = ioc.FirstSeen.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    ["modified"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    ["name"] = $"{ioc.Type.ToUpper()}: {ioc.Value}",
                    ["description"] = ioc.Context,
                    ["pattern"] = GetStixPattern(ioc),
                    ["pattern_type"] = "stix",
                    ["valid_from"] = ioc.FirstSeen.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                    ["labels"] = new[] { ioc.Category.ToLower() },
                    ["severity"] = ioc.Severity
                };
                objects.Add(indicator);
            }

            var options = new JsonSerializerOptions { WriteIndented = true };
            return System.Text.Json.JsonSerializer.Serialize(bundle, options);
        }

        /// <summary>
        /// Export IOCs in CSV format (for Splunk/ELK/SIEM).
        /// </summary>
        public static string ExportCsv(List<Indicator> iocs)
        {
            var sb = new StringBuilder();
            sb.AppendLine("type,value,context,severity,category,source_host,mitre_technique");

            foreach (var ioc in iocs)
            {
                sb.AppendLine($"{CsvEscape(ioc.Type)},{CsvEscape(ioc.Value)}," +
                    $"{CsvEscape(ioc.Context)},{CsvEscape(ioc.Severity)}," +
                    $"{CsvEscape(ioc.Category)},{CsvEscape(ioc.SourceHost ?? "")}," +
                    $"{CsvEscape(ioc.MitreTechnique ?? "")}");
            }

            return sb.ToString();
        }

        /// <summary>
        /// Export IOCs in MISP-compatible JSON format.
        /// </summary>
        public static string ExportMispJson(List<Indicator> iocs)
        {
            var mispEvent = new Dictionary<string, object>
            {
                ["Event"] = new Dictionary<string, object>
                {
                    ["info"] = $"BruteShark Studio IOC Export - {DateTime.UtcNow:yyyy-MM-dd}",
                    ["date"] = DateTime.UtcNow.ToString("yyyy-MM-dd"),
                    ["threat_level_id"] = "3", // Medium
                    ["published"] = false,
                    ["analysis"] = "1", // Ongoing
                    ["Attribute"] = new List<object>()
                }
            };

            var attributes = (List<object>)((Dictionary<string, object>)mispEvent["Event"])["Attribute"];

            foreach (var ioc in iocs)
            {
                attributes.Add(new Dictionary<string, object>
                {
                    ["type"] = MapToMispType(ioc.Type),
                    ["category"] = MapToMispCategory(ioc.Category),
                    ["value"] = ioc.Value,
                    ["comment"] = ioc.Context,
                    ["to_ids"] = true,
                    ["distribution"] = "0" // Your organization only
                });
            }

            var options = new JsonSerializerOptions { WriteIndented = true };
            return System.Text.Json.JsonSerializer.Serialize(mispEvent, options);
        }

        /// <summary>
        /// Export IOCs to file in the requested format.
        /// </summary>
        public static string ExportToFile(string directory, List<Indicator> iocs, string format = "csv")
        {
            string content = format.ToLower() switch
            {
                "stix" => ExportStixJson(iocs),
                "misp" => ExportMispJson(iocs),
                "csv" => ExportCsv(iocs),
                _ => ExportCsv(iocs)
            };

            string extension = format.ToLower() switch
            {
                "stix" => ".stix.json",
                "misp" => ".misp.json",
                _ => ".csv"
            };

            var filePath = Exporting.GetUniqueFilePath(
                Path.Combine(directory, $"BruteShark_IOCs_{DateTime.Now:yyyyMMdd_HHmmss}{extension}"));

            File.WriteAllText(filePath, content);
            return filePath;
        }

        private static string GetStixPattern(Indicator ioc)
        {
            return ioc.Type switch
            {
                "ipv4" => $"[ipv4-addr:value = '{ioc.Value}']",
                "domain" => $"[domain-name:value = '{ioc.Value}']",
                "hash-md5" => $"[file:hashes.MD5 = '{ioc.Value}']",
                "hash-sha256" => $"[file:hashes.'SHA-256' = '{ioc.Value}']",
                "url" => $"[url:value = '{ioc.Value}']",
                _ => $"[artifact:payload_bin MATCHES '{ioc.Value}']"
            };
        }

        private static string MapToMispType(string stixType)
        {
            return stixType switch
            {
                "ipv4" => "ip-dst",
                "domain" => "domain",
                "hash-md5" => "md5",
                "hash-sha256" => "sha256",
                "url" => "url",
                "email" => "email-dst",
                _ => "other"
            };
        }

        private static string MapToMispCategory(string category)
        {
            return category switch
            {
                "C2" => "Network activity",
                "Malware" => "Payload delivery",
                "Phishing" => "Social engineering",
                "Exfiltration" => "Exfiltration",
                _ => "Network activity"
            };
        }

        private static bool IsPrivateIp(string ip)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ip)) return true;
                var addr = System.Net.IPAddress.Parse(ip);
                byte[] b = addr.GetAddressBytes();
                if (b[0] == 10) return true;
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
                if (b[0] == 192 && b[1] == 168) return true;
                if (b[0] == 127) return true;
                return false;
            }
            catch { return true; }
        }

        private static string GetPortSeverity(int port)
        {
            return port switch
            {
                4444 or 31337 or 1337 or 6666 or 6667 or 12345 => "HIGH",
                445 or 3389 or 22 or 23 => "MEDIUM",
                _ => "LOW"
            };
        }

        private static string GetPortCategory(int port)
        {
            return port switch
            {
                4444 or 31337 or 1337 or 6666 or 6667 => "C2",
                445 or 139 => "Lateral Movement",
                3389 => "Remote Access",
                22 => "Administration",
                23 => "Cleartext Admin",
                443 or 8443 => "Web",
                80 or 8080 => "Web",
                _ => "Unknown"
            };
        }

        private static string CsvEscape(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            if (value.Contains(",") || value.Contains("\"") || value.Contains("\n"))
                return $"\"{value.Replace("\"", "\"\"")}\"";
            return value;
        }
    }
}
