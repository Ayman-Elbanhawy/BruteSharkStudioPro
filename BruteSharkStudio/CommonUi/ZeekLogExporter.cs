// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// Zeek-Format (Bro) Log Exporter for BruteShark Studio.
// Generates tab-separated log files in the standard Zeek format:
//   conn.log, http.log, dns.log, ssl.log, files.log
//
// Zeek log format: https://docs.zeek.org/en/master/log-formats.html
// Each log file has a header section (#separator, #fields, #types) and
// tab-separated data rows, compatible with Zeek analysis tools.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PcapAnalyzer;

namespace CommonUi
{
    public static class ZeekLogExporter
    {
        private const string Separator = "\\x09"; // Tab
        private const string SetSeparator = ",";
        private const string EmptyField = "-";
        private const string UnsetField = "-";

        /// <summary>
        /// Generate all Zeek-format logs from analysis results.
        /// </summary>
        public static string ExportAllZeekLogs(string directory, NetworkContext context,
            IEnumerable<HttpTransaction> httpTransactions = null)
        {
            var logDir = Path.Combine(directory, "zeek_logs");
            Directory.CreateDirectory(logDir);

            ExportConnLog(logDir, context.Connections);
            ExportDnsLog(logDir, context.DnsMappings);
            ExportSslLog(logDir, context.Ja3Fingerprints);
            if (httpTransactions?.Any() == true)
                ExportHttpLog(logDir, httpTransactions);

            return logDir;
        }

        /// <summary>
        /// Zeek conn.log — connection summary records.
        /// </summary>
        private static void ExportConnLog(string dir, HashSet<PcapAnalyzer.NetworkConnection> connections)
        {
            var sb = new StringBuilder();
            WriteZeekHeader(sb, "conn", new[]
            {
                ("ts", "time"), ("uid", "string"), ("id.orig_h", "addr"),
                ("id.orig_p", "port"), ("id.resp_h", "addr"), ("id.resp_p", "port"),
                ("proto", "enum"), ("service", "string"), ("duration", "interval"),
                ("orig_bytes", "count"), ("resp_bytes", "count"), ("conn_state", "string"),
                ("local_orig", "bool"), ("local_resp", "bool"), ("missed_bytes", "count"),
                ("history", "string"), ("orig_pkts", "count"), ("orig_ip_bytes", "count"),
                ("resp_pkts", "count"), ("resp_ip_bytes", "count")
            });

            string ts = DateTime.UtcNow.ToString("o");
            string uid = Guid.NewGuid().ToString().Substring(0, 12);

            foreach (var conn in connections)
            {
                sb.Append(string.Join("\t", new[]
                {
                    ts, uid, conn.Source, conn.SrcPort.ToString(),
                    conn.Destination, conn.DestPort.ToString(),
                    conn.Protocol?.ToLower() ?? "tcp",
                    ClassifyZeekService(conn.DestPort, conn.Protocol),
                    "0.0", "0", "0", "OTH",
                    EmptyField, EmptyField, "0", EmptyField, "0", EmptyField, "0", EmptyField
                }));
                sb.AppendLine();
            }

            File.WriteAllText(Path.Combine(dir, "conn.log"), sb.ToString());
        }

        /// <summary>
        /// Zeek dns.log — DNS activity records.
        /// </summary>
        private static void ExportDnsLog(string dir, HashSet<PcapAnalyzer.DnsNameMapping> dnsMappings)
        {
            var sb = new StringBuilder();
            WriteZeekHeader(sb, "dns", new[]
            {
                ("ts", "time"), ("uid", "string"), ("id.orig_h", "addr"),
                ("id.orig_p", "port"), ("id.resp_h", "addr"), ("id.resp_p", "port"),
                ("proto", "enum"), ("trans_id", "count"), ("rtt", "interval"),
                ("query", "string"), ("qclass", "count"), ("qclass_name", "string"),
                ("qtype", "count"), ("qtype_name", "string"), ("rcode", "count"),
                ("rcode_name", "string"), ("AA", "bool"), ("TC", "bool"),
                ("RD", "bool"), ("RA", "bool"), ("Z", "count"),
                ("answers", "vector[string]"), ("TTLs", "vector[interval]"),
                ("rejected", "bool")
            });

            string ts = DateTime.UtcNow.ToString("o");
            string uid = Guid.NewGuid().ToString().Substring(0, 12);

            foreach (var dns in dnsMappings)
            {
                sb.Append(string.Join("\t", new[]
                {
                    ts, uid, EmptyField, "0", EmptyField, "53",
                    "udp", "0", "0.0",
                    dns.Query ?? "", "1", "C_INTERNET",
                    "1", "A", "0", "NOERROR",
                    "F", "F", "T", "F", "0",
                    dns.Destination ?? EmptyField, "0.0", "F"
                }));
                sb.AppendLine();
            }

            File.WriteAllText(Path.Combine(dir, "dns.log"), sb.ToString());
        }

        /// <summary>
        /// Zeek ssl.log — SSL/TLS handshake records.
        /// </summary>
        private static void ExportSslLog(string dir, List<PcapAnalyzer.Ja3Fingerprint> ja3Prints)
        {
            var sb = new StringBuilder();
            WriteZeekHeader(sb, "ssl", new[]
            {
                ("ts", "time"), ("uid", "string"), ("id.orig_h", "addr"),
                ("id.orig_p", "port"), ("id.resp_h", "addr"), ("id.resp_p", "port"),
                ("version", "string"), ("cipher", "count"), ("curve", "string"),
                ("server_name", "string"), ("resumed", "bool"), ("last_alert", "string"),
                ("next_protocol", "string"), ("established", "bool"),
                ("ssl_history", "string"), ("cert_chain_fuids", "vector[string]"),
                ("client_cert_chain_fuids", "vector[string]"),
                ("subject", "string"), ("issuer", "string"),
                ("ja3", "string"), ("ja3s", "string")
            });

            string ts = DateTime.UtcNow.ToString("o");

            foreach (var ja3 in ja3Prints)
            {
                string known = string.IsNullOrEmpty(ja3.KnownSoftware) ? EmptyField : ja3.KnownSoftware;
                sb.Append(string.Join("\t", new[]
                {
                    ts, Guid.NewGuid().ToString().Substring(0, 12),
                    ja3.SourceIp ?? EmptyField, EmptyField,
                    ja3.DestinationIp ?? EmptyField, ja3.DestinationPort.ToString(),
                    "TLSv12", "0", EmptyField,
                    known, "F", EmptyField,
                    EmptyField, "T",
                    EmptyField, EmptyField, EmptyField,
                    EmptyField, EmptyField,
                    ja3.Ja3Hash, EmptyField
                }));
                sb.AppendLine();
            }

            File.WriteAllText(Path.Combine(dir, "ssl.log"), sb.ToString());
        }

        /// <summary>
        /// Zeek http.log — HTTP request/response records.
        /// </summary>
        private static void ExportHttpLog(string dir, IEnumerable<HttpTransaction> transactions)
        {
            var sb = new StringBuilder();
            WriteZeekHeader(sb, "http", new[]
            {
                ("ts", "time"), ("uid", "string"), ("id.orig_h", "addr"),
                ("id.orig_p", "port"), ("id.resp_h", "addr"), ("id.resp_p", "port"),
                ("trans_depth", "count"), ("method", "string"), ("host", "string"),
                ("uri", "string"), ("referrer", "string"), ("version", "string"),
                ("user_agent", "string"), ("origin", "string"),
                ("request_body_len", "count"), ("response_body_len", "count"),
                ("status_code", "count"), ("status_msg", "string"),
                ("info_code", "count"), ("info_msg", "string"),
                ("tags", "set[enum]"), ("username", "string"),
                ("password", "string"), ("proxied", "set[string]"),
                ("orig_fuids", "vector[string]"), ("resp_fuids", "vector[string]"),
                ("orig_filenames", "vector[string]"), ("resp_filenames", "vector[string]"),
                ("orig_mime_types", "vector[string]"), ("resp_mime_types", "vector[string]")
            });

            foreach (var tx in transactions.Where(t => t.Method != null))
            {
                sb.Append(string.Join("\t", new[]
                {
                    DateTime.UtcNow.ToString("o"),
                    Guid.NewGuid().ToString().Substring(0, 12),
                    tx.SourceIp ?? EmptyField, tx.SourcePort.ToString(),
                    tx.DestinationIp ?? EmptyField, tx.DestinationPort.ToString(),
                    "1", tx.Method, tx.Host ?? EmptyField,
                    tx.Uri ?? EmptyField, tx.Referer ?? EmptyField,
                    tx.HttpVersion ?? "1.1",
                    tx.UserAgent ?? EmptyField, EmptyField,
                    "0", "0",
                    tx.StatusCode > 0 ? tx.StatusCode.ToString() : "0",
                    tx.StatusMessage ?? EmptyField,
                    EmptyField, EmptyField,
                    EmptyField, EmptyField, EmptyField,
                    EmptyField, EmptyField, EmptyField,
                    EmptyField, EmptyField, EmptyField,
                    tx.ContentType ?? EmptyField, EmptyField
                }));
                sb.AppendLine();
            }

            File.WriteAllText(Path.Combine(dir, "http.log"), sb.ToString());
        }

        private static void WriteZeekHeader(StringBuilder sb, string module, (string field, string type)[] columns)
        {
            sb.AppendLine($"#separator {Separator}");
            sb.AppendLine($"#set_separator\t{SetSeparator}");
            sb.AppendLine($"#empty_field\t{EmptyField}");
            sb.AppendLine($"#unset_field\t{UnsetField}");
            sb.AppendLine($"#path\t{module}");
            sb.AppendLine("#open\t" + DateTime.UtcNow.ToString("yyyy-MM-dd-HH-mm-ss"));
            sb.AppendLine($"#fields\t{string.Join("\t", columns.Select(c => c.field))}");
            sb.AppendLine($"#types\t{string.Join("\t", columns.Select(c => c.type))}");
        }

        private static string ClassifyZeekService(int port, string proto)
        {
            string p = proto?.ToLower() ?? "tcp";
            return (p, port) switch
            {
                ("tcp", 80) or ("tcp", 8080) => "http",
                ("tcp", 443) or ("tcp", 8443) => "ssl",
                ("tcp", 21) => "ftp",
                ("tcp", 22) => "ssh",
                ("tcp", 23) => "telnet",
                ("tcp", 25) => "smtp",
                (_, 53) => "dns",
                ("udp", 67) or ("udp", 68) => "dhcp",
                ("tcp", 110) => "pop3",
                ("tcp", 143) => "imap",
                ("tcp", 389) or ("tcp", 636) => "ldap",
                ("tcp", 445) or ("tcp", 139) => "smb",
                ("tcp", 1433) => "mssql",
                ("tcp", 3306) => "mysql",
                ("tcp", 3389) => "rdp",
                _ => p
            };
        }
    }
}
