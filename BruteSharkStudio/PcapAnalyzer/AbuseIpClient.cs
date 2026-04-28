// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// AbuseIPDB API v2 integration for BruteShark Studio.
// Provides IP reputation checking against AbuseIPDB's threat database.
// API key must be set via environment variable ABUSEIPDB_API_KEY.
//
// AbuseIPDB: https://www.abuseipdb.com/
// Free tier: 1000 lookups/day, rate-limited.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Text.Json;
using System.Linq;

namespace PcapAnalyzer
{
    /// <summary>
    /// AbuseIPDB reputation check result.
    /// </summary>
    public class AbuseIpResult
    {
        public string IpAddress { get; set; }
        public int AbuseConfidenceScore { get; set; } // 0-100
        public int TotalReports { get; set; }
        public DateTime? LastReportedAt { get; set; }
        public string CountryCode { get; set; }
        public string Isp { get; set; }
        public string Domain { get; set; }
        public string UsageType { get; set; }
        public List<string> Categories { get; set; } = new List<string>();

        public bool IsMalicious => AbuseConfidenceScore >= 50;
        public bool IsHighlyMalicious => AbuseConfidenceScore >= 90;
        public string RiskLevel => AbuseConfidenceScore >= 90 ? "CRITICAL" :
                                  AbuseConfidenceScore >= 50 ? "HIGH" :
                                  AbuseConfidenceScore >= 25 ? "MEDIUM" :
                                  AbuseConfidenceScore >= 1 ? "LOW" : "CLEAN";

        public override string ToString()
            => $"AbuseIPDB: {IpAddress} Score: {AbuseConfidenceScore}% | Reports: {TotalReports} | {Isp}";
    }

    /// <summary>
    /// AbuseIPDB API v2 client with rate limiting and caching.
    /// Free tier: 1000 lookups/day.
    /// </summary>
    public class AbuseIpClient : IDisposable
    {
        private readonly HttpClient _http;
        private readonly string _apiKey;
        private readonly Dictionary<string, AbuseIpResult> _cache;
        private readonly object _cacheLock = new();
        private DateTime _lastRequestTime = DateTime.MinValue;
        private readonly TimeSpan _minInterval = TimeSpan.FromMilliseconds(500); // 2000/day max
        private bool _disposed;

        public int CacheHits { get; private set; }
        public int ApiCalls { get; private set; }
        public bool HasApiKey => !string.IsNullOrWhiteSpace(_apiKey);

        private static readonly Dictionary<int, string> CategoryNames = new()
        {
            [3] = "Fraud", [4] = "DDoS", [5] = "FTP Brute-Force",
            [6] = "Web Attack", [7] = "Spam", [8] = "Botnet C2",
            [9] = "SSH Brute-Force", [10] = "IoT Targeted",
            [11] = "Tor Exit Node", [14] = "Port Scan",
            [15] = "Hacking", [16] = "SQL Injection",
            [18] = "Brute-Force", [19] = "Bad Web Bot",
            [20] = "Fake Google Bot", [21] = "DDoS Attack",
            [22] = "SSH Abuse", [23] = "Telnet Abuse"
        };

        public AbuseIpClient(string apiKey = null)
        {
            _apiKey = apiKey ?? Environment.GetEnvironmentVariable("ABUSEIPDB_API_KEY") ?? "";
            _http = new HttpClient();
            _http.DefaultRequestHeaders.Add("User-Agent", "BruteSharkStudio/2.0");
            _http.DefaultRequestHeaders.Add("Accept", "application/json");
            if (!string.IsNullOrWhiteSpace(_apiKey))
                _http.DefaultRequestHeaders.Add("Key", _apiKey);
            _http.Timeout = TimeSpan.FromSeconds(15);
            _cache = new Dictionary<string, AbuseIpResult>();
        }

        public async Task<AbuseIpResult> CheckIpAsync(string ipAddress, int maxAgeDays = 90)
        {
            if (!HasApiKey || string.IsNullOrWhiteSpace(ipAddress)) return null;

            string cacheKey = $"ip:{ipAddress}";
            lock (_cacheLock)
            {
                if (_cache.TryGetValue(cacheKey, out var cached))
                {
                    CacheHits++;
                    return cached;
                }
            }

            await EnforceRateLimit();

            try
            {
                string url = $"https://api.abuseipdb.com/api/v2/check" +
                    $"?ipAddress={Uri.EscapeDataString(ipAddress)}" +
                    $"&maxAgeInDays={maxAgeDays}&verbose";

                var response = await _http.GetAsync(url);
                ApiCalls++;

                if (!response.IsSuccessStatusCode) return null;

                var json = await response.Content.ReadAsStringAsync();
                var result = ParseResponse(json, ipAddress);

                lock (_cacheLock) { _cache[cacheKey] = result; }
                return result;
            }
            catch { return null; }
        }

        /// <summary>
        /// Bulk check IPs and return only malicious ones.
        /// </summary>
        public async Task<List<AbuseIpResult>> CheckIpsAsync(IEnumerable<string> ipAddresses)
        {
            var results = new List<AbuseIpResult>();
            foreach (var ip in ipAddresses.Distinct())
            {
                var result = await CheckIpAsync(ip);
                if (result != null)
                    results.Add(result);
            }
            return results;
        }

        /// <summary>
        /// Check all external IPs from a list of connections and DNS mappings.
        /// </summary>
        public async Task<List<AbuseIpResult>> CheckExternalIpsAsync(
            IEnumerable<NetworkConnection> connections,
            IEnumerable<DnsNameMapping> dnsMappings = null)
        {
            var externalIps = new HashSet<string>();
            foreach (var conn in connections)
            {
                if (!IsPrivateIp(conn.Destination)) externalIps.Add(conn.Destination);
                if (!IsPrivateIp(conn.Source)) externalIps.Add(conn.Source);
            }
            if (dnsMappings != null)
            {
                foreach (var dns in dnsMappings)
                {
                    if (!IsPrivateIp(dns.Destination)) externalIps.Add(dns.Destination);
                }
            }

            var results = new List<AbuseIpResult>();
            foreach (var ip in externalIps.Take(50)) // Free tier limit
            {
                var result = await CheckIpAsync(ip);
                if (result != null && result.IsMalicious)
                {
                    results.Add(result);
                }
            }
            return results;
        }

        private async Task EnforceRateLimit()
        {
            var elapsed = DateTime.UtcNow - _lastRequestTime;
            if (elapsed < _minInterval)
                await Task.Delay(_minInterval - elapsed);
            _lastRequestTime = DateTime.UtcNow;
        }

        private AbuseIpResult ParseResponse(string json, string ip)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var data = doc.RootElement.GetProperty("data");

                var result = new AbuseIpResult
                {
                    IpAddress = data.GetProperty("ipAddress").GetString(),
                    AbuseConfidenceScore = data.GetProperty("abuseConfidenceScore").GetInt32(),
                    TotalReports = data.GetProperty("totalReports").GetInt32(),
                    CountryCode = data.TryGetProperty("countryCode", out var cc) ? cc.GetString() : "",
                    Isp = data.TryGetProperty("isp", out var isp) ? isp.GetString() : "",
                    Domain = data.TryGetProperty("domain", out var dom) ? dom.GetString() : "",
                    UsageType = data.TryGetProperty("usageType", out var ut) ? ut.GetString() : "",
                };

                if (data.TryGetProperty("lastReportedAt", out var lr) && lr.ValueKind != JsonValueKind.Null)
                    result.LastReportedAt = lr.GetDateTime();

                if (data.TryGetProperty("reports", out var reports) && reports.ValueKind == JsonValueKind.Array)
                {
                    var cats = new HashSet<string>();
                    foreach (var report in reports.EnumerateArray())
                    {
                        if (report.TryGetProperty("categories", out var catsArr))
                        {
                            foreach (var cat in catsArr.EnumerateArray())
                            {
                                int catId = cat.GetInt32();
                                if (CategoryNames.TryGetValue(catId, out string name))
                                    cats.Add(name);
                            }
                        }
                    }
                    result.Categories = cats.ToList();
                }

                return result;
            }
            catch { return null; }
        }

        private static bool IsPrivateIp(string ip)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ip)) return true;
                var addr = System.Net.IPAddress.Parse(ip);
                byte[] b = addr.GetAddressBytes();
                if (b.Length != 4) return true;
                if (b[0] == 10 || b[0] == 127) return true;
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
                if (b[0] == 192 && b[1] == 168) return true;
                if (b[0] == 169 && b[1] == 254) return true;
                return false;
            }
            catch { return true; }
        }

        public void Dispose()
        {
            if (!_disposed) { _http?.Dispose(); _disposed = true; }
            GC.SuppressFinalize(this);
        }
    }
}
