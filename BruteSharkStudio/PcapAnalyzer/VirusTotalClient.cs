// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// VirusTotal API v3 integration module for BruteShark Studio.
// Provides hash lookup, IP reputation, domain reputation, and file submission.
// Uses the free VirusTotal API (rate-limited: 4 lookups/min, 500/day).
//
// API docs: https://docs.virustotal.com/reference/overview

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace PcapAnalyzer
{
    /// <summary>
    /// VirusTotal lookup result for a hash, IP, or domain.
    /// </summary>
    public class VirusTotalResult
    {
        public string Indicator { get; set; }
        public string IndicatorType { get; set; } // "hash", "ip", "domain"
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Harmless { get; set; }
        public int Undetected { get; set; }
        public int TotalEngines => Malicious + Suspicious + Harmless + Undetected;
        public string ThreatLabel { get; set; }
        public List<string> MaliciousEngineNames { get; set; } = new List<string>();
        public string Permalink { get; set; }
        public string Country { get; set; }
        public string ASNOwner { get; set; }
        public int? ASN { get; set; }

        public bool IsMalicious => Malicious > 0;
        public bool IsHighlyMalicious => Malicious >= 5;
        public string RiskLevel => Malicious >= 10 ? "CRITICAL" :
                                   Malicious >= 5 ? "HIGH" :
                                   Malicious >= 2 ? "MEDIUM" :
                                   Malicious >= 1 ? "LOW" : "CLEAN";
    }

    /// <summary>
    /// VirusTotal API v3 client with rate limiting and caching.
    /// API key must be set via environment variable VT_API_KEY or passed explicitly.
    /// </summary>
    public class VirusTotalClient : IDisposable
    {
        private readonly HttpClient _http;
        private readonly string _apiKey;
        private readonly Dictionary<string, VirusTotalResult> _cache;
        private readonly object _cacheLock = new object();
        private DateTime _lastRequestTime = DateTime.MinValue;
        private readonly TimeSpan _minRequestInterval = TimeSpan.FromSeconds(15); // 4/min rate limit
        private bool _disposed;

        public int CacheHits { get; private set; }
        public int ApiCalls { get; private set; }
        public bool HasApiKey => !string.IsNullOrWhiteSpace(_apiKey);

        public VirusTotalClient(string apiKey = null)
        {
            _apiKey = apiKey ?? Environment.GetEnvironmentVariable("VT_API_KEY") ?? "";
            _http = new HttpClient();
            _http.DefaultRequestHeaders.Add("User-Agent", "BruteSharkStudio/1.0");
            if (!string.IsNullOrWhiteSpace(_apiKey))
            {
                _http.DefaultRequestHeaders.Add("x-apikey", _apiKey);
            }
            _http.Timeout = TimeSpan.FromSeconds(30);
            _cache = new Dictionary<string, VirusTotalResult>();
        }

        /// <summary>
        /// Look up a file hash (MD5, SHA-1, or SHA-256) on VirusTotal.
        /// </summary>
        public async Task<VirusTotalResult> LookupHashAsync(NetworkHash hash)
        {
            string hashValue = hash.Hash;
            if (string.IsNullOrWhiteSpace(hashValue) || hashValue.Length < 32)
                return null;

            return await LookupHashAsync(hashValue);
        }

        public async Task<VirusTotalResult> LookupHashAsync(string hashValue)
        {
            if (!HasApiKey) return null;

            string cacheKey = $"hash:{hashValue}";

            // Check cache
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
                var response = await _http.GetAsync(
                    $"https://www.virustotal.com/api/v3/files/{hashValue}");

                ApiCalls++;

                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    // Hash not found on VT - still useful info
                    var result = new VirusTotalResult
                    {
                        Indicator = hashValue,
                        IndicatorType = "hash",
                        ThreatLabel = "Unknown (not in VirusTotal)"
                    };
                    CacheResult(cacheKey, result);
                    return result;
                }

                if (!response.IsSuccessStatusCode)
                    return null;

                var json = await response.Content.ReadAsStringAsync();
                var result2 = ParseHashResponse(json, hashValue);
                CacheResult(cacheKey, result2);
                return result2;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Look up an IP address reputation.
        /// </summary>
        public async Task<VirusTotalResult> LookupIpAsync(string ipAddress)
        {
            if (!HasApiKey || string.IsNullOrWhiteSpace(ipAddress))
                return null;

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
                var response = await _http.GetAsync(
                    $"https://www.virustotal.com/api/v3/ip_addresses/{ipAddress}");

                ApiCalls++;

                if (!response.IsSuccessStatusCode)
                    return null;

                var json = await response.Content.ReadAsStringAsync();
                var result = ParseIpResponse(json, ipAddress);
                CacheResult(cacheKey, result);
                return result;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Look up a domain reputation.
        /// </summary>
        public async Task<VirusTotalResult> LookupDomainAsync(string domain)
        {
            if (!HasApiKey || string.IsNullOrWhiteSpace(domain))
                return null;

            string cacheKey = $"domain:{domain}";

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
                var response = await _http.GetAsync(
                    $"https://www.virustotal.com/api/v3/domains/{domain}");

                ApiCalls++;

                if (!response.IsSuccessStatusCode)
                    return null;

                var json = await response.Content.ReadAsStringAsync();
                var result = ParseDomainResponse(json, domain);
                CacheResult(cacheKey, result);
                return result;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Enrich a DNS name mapping with VirusTotal data.
        /// </summary>
        public async Task<VirusTotalEnrichedDns> EnrichDnsMappingAsync(DnsNameMapping dns)
        {
            var result = new VirusTotalEnrichedDns { DnsMapping = dns };

            if (System.Net.IPAddress.TryParse(dns.Destination, out _))
            {
                result.IpResult = await LookupIpAsync(dns.Destination);
            }

            // Also check the queried domain
            string domain = dns.Query?.TrimEnd('.');
            if (!string.IsNullOrWhiteSpace(domain))
            {
                result.DomainResult = await LookupDomainAsync(domain);
            }

            return result;
        }

        /// <summary>
        /// Batch-enrich all hashes from analysis results.
        /// Returns results as they complete.
        /// </summary>
        public async Task<List<VirusTotalResult>> EnrichHashesAsync(IEnumerable<NetworkHash> hashes)
        {
            var results = new List<VirusTotalResult>();
            foreach (var hash in hashes)
            {
                var result = await LookupHashAsync(hash);
                if (result != null)
                    results.Add(result);
            }
            return results;
        }

        private async Task EnforceRateLimit()
        {
            var elapsed = DateTime.UtcNow - _lastRequestTime;
            if (elapsed < _minRequestInterval)
            {
                var delay = _minRequestInterval - elapsed;
                await Task.Delay(delay);
            }
            _lastRequestTime = DateTime.UtcNow;
        }

        private void CacheResult(string key, VirusTotalResult result)
        {
            if (result == null) return;
            lock (_cacheLock)
            {
                _cache[key] = result;
            }
        }

        private VirusTotalResult ParseHashResponse(string json, string hashValue)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var data = root.GetProperty("data");
                var attributes = data.GetProperty("attributes");
                var stats = attributes.GetProperty("last_analysis_stats");

                var result = new VirusTotalResult
                {
                    Indicator = hashValue,
                    IndicatorType = "hash",
                    Malicious = stats.GetProperty("malicious").GetInt32(),
                    Suspicious = stats.GetProperty("suspicious").GetInt32(),
                    Harmless = stats.GetProperty("harmless").GetInt32(),
                    Undetected = stats.GetProperty("undetected").GetInt32(),
                };

                // Parse malicious engine names
                if (attributes.TryGetProperty("last_analysis_results", out var engines))
                {
                    foreach (var engine in engines.EnumerateObject())
                    {
                        var cat = engine.Value.GetProperty("category").GetString();
                        if (cat == "malicious")
                        {
                            string engineName = engine.Name;
                            string label = engine.Value.TryGetProperty("result", out var r) ? r.GetString() : "";
                            result.MaliciousEngineNames.Add($"{engineName}: {label}");
                            if (result.ThreatLabel == null) result.ThreatLabel = label;
                        }
                    }
                }

                // Popular threat label
                if (attributes.TryGetProperty("popular_threat_classification", out var ptc))
                {
                    if (ptc.TryGetProperty("suggested_threat_label", out var stl))
                        result.ThreatLabel = stl.GetString();
                }

                result.Permalink = $"https://www.virustotal.com/gui/file/{hashValue}";
                return result;
            }
            catch { return null; }
        }

        private VirusTotalResult ParseIpResponse(string json, string ipAddress)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var data = root.GetProperty("data");
                var attributes = data.GetProperty("attributes");
                var stats = attributes.GetProperty("last_analysis_stats");

                var result = new VirusTotalResult
                {
                    Indicator = ipAddress,
                    IndicatorType = "ip",
                    Malicious = stats.GetProperty("malicious").GetInt32(),
                    Suspicious = stats.GetProperty("suspicious").GetInt32(),
                    Harmless = stats.GetProperty("harmless").GetInt32(),
                    Undetected = stats.GetProperty("undetected").GetInt32(),
                };

                // Country and ASN
                if (attributes.TryGetProperty("country", out var country))
                    result.Country = country.GetString();
                if (attributes.TryGetProperty("as_owner", out var asOwner))
                    result.ASNOwner = asOwner.GetString();
                if (attributes.TryGetProperty("asn", out var asn) && asn.ValueKind == JsonValueKind.Number)
                    result.ASN = asn.GetInt32();

                result.Permalink = $"https://www.virustotal.com/gui/ip-address/{ipAddress}";
                return result;
            }
            catch { return null; }
        }

        private VirusTotalResult ParseDomainResponse(string json, string domain)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var data = root.GetProperty("data");
                var attributes = data.GetProperty("attributes");
                var stats = attributes.GetProperty("last_analysis_stats");

                var result = new VirusTotalResult
                {
                    Indicator = domain,
                    IndicatorType = "domain",
                    Malicious = stats.GetProperty("malicious").GetInt32(),
                    Suspicious = stats.GetProperty("suspicious").GetInt32(),
                    Harmless = stats.GetProperty("harmless").GetInt32(),
                    Undetected = stats.GetProperty("undetected").GetInt32(),
                };

                result.Permalink = $"https://www.virustotal.com/gui/domain/{domain}";
                return result;
            }
            catch { return null; }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _http?.Dispose();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }

    /// <summary>
    /// DNS mapping enriched with VirusTotal reputation data.
    /// </summary>
    public class VirusTotalEnrichedDns
    {
        public DnsNameMapping DnsMapping { get; set; }
        public VirusTotalResult IpResult { get; set; }
        public VirusTotalResult DomainResult { get; set; }

        public bool HasMaliciousIndicator =>
            (IpResult?.IsMalicious == true) || (DomainResult?.IsMalicious == true);

        public string HighestRisk =>
            (IpResult?.RiskLevel == "CRITICAL" || DomainResult?.RiskLevel == "CRITICAL") ? "CRITICAL" :
            (IpResult?.RiskLevel == "HIGH" || DomainResult?.RiskLevel == "HIGH") ? "HIGH" :
            (IpResult?.RiskLevel == "MEDIUM" || DomainResult?.RiskLevel == "MEDIUM") ? "MEDIUM" :
            (IpResult?.IsMalicious == true || DomainResult?.IsMalicious == true) ? "LOW" : "CLEAN";

        public override string ToString()
        {
            return $"{DnsMapping.Query} -> {DnsMapping.Destination} " +
                   $"[IP: {IpResult?.RiskLevel ?? "?"} | Domain: {DomainResult?.RiskLevel ?? "?"}]";
        }
    }
}
