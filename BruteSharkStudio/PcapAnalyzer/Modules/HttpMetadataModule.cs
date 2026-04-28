// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// HTTP Metadata Extraction Module for BruteShark Studio.
// Extracts full HTTP request/response metadata: URLs, User-Agents,
// Cookies, Referrers, Server headers, content types, status codes.
// Inspired by Zeek (Bro) http.log format.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapAnalyzer
{
    public class HttpMetadataModule : IModule
    {
        public string Name => "HTTP Metadata Extractor";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        // HTTP request line: METHOD /path HTTP/1.1
        private static readonly Regex HttpRequestLine = new Regex(
            @"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/(\d\.\d)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // HTTP response line: HTTP/1.1 200 OK
        private static readonly Regex HttpResponseLine = new Regex(
            @"^HTTP/(\d\.\d)\s+(\d{3})\s+(.*)",
            RegexOptions.Compiled);

        // Common HTTP headers
        private static readonly Regex HostHeader = new Regex(@"^Host:\s*(.+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);
        private static readonly Regex UserAgentHeader = new Regex(@"^User-Agent:\s*(.+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);
        private static readonly Regex CookieHeader = new Regex(@"^Cookie:\s*(.+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);
        private static readonly Regex SetCookieHeader = new Regex(@"^Set-Cookie:\s*(.+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);
        private static readonly Regex RefererHeader = new Regex(@"^Referer:\s*(.+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);
        private static readonly Regex ServerHeader = new Regex(@"^Server:\s*(.+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);
        private static readonly Regex ContentTypeHeader = new Regex(@"^Content-Type:\s*(.+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);
        private static readonly Regex LocationHeader = new Regex(@"^Location:\s*(.+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);
        private static readonly Regex AuthorizationHeader = new Regex(@"^Authorization:\s*(\S+)\s+(.+)?$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);

        public void Analyze(UdpPacket udpPacket) { }
        public void Analyze(UdpStream udpStream) { }

        public void Analyze(TcpPacket tcpPacket)
        {
            ExtractHttpMetadata(tcpPacket.Data, tcpPacket.SourceIp, tcpPacket.DestinationIp,
                tcpPacket.SourcePort, tcpPacket.DestinationPort);
        }

        public void Analyze(TcpSession tcpSession)
        {
            ExtractHttpMetadata(tcpSession.Data, tcpSession.SourceIp, tcpSession.DestinationIp,
                tcpSession.SourcePort, tcpSession.DestinationPort);
        }

        private void ExtractHttpMetadata(byte[] data, string src, string dst, int sp, int dp)
        {
            if (data == null || data.Length < 10) return;

            try
            {
                string text = Encoding.UTF8.GetString(data);

                // Determine if this is an HTTP request or response
                var reqMatch = HttpRequestLine.Match(text);
                HttpTransaction tx = new HttpTransaction
                {
                    SourceIp = src,
                    DestinationIp = dst,
                    SourcePort = sp,
                    DestinationPort = dp,
                    Timestamp = DateTime.UtcNow
                };

                if (reqMatch.Success)
                {
                    tx.Method = reqMatch.Groups[1].Value.ToUpper();
                    tx.Uri = reqMatch.Groups[2].Value;
                    tx.HttpVersion = reqMatch.Groups[3].Value;
                    tx.IsRequest = true;

                    // Extract Host header to build full URL
                    var hostMatch = HostHeader.Match(text);
                    if (hostMatch.Success)
                    {
                        tx.Host = hostMatch.Groups[1].Value.Trim();
                        tx.FullUrl = $"http{(dp == 443 ? "s" : "")}://{tx.Host}{tx.Uri}";
                    }
                    else
                    {
                        tx.FullUrl = tx.Uri;
                    }

                    // Extract User-Agent
                    var uaMatch = UserAgentHeader.Match(text);
                    if (uaMatch.Success)
                        tx.UserAgent = uaMatch.Groups[1].Value.Trim();

                    // Extract Cookie
                    var cookieMatch = CookieHeader.Match(text);
                    if (cookieMatch.Success)
                        tx.RequestCookies = cookieMatch.Groups[1].Value.Trim();

                    // Extract Referer
                    var refMatch = RefererHeader.Match(text);
                    if (refMatch.Success)
                        tx.Referer = refMatch.Groups[1].Value.Trim();

                    // Extract Authorization
                    var authMatch = AuthorizationHeader.Match(text);
                    if (authMatch.Success)
                        tx.AuthScheme = authMatch.Groups[1].Value;
                }

                var respMatch = HttpResponseLine.Match(text);
                if (respMatch.Success)
                {
                    tx.HttpVersion = respMatch.Groups[1].Value;
                    tx.StatusCode = int.Parse(respMatch.Groups[2].Value);
                    tx.StatusMessage = respMatch.Groups[3].Value.Trim();
                    tx.IsRequest = false;

                    // Extract Server
                    var srvMatch = ServerHeader.Match(text);
                    if (srvMatch.Success)
                        tx.Server = srvMatch.Groups[1].Value.Trim();

                    // Extract Set-Cookie
                    var scMatch = SetCookieHeader.Match(text);
                    if (scMatch.Success)
                        tx.ResponseCookies = scMatch.Groups[1].Value.Trim();

                    // Extract Content-Type
                    var ctMatch = ContentTypeHeader.Match(text);
                    if (ctMatch.Success)
                        tx.ContentType = ctMatch.Groups[1].Value.Trim();

                    // Extract Location (redirects)
                    var locMatch = LocationHeader.Match(text);
                    if (locMatch.Success)
                        tx.Location = locMatch.Groups[1].Value.Trim();
                }

                // Only emit if we found useful metadata
                if (tx.Method != null || tx.StatusCode > 0 || tx.UserAgent != null)
                {
                    ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs
                    {
                        ParsedItem = tx
                    });
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Represents a single HTTP request/response transaction.
    /// </summary>
    public class HttpTransaction : NetworkLayerObject
    {
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public DateTime Timestamp { get; set; }

        // Request fields
        public bool IsRequest { get; set; }
        public string Method { get; set; }
        public string Uri { get; set; }
        public string Host { get; set; }
        public string FullUrl { get; set; }
        public string HttpVersion { get; set; }
        public string UserAgent { get; set; }
        public string Referer { get; set; }
        public string RequestCookies { get; set; }
        public string AuthScheme { get; set; }

        // Response fields
        public int StatusCode { get; set; }
        public string StatusMessage { get; set; }
        public string Server { get; set; }
        public string ContentType { get; set; }
        public string ResponseCookies { get; set; }
        public string Location { get; set; }

        public override string ToString()
        {
            if (Method != null)
                return $"HTTP {Method} {FullUrl ?? Uri} [{UserAgent ?? "?"}]";
            if (StatusCode > 0)
                return $"HTTP {StatusCode} {StatusMessage} [{Server ?? "?"}] ({ContentType ?? "?"})";
            return $"HTTP {SourceIp} -> {DestinationIp}:{DestinationPort}";
        }
    }
}
