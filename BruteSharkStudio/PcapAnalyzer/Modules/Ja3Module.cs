// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// JA3 TLS Client Fingerprinting Module
// Based on the JA3 algorithm by Salesforce (https://github.com/salesforce/ja3)
// 
// JA3 gathers the decimal values of the bytes for the following fields in a
// TLS Client Hello packet: SSLVersion, Ciphers, Extensions, EllipticCurves,
// and EllipticCurvePointFormats. These values are concatenated with commas,
// using a "-" to delimit fields, resulting in a fingerprint string.
// An MD5 hash of this string is computed as the final JA3 fingerprint.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PcapAnalyzer
{
    public class Ja3FingerprintModule : IModule
    {
        public string Name => "JA3/JA4 TLS Fingerprinting";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        // TLS Content Type: Handshake = 0x16
        private const byte TlsContentTypeHandshake = 0x16;

        // Handshake Type: Client Hello = 0x01
        private const byte HandshakeTypeClientHello = 0x01;

        // Extension types for JA3
        private const ushort ExtSupportedGroups = 10;
        private const ushort ExtEcPointFormats = 11;
        private const ushort ExtEncryptThenMac = 22;
        private const ushort ExtExtendedMasterSecret = 23;
        private const ushort ExtSessionTicket = 35;
        private const ushort ExtSupportedVersions = 43;
        private const ushort ExtPskKeyExchangeModes = 45;
        private const ushort ExtKeyShare = 51;

        // Known JA3 hashes for common malware/TLS implementations
        // Format: (ja3_hash, description)
        private static readonly Dictionary<string, string> KnownJa3Signatures = new Dictionary<string, string>
        {
            // Malware C2
            ["6734f37431670b3ab4292b8f60f29984"] = "TrickBot",
            ["72a25bd9663386c2ea4ba763feb9c690"] = "Emotet",
            ["a0e9f5d64349fb13191b781eb81fd42e"] = "Cobalt Strike (default)",
            ["b38526b074a2f1f2e4ce9f6e2f1564a1"] = "Meterpreter (default)",
            ["155bf8eaa7bd1f5a95c9e8ce68c1ae2b"] = "Gozi/ISFB",
            ["7bc70dedb4bfe4712aa28e067f64914c"] = "Dridex",
            ["21c450a84eb89e51f530f5cb23500a31"] = "IcedID",
            ["e287aef67bec3abfd548201b3571c4a8"] = "Qakbot",
            ["ce5cc4f042fed66903fcdc46cdc4e3e9"] = "Ursnif",
            ["4c8d1ab0847c8c9195f9e25bef08461b"] = "BazarLoader",
            
            // Common browsers (for comparison)
            ["cd08e31494f9531f560d64c695473da9"] = "Firefox 65",
            ["4c8ce19bd0b057cece70d84d240b0be2"] = "Firefox 110 (Win)",
            ["f4a450cc1fb4fc9bbfc035284c88eede"] = "Chrome 120 (Win)",
            ["51c64c77e60f3980eea90860c93dea23"] = "Chrome 110 (Win)",
            ["0d0c56cb1ef63617f2c9a1985973f8ca"] = "Edge 110 (Win)",
            ["c7958f0a160abd9f22b67bc72d8e11e5"] = "Safari 16.3",
            // Generic Tor
            ["e7bcc1226832f1f7f7e2ecd5fc9f3743"] = "Tor Browser (likely)",
        };

        private HashSet<string> _seenFingerprints = new HashSet<string>();

        public void Analyze(TcpPacket tcpPacket)
        {
            var ja3Result = ComputeJa3(tcpPacket.Data);
            if (ja3Result != null)
            {
                string ja3Hash = ja3Result.Value.hash;
                string ja3String = ja3Result.Value.ja3String;

                // Deduplicate within this analysis run
                string uniqueKey = $"{tcpPacket.SourceIp}:{ja3Hash}";
                if (!_seenFingerprints.Add(uniqueKey))
                    return;

                string knownLabel = KnownJa3Signatures.ContainsKey(ja3Hash) 
                    ? $" [{KnownJa3Signatures[ja3Hash]}]" 
                    : "";

                var fingerprint = new Ja3Fingerprint
                {
                    SourceIp = tcpPacket.SourceIp,
                    DestinationIp = tcpPacket.DestinationIp,
                    SourcePort = tcpPacket.SourcePort,
                    DestinationPort = tcpPacket.DestinationPort,
                    Ja3Hash = ja3Hash,
                    Ja3String = ja3String,
                    KnownSoftware = knownLabel.Trim().TrimStart('[').TrimEnd(']')
                };

                this.ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs()
                {
                    ParsedItem = fingerprint
                });
            }
        }

        public void Analyze(UdpPacket udpPacket) { }
        public void Analyze(TcpSession tcpSession) { }
        public void Analyze(UdpStream udpStream) { }

        /// <summary>
        /// Compute JA3 fingerprint from a raw packet payload.
        /// Returns (ja3_hash, ja3_string) or null if not a TLS Client Hello.
        /// </summary>
        public static (string hash, string ja3String)? ComputeJa3(byte[] packetData)
        {
            try
            {
                if (packetData == null || packetData.Length < 43)
                    return null;

                // Check TLS record header: ContentType = Handshake (0x16)
                if (packetData[0] != TlsContentTypeHandshake)
                    return null;

                // Check TLS version (handshake layer)
                // SSL 3.0 = 0x0300, TLS 1.0 = 0x0301, TLS 1.1 = 0x0302,
                // TLS 1.2 = 0x0303, TLS 1.3 = 0x0304
                int tlsVersion = (packetData[1] << 8) | packetData[2];
                int sslVersion;

                // TLS record length
                int recordLen = (packetData[3] << 8) | packetData[4];

                // Handshake type (should be Client Hello = 0x01)
                if (5 >= packetData.Length || packetData[5] != HandshakeTypeClientHello)
                    return null;

                // Handshake length (3 bytes)
                int handshakeLen = (packetData[6] << 16) | (packetData[7] << 8) | packetData[8];

                // Client Version (at offset 9)
                if (9 + 2 > packetData.Length) return null;
                sslVersion = (packetData[9] << 8) | packetData[10];

                // Skip Random (32 bytes) + Session ID
                int pos = 11 + 32; // after version + random
                if (pos >= packetData.Length) return null;
                int sessionIdLen = packetData[pos];
                pos += 1 + sessionIdLen;

                // Cipher Suites (2 bytes length + list)
                if (pos + 2 > packetData.Length) return null;
                int cipherSuitesLen = (packetData[pos] << 8) | packetData[pos + 1];
                pos += 2;

                if (pos + cipherSuitesLen > packetData.Length) return null;
                var cipherSuites = new List<int>();
                for (int i = 0; i < cipherSuitesLen; i += 2)
                {
                    cipherSuites.Add((packetData[pos + i] << 8) | packetData[pos + i + 1]);
                }
                pos += cipherSuitesLen;

                // Compression Methods
                if (pos >= packetData.Length) return null;
                int compLen = packetData[pos];
                pos += 1 + compLen;

                // Extensions
                var extensions = new List<int>();
                var ellipticCurves = new List<int>();
                var ecPointFormats = new List<int>();

                if (pos + 2 <= packetData.Length)
                {
                    int extensionsLen = (packetData[pos] << 8) | packetData[pos + 1];
                    pos += 2;

                    int extEnd = Math.Min(pos + extensionsLen, packetData.Length);
                    while (pos + 4 <= extEnd)
                    {
                        int extType = (packetData[pos] << 8) | packetData[pos + 1];
                        int extLen = (packetData[pos + 2] << 8) | packetData[pos + 3];
                        pos += 4;

                        extensions.Add(extType);

                        if (extType == ExtSupportedGroups && pos + extLen <= extEnd)
                        {
                            // supported_groups: 2 bytes count + list of 2-byte values
                            int groupsEnd = Math.Min(pos + extLen, extEnd);
                            if (pos + 2 <= groupsEnd)
                            {
                                int groupsListLen = (packetData[pos] << 8) | packetData[pos + 1];
                                int gPos = pos + 2;
                                int gEnd = Math.Min(gPos + groupsListLen, groupsEnd);
                                while (gPos + 2 <= gEnd)
                                {
                                    ellipticCurves.Add((packetData[gPos] << 8) | packetData[gPos + 1]);
                                    gPos += 2;
                                }
                            }
                        }
                        else if (extType == ExtEcPointFormats && pos + extLen <= extEnd)
                        {
                            if (pos < extEnd)
                            {
                                int formatsLen = packetData[pos];
                                int fPos = pos + 1;
                                int fEnd = Math.Min(fPos + formatsLen, extEnd);
                                while (fPos < fEnd)
                                {
                                    ecPointFormats.Add(packetData[fPos]);
                                    fPos++;
                                }
                            }
                        }

                        pos += extLen;
                    }
                }

                // Build JA3 string
                var sb = new StringBuilder();
                sb.Append(sslVersion);
                sb.Append('-');
                sb.Append(cipherSuites.Count > 0 ? string.Join("-", cipherSuites) : "0");
                sb.Append('-');
                sb.Append(extensions.Count > 0 ? string.Join("-", extensions) : "0");
                sb.Append('-');
                sb.Append(ellipticCurves.Count > 0 ? string.Join("-", ellipticCurves) : "0");
                sb.Append('-');
                sb.Append(ecPointFormats.Count > 0 ? string.Join("-", ecPointFormats) : "0");

                string ja3String = sb.ToString();

                // Compute MD5 hash
                using (var md5 = MD5.Create())
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(ja3String);
                    byte[] hashBytes = md5.ComputeHash(inputBytes);
                    string ja3Hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                    return (ja3Hash, ja3String);
                }
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Represents a JA3 TLS fingerprint observation.
    /// </summary>
    public class Ja3Fingerprint : NetworkLayerObject
    {
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string Ja3Hash { get; set; }
        public string Ja3String { get; set; }
        public string KnownSoftware { get; set; }

        public override string ToString()
        {
            string known = string.IsNullOrEmpty(KnownSoftware) ? "" : $" ({KnownSoftware})";
            return $"JA3: {Ja3Hash} {SourceIp} -> {DestinationIp}:{DestinationPort}{known}";
        }
    }
}
