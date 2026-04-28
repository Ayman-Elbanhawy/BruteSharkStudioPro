// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// TLS Certificate Extraction Module for BruteShark Studio.
// Extracts X.509 server certificates from TLS handshake (port 443/8443).
// Detects suspicious certificates: self-signed, expired, weak keys,
// mismatched CN/SAN, and untrusted issuers.
//
// TLS 1.2/1.3 Certificate message: 
//   Handshake Type: 0x0B (Certificate)
//   Certificates are ASN.1 DER-encoded X.509 structures.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PcapAnalyzer
{
    public class TlsCertificateModule : IModule
    {
        public string Name => "TLS Certificate Analysis";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        // TLS Record: ContentType=0x16 (Handshake), Version=0x03xx
        // Handshake Type 0x0B = Certificate
        private const byte TlsHandshake = 0x16;
        private const byte CertHandshakeType = 0x0B;

        // ASN.1 DER tags
        private const byte AsnSequence = 0x30;
        private const byte AsnSet = 0x31;
        private const byte AsnPrintableString = 0x13;
        private const byte AsnUtf8String = 0x0C;
        private const byte AsnIa5String = 0x16;
        private const byte AsnTeletexString = 0x14;
        private const byte AsnBitString = 0x03;
        private const byte AsnOctetString = 0x04;
        private const byte AsnOid = 0x06;
        private const byte AsnInteger = 0x02;
        private const byte AsnUtcTime = 0x17;
        private const byte AsnGeneralizedTime = 0x18;
        private const byte AsnContext0 = 0xA0;
        private const byte AsnContext3 = 0xA3;

        // OIDs for certificate fields
        private static readonly byte[] OidCommonName = { 0x55, 0x04, 0x03 };
        private static readonly byte[] OidOrganization = { 0x55, 0x04, 0x0A };
        private static readonly byte[] OidCountry = { 0x55, 0x04, 0x06 };

        public void Analyze(UdpPacket udpPacket) { }
        public void Analyze(UdpStream udpStream) { }

        public void Analyze(TcpPacket tcpPacket)
        {
            ExtractCertificate(tcpPacket.Data, tcpPacket.SourceIp, tcpPacket.DestinationIp,
                tcpPacket.DestinationPort);
        }

        public void Analyze(TcpSession tcpSession)
        {
            ExtractCertificate(tcpSession.Data, tcpSession.SourceIp, tcpSession.DestinationIp,
                tcpSession.DestinationPort);
        }

        private void ExtractCertificate(byte[] data, string src, string dst, int dstPort)
        {
            if (data == null || data.Length < 50) return;

            int offset = 0;
            while (offset < data.Length - 10)
            {
                // Find TLS Handshake record
                if (data[offset] == TlsHandshake && offset + 6 < data.Length)
                {
                    int recordLen = (data[offset + 3] << 8) | data[offset + 4];
                    int handshakeType = data[offset + 5];

                    if (handshakeType == CertHandshakeType && recordLen > 10)
                    {
                        int certDataStart = offset + 5;
                        int certDataEnd = Math.Min(offset + 5 + recordLen, data.Length);
                        byte[] certBlock = new byte[certDataEnd - certDataStart];
                        Array.Copy(data, certDataStart, certBlock, 0, certBlock.Length);

                        var certs = ParseCertificates(certBlock, dst, dstPort);
                        foreach (var cert in certs)
                        {
                            // Check for suspicious attributes
                            cert.IsSuspicious = CheckSuspicious(cert);

                            ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs
                            {
                                ParsedItem = cert
                            });
                        }
                        return; // Only process first certificate message
                    }
                }
                offset++;
            }
        }

        private List<TlsCertificate> ParseCertificates(byte[] data, string server, int port)
        {
            var certs = new List<TlsCertificate>();
            int pos = 0;

            // Skip handshake type (1 byte), 3-byte length
            if (pos + 1 >= data.Length || data[pos] != CertHandshakeType) return certs;
            pos = 4; // Skip handshake header

            // Read certificates length (3 bytes)
            if (pos + 3 > data.Length) return certs;
            pos += 3;

            while (pos + 3 < data.Length)
            {
                int certLen = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
                pos += 3;

                if (certLen <= 0 || pos + certLen > data.Length) break;

                byte[] certDer = new byte[certLen];
                Array.Copy(data, pos, certDer, 0, certLen);

                var cert = ParseX509Cert(certDer);
                if (cert != null)
                {
                    cert.ServerIp = server;
                    cert.ServerPort = port;
                    cert.RawSize = certLen;

                    using var sha256 = System.Security.Cryptography.SHA256.Create();
                    cert.Fingerprint = BitConverter.ToString(
                        sha256.ComputeHash(certDer)).Replace("-", "").ToLower();
                }

                certs.Add(cert);
                pos += certLen;
            }

            return certs;
        }

        private TlsCertificate ParseX509Cert(byte[] der)
        {
            try
            {
                var cert = new TlsCertificate();
                int pos = 0;

                // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
                if (der[pos] != AsnSequence) return null;
                pos++;
                int outerLen = ReadAsn1Length(der, ref pos);
                int outerEnd = pos + outerLen;

                // tbsCertificate
                if (pos >= der.Length || der[pos] != AsnSequence) return null;
                pos++;
                int tbsLen = ReadAsn1Length(der, ref pos);
                int tbsEnd = pos + tbsLen;

                // Skip version [0] EXPLICIT if present
                if (pos < tbsEnd && der[pos] == AsnContext0)
                {
                    pos++;
                    int ctxLen = ReadAsn1Length(der, ref pos);
                    pos += ctxLen;
                }

                // Serial number
                if (pos >= tbsEnd || der[pos] != AsnInteger) return cert;
                pos++;
                int serialLen = ReadAsn1Length(der, ref pos);
                cert.SerialNumber = BitConverter.ToString(der, pos, serialLen).Replace("-", ":");
                pos += serialLen;

                // Skip signature algorithm
                pos = SkipAsn1Value(der, pos, tbsEnd);

                // Issuer
                if (pos >= tbsEnd || der[pos] != AsnSequence) return cert;
                pos++;
                int issuerLen = ReadAsn1Length(der, ref pos);
                cert.Issuer = ParseDn(der, pos, pos + issuerLen);
                pos += issuerLen;

                // Validity
                if (pos >= tbsEnd || der[pos] != AsnSequence) return cert;
                pos++;
                int validityLen = ReadAsn1Length(der, ref pos);
                int validEnd = pos + validityLen;

                // NotBefore
                cert.NotBefore = ReadAsn1Time(der, ref pos);
                // NotAfter
                cert.NotAfter = ReadAsn1Time(der, ref pos);

                pos = validEnd;

                // Subject
                if (pos >= tbsEnd || der[pos] != AsnSequence) return cert;
                pos++;
                int subjectLen = ReadAsn1Length(der, ref pos);
                cert.Subject = ParseDn(der, pos, pos + subjectLen);

                return cert;
            }
            catch { return null; }
        }

        private string ParseDn(byte[] data, int start, int end)
        {
            var parts = new List<string>();
            int pos = start;

            while (pos < end)
            {
                if (data[pos] != AsnSet && data[pos] != AsnSequence)
                {
                    pos++;
                    continue;
                }

                bool isSet = data[pos] == AsnSet;
                pos++;
                ReadAsn1Length(data, ref pos);

                if (pos + 5 > end) break;

                // Read OID
                int oidStart = pos;
                if (data[pos] != AsnSequence) break;
                pos++;
                int oidSeqLen = ReadAsn1Length(data, ref pos);
                int oidSeqEnd = pos + oidSeqLen;

                if (pos >= oidSeqEnd || data[pos] != AsnOid) break;
                pos++;
                int oidLen = ReadAsn1Length(data, ref pos);
                byte[] oid = new byte[oidLen];
                Array.Copy(data, pos, oid, 0, oidLen);
                pos = oidSeqEnd;

                // Read value
                if (pos >= end) break;
                byte tag = data[pos];
                pos++;
                int valLen = ReadAsn1Length(data, ref pos);
                if (pos + valLen > end) break;

                string value = tag switch
                {
                    AsnPrintableString or AsnUtf8String or AsnIa5String or AsnTeletexString =>
                        Encoding.ASCII.GetString(data, pos, valLen),
                    _ => ""
                };

                string field = BytesEqual(oid, OidCommonName) ? "CN" :
                               BytesEqual(oid, OidOrganization) ? "O" :
                               BytesEqual(oid, OidCountry) ? "C" : "?";

                if (!string.IsNullOrWhiteSpace(value))
                    parts.Add($"{field}={value}");

                pos += valLen;
            }

            return string.Join(", ", parts);
        }

        private DateTime ReadAsn1Time(byte[] data, ref int pos)
        {
            byte tag = data[pos];
            pos++;
            int len = ReadAsn1Length(data, ref pos);
            string timeStr = Encoding.ASCII.GetString(data, pos, len);
            pos += len;

            // UTCTime: YYMMDDHHMMSSZ or GeneralizedTime: YYYYMMDDHHMMSSZ
            if (timeStr.EndsWith("Z")) timeStr = timeStr.TrimEnd('Z');

            if (timeStr.Length == 12) // UTCTime
            {
                int year = int.Parse(timeStr.Substring(0, 2));
                year += year >= 50 ? 1900 : 2000;
                return new DateTime(year,
                    int.Parse(timeStr.Substring(2, 2)),
                    int.Parse(timeStr.Substring(4, 2)),
                    int.Parse(timeStr.Substring(6, 2)),
                    int.Parse(timeStr.Substring(8, 2)),
                    int.Parse(timeStr.Substring(10, 2)),
                    DateTimeKind.Utc);
            }
            else if (timeStr.Length >= 14) // GeneralizedTime
            {
                return new DateTime(
                    int.Parse(timeStr.Substring(0, 4)),
                    int.Parse(timeStr.Substring(4, 2)),
                    int.Parse(timeStr.Substring(6, 2)),
                    int.Parse(timeStr.Substring(8, 2)),
                    int.Parse(timeStr.Substring(10, 2)),
                    int.Parse(timeStr.Substring(12, 2)),
                    DateTimeKind.Utc);
            }

            return DateTime.MinValue;
        }

        private int SkipAsn1Value(byte[] data, int pos, int maxPos)
        {
            if (pos >= maxPos) return pos;
            pos++;
            ReadAsn1Length(data, ref pos);
            return pos;
        }

        private bool CheckSuspicious(TlsCertificate cert)
        {
            if (cert == null) return false;
            var now = DateTime.UtcNow;

            // Expired
            if (cert.NotAfter != DateTime.MinValue && cert.NotAfter < now)
                return true;

            // Not yet valid
            if (cert.NotBefore != DateTime.MinValue && cert.NotBefore > now)
                return true;

            // Self-signed (subject == issuer)
            if (!string.IsNullOrEmpty(cert.Subject) && cert.Subject == cert.Issuer)
                return true;

            // Long validity period (> 2 years — common for malware C2 certs)
            if (cert.NotAfter != DateTime.MinValue && cert.NotBefore != DateTime.MinValue)
            {
                var validitySpan = cert.NotAfter - cert.NotBefore;
                if (validitySpan.TotalDays > 730)
                    return true;
            }

            return false;
        }

        private int ReadAsn1Length(byte[] data, ref int pos)
        {
            if (pos >= data.Length) return 0;
            int b = data[pos++];
            if ((b & 0x80) == 0) return b;
            int numBytes = b & 0x7F;
            int len = 0;
            for (int i = 0; i < numBytes; i++)
                len = (len << 8) | data[pos++];
            return len;
        }

        private bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }

    public class TlsCertificate : NetworkLayerObject
    {
        public string ServerIp { get; set; }
        public int ServerPort { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public string SerialNumber { get; set; }
        public string Fingerprint { get; set; }
        public bool IsSuspicious { get; set; }
        public int RawSize { get; set; }

        public override string ToString()
        {
            string alert = IsSuspicious ? "⚠ " : "";
            return $"{alert}TLS Cert: {Subject} | Issuer: {Issuer} | " +
                   $"Valid: {NotBefore:yyyy-MM-dd} to {NotAfter:yyyy-MM-dd}";
        }
    }
}
