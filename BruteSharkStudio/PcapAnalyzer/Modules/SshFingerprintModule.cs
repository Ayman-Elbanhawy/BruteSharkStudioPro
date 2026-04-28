// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// SSH Host Key Fingerprinting Module for BruteShark Studio.
// Extracts SSH server host keys from SSH handshake (port 22)
// and tracks key changes for MITM detection.
//
// SSH handshake (RFC 4253):
//   Server: SSH-2.0-OpenSSH_8.9\r\n
//   Client: SSH-2.0-OpenSSH_8.9\r\n
//   → Key Exchange Init (SSH_MSG_KEXINIT)
//   → Diffie-Hellman Key Exchange
//   → Server sends host key (SSH_MSG_KEXDH_REPLY)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PcapAnalyzer
{
    public class SshFingerprintModule : IModule
    {
        public string Name => "SSH Host Key Fingerprinting";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        // Track known server keys: IP:Port → key fingerprint
        private readonly ConcurrentDictionary<string, SshServerRecord> _knownServers;

        public SshFingerprintModule()
        {
            _knownServers = new ConcurrentDictionary<string, SshServerRecord>();
        }

        public void Analyze(UdpPacket udpPacket) { }
        public void Analyze(UdpStream udpStream) { }
        public void Analyze(TcpPacket tcpPacket) { }
        public void Analyze(TcpSession tcpSession)
        {
            ExtractSshInfo(tcpSession);
        }

        private void ExtractSshInfo(TcpSession session)
        {
            if (session.Data == null || session.Data.Length < 20) return;

            try
            {
                string data = Encoding.ASCII.GetString(session.Data);

                // Extract SSH banner
                if (data.StartsWith("SSH-"))
                {
                    int bannerEnd = data.IndexOf('\n');
                    string banner = bannerEnd > 0 ? data.Substring(0, bannerEnd).Trim() : data.Substring(0, Math.Min(80, data.Length));

                    // Parse version
                    string version = banner.Length > 7 ? banner.Substring(4) : banner;

                    EmitFinding(new SshServerFingerprint
                    {
                        ServerIp = session.DestinationIp,
                        ServerPort = session.DestinationPort,
                        ClientIp = session.SourceIp,
                        Banner = banner,
                        SoftwareVersion = version,
                        KeyType = "SSH Banner",
                        KeyFingerprint = ""
                    });
                }

                // Look for SSH host key in binary key exchange
                // SSH_MSG_KEXDH_REPLY = 0x1F (31) or SSH_MSG_KEX_ECDH_REPLY = 0x1F
                // The host key follows: string key_type, bytes key_data
                SearchForHostKey(session.Data, session);
            }
            catch { }
        }

        private void SearchForHostKey(byte[] data, TcpSession session)
        {
            // Search for SSH host key types in the binary stream
            var keyTypes = new Dictionary<string, byte[]>
            {
                ["ssh-rsa"] = Encoding.ASCII.GetBytes("ssh-rsa"),
                ["ssh-ed25519"] = Encoding.ASCII.GetBytes("ssh-ed25519"),
                ["ecdsa-sha2-nistp256"] = Encoding.ASCII.GetBytes("ecdsa-sha2-nistp256"),
                ["ecdsa-sha2-nistp384"] = Encoding.ASCII.GetBytes("ecdsa-sha2-nistp384"),
                ["ecdsa-sha2-nistp521"] = Encoding.ASCII.GetBytes("ecdsa-sha2-nistp521"),
                ["ssh-dss"] = Encoding.ASCII.GetBytes("ssh-dss"),
            };

            foreach (var kvp in keyTypes)
            {
                int pos = Utilities.SearchForSubarray(data, kvp.Value);
                if (pos >= 0 && pos + kvp.Value.Length + 4 < data.Length)
                {
                    // Read the 4-byte length prefix that follows the key type
                    int keyLenOffset = pos + kvp.Value.Length;
                    int keyLen = (data[keyLenOffset] << 24) | (data[keyLenOffset + 1] << 16) |
                                 (data[keyLenOffset + 2] << 8) | data[keyLenOffset + 3];

                    if (keyLen > 0 && keyLen < 8192 && keyLenOffset + 4 + keyLen <= data.Length)
                    {
                        byte[] keyBytes = new byte[keyLen];
                        Array.Copy(data, keyLenOffset + 4, keyBytes, 0, keyLen);

                        using var sha256 = SHA256.Create();
                        string fingerprint = "SHA256:" + Convert.ToBase64String(sha256.ComputeHash(keyBytes));

                        string serverKey = $"{session.DestinationIp}:{session.DestinationPort}";

                        // Check for key change (MITM detection)
                        var record = _knownServers.GetOrAdd(serverKey, _ => new SshServerRecord
                        {
                            Server = serverKey,
                            FirstSeen = DateTime.UtcNow
                        });

                        if (record.Fingerprint != null && record.Fingerprint != fingerprint)
                        {
                            EmitFinding(new SshServerFingerprint
                            {
                                ServerIp = session.DestinationIp,
                                ServerPort = session.DestinationPort,
                                ClientIp = session.SourceIp,
                                KeyType = kvp.Key,
                                KeyFingerprint = fingerprint,
                                Banner = "⚠ KEY CHANGED — Possible MITM!",
                                SoftwareVersion = $"Previous fingerprint: {record.Fingerprint}"
                            });
                        }

                        record.Fingerprint = fingerprint;
                        record.LastSeen = DateTime.UtcNow;

                        EmitFinding(new SshServerFingerprint
                        {
                            ServerIp = session.DestinationIp,
                            ServerPort = session.DestinationPort,
                            ClientIp = session.SourceIp,
                            KeyType = kvp.Key,
                            KeyFingerprint = fingerprint,
                            Banner = $"SSH Server Key ({kvp.Key})",
                            SoftwareVersion = $"First seen: {record.FirstSeen}"
                        });
                    }
                }
            }
        }

        private void EmitFinding(SshServerFingerprint fp)
        {
            ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs
            {
                ParsedItem = fp
            });
        }

        private class SshServerRecord
        {
            public string Server { get; set; }
            public string Fingerprint { get; set; }
            public DateTime FirstSeen { get; set; }
            public DateTime LastSeen { get; set; }
        }
    }

    public class SshServerFingerprint : NetworkLayerObject
    {
        public string ServerIp { get; set; }
        public int ServerPort { get; set; }
        public string ClientIp { get; set; }
        public string KeyType { get; set; }
        public string KeyFingerprint { get; set; }
        public string Banner { get; set; }
        public string SoftwareVersion { get; set; }

        public override string ToString()
            => $"SSH: {ServerIp}:{ServerPort} {KeyType} {KeyFingerprint} [{Banner}]";
    }
}
