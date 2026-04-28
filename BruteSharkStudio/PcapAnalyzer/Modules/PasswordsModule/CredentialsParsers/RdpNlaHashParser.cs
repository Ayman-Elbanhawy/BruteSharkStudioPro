// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// RDP NLA (Network Level Authentication) hash parser.
// Extracts NetNTLMv2 hashes from RDP NLA handshake packets (port 3389).
// Based on PCredz RDP extraction algorithm by Laurent Gaffie.
//
// RDP NLA wraps a CredSSP → SPNEGO → NTLMSSP exchange over TLS/SSL.
// The NTLM authentication is embedded in the NLA negotiation.

using System;
using System.Linq;
using System.Text;

namespace PcapAnalyzer
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // Ported from PCredz RDP NLA extraction algorithm.
    public class RdpNlaHashParser : IPasswordParser
    {
        // NTLMSSP signature bytes
        private static readonly byte[] NtlmsspSignature = new byte[] 
            { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00 };

        // NTLM message types
        private const int NtlmType1 = 1;
        private const int NtlmType2 = 2;
        private const int NtlmType3 = 3;

        public NetworkLayerObject Parse(UdpPacket udpPacket) => null;

        public NetworkLayerObject Parse(TcpPacket tcpPacket)
        {
            return ExtractNtlmFromPacket(tcpPacket.Data, tcpPacket.SourceIp, 
                tcpPacket.DestinationIp, tcpPacket.SourcePort, tcpPacket.DestinationPort);
        }

        public NetworkLayerObject Parse(TcpSession tcpSession)
        {
            // Search through entire TCP stream for NTLMSSP handshake
            var data = tcpSession.Data;
            if (data == null || data.Length < 50) return null;

            int offset = 0;
            byte[] ntlmChallenge = null;
            string challengeHex = null;

            // Find Type 2 (Challenge) first
            while (offset < data.Length - 12)
            {
                int sigPos = Utilities.SearchForSubarray(data, NtlmsspSignature, offset);
                if (sigPos < 0) break;

                if (sigPos + 20 > data.Length) break;

                int msgType = BitConverter.ToInt32(data, sigPos + 8);
                if (msgType == NtlmType2 && sigPos + 32 <= data.Length)
                {
                    ntlmChallenge = new byte[8];
                    Array.Copy(data, sigPos + 24, ntlmChallenge, 0, 8);
                    challengeHex = BitConverter.ToString(ntlmChallenge).Replace("-", "").ToUpper();
                }
                offset = sigPos + 12;
            }

            // Find Type 3 (Response)
            offset = 0;
            while (offset < data.Length - 12)
            {
                int sigPos = Utilities.SearchForSubarray(data, NtlmsspSignature, offset);
                if (sigPos < 0) break;

                if (sigPos + 64 > data.Length) break;

                int msgType = BitConverter.ToInt32(data, sigPos + 8);
                if (msgType == NtlmType3)
                {
                    // Parse NTLM Type 3 message fields
                    int lmLen = BitConverter.ToUInt16(data, sigPos + 12);
                    int lmOff = BitConverter.ToUInt16(data, sigPos + 16);
                    int ntLen = BitConverter.ToUInt16(data, sigPos + 20);
                    int ntOff = BitConverter.ToUInt16(data, sigPos + 24);
                    int domLen = BitConverter.ToUInt16(data, sigPos + 28);
                    int domOff = BitConverter.ToUInt16(data, sigPos + 32);
                    int usrLen = BitConverter.ToUInt16(data, sigPos + 36);
                    int usrOff = BitConverter.ToUInt16(data, sigPos + 40);

                    string domain = "", user = "", lmResp = "", ntResp = "";
                    
                    if (domOff + domLen <= data.Length - sigPos && domLen > 0)
                        domain = Encoding.Unicode.GetString(data, sigPos + domOff, domLen).Replace("\0", "");
                    
                    if (usrOff + usrLen <= data.Length - sigPos && usrLen > 0)
                        user = Encoding.Unicode.GetString(data, sigPos + usrOff, usrLen).Replace("\0", "");
                    
                    if (lmOff + lmLen <= data.Length - sigPos && lmLen > 0)
                        lmResp = BitConverter.ToString(data, sigPos + lmOff, Math.Min(lmLen, data.Length - sigPos - lmOff)).Replace("-", "");
                    
                    if (ntOff + ntLen <= data.Length - sigPos && ntLen > 0)
                        ntResp = BitConverter.ToString(data, sigPos + ntOff, Math.Min(ntLen, data.Length - sigPos - ntOff)).Replace("-", "");

                    string hashType = ntResp.Length > 48 ? "NTLMv2" : "NTLMv1";
                    string hashValue = ntResp.Length > 48 ? ntResp.Substring(0, 48) + "..." : ntResp;

                    if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(ntResp))
                    {
                        string hashcatFormat = ntResp.Length > 48
                            ? $"{user}::{domain}:{challengeHex ?? "0000000000000000"}:{ntResp.Substring(0, 32)}:{ntResp.Substring(32)}"
                            : $"{user}::{domain}:{lmResp}:{ntResp}:{challengeHex ?? "0000000000000000"}";

                        return new NtlmHash
                        {
                            Protocol = "RDP NLA",
                            HashType = hashType,
                            User = user,
                            Domain = domain,
                            Hash = hashcatFormat,
                            Challenge = challengeHex ?? "",
                            NtHash = ntResp,
                            LmHash = lmResp,
                            Source = tcpSession.SourceIp,
                            Destination = tcpSession.DestinationIp
                        };
                    }
                }
                offset = sigPos + 12;
            }

            return null;
        }

        private NetworkLayerObject ExtractNtlmFromPacket(byte[] data, string srcIp, 
            string dstIp, int srcPort, int dstPort)
        {
            if (data == null || data.Length < 30) return null;

            int sigPos = Utilities.SearchForSubarray(data, NtlmsspSignature);
            if (sigPos < 0) return null;

            int msgType = BitConverter.ToInt32(data, sigPos + 8);
            if (msgType == NtlmType2 && sigPos + 32 <= data.Length)
            {
                // Just capture the challenge for later use
                // The actual hash extraction happens in TcpSession parsing
                byte[] challenge = new byte[8];
                Array.Copy(data, sigPos + 24, challenge, 0, 8);
                string challengeHex = BitConverter.ToString(challenge).Replace("-", "").ToUpper();
                
                return new NtlmHash
                {
                    Protocol = "RDP NLA Challenge",
                    HashType = "NTLM Challenge",
                    Challenge = challengeHex,
                    Source = srcIp,
                    Destination = dstIp
                };
            }

            return null;
        }
    }
}
