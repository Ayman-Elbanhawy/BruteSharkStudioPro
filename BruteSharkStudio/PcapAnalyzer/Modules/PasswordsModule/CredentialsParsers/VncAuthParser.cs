// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// VNC Authentication parser for BruteShark Studio.
// Extracts VNC challenge-response hashes (port 5900+) for offline cracking.
// Based on PCredz VNC extraction algorithm by Laurent Gaffie.
//
// VNC uses a 16-byte random challenge. The client responds with DES-encrypted
// response using the password as the key. Hashcat mode 24900 supports cracking.

using System;
using System.Text;

namespace PcapAnalyzer
{
    public class VncAuthParser : IPasswordParser
    {
        private static bool IsVncPort(int port) => port >= 5900 && port <= 5999;

        public NetworkLayerObject Parse(UdpPacket udpPacket) => null;

        public NetworkLayerObject Parse(TcpPacket tcpPacket)
        {
            return ExtractVncChallenge(tcpPacket.Data, tcpPacket.SourceIp, 
                tcpPacket.DestinationIp, tcpPacket.SourcePort, tcpPacket.DestinationPort);
        }

        public NetworkLayerObject Parse(TcpSession tcpSession)
        {
            return ExtractVncFromSession(tcpSession.Data, tcpSession.SourceIp, 
                tcpSession.DestinationIp, tcpSession.SourcePort, tcpSession.DestinationPort);
        }

        private NetworkLayerObject ExtractVncChallenge(byte[] data, string src, string dst, int sp, int dp)
        {
            if (data == null || data.Length < 4) return null;

            // VNC handshake: server sends RFB protocol version, client responds with version
            // Server then sends security types, client picks one
            // For VNC auth (type 2): server sends 16-byte challenge, client sends 16-byte response
            
            // Check for VNC challenge: server sends 4 bytes (security result) + 16 bytes (challenge)
            // Security result byte pattern: 0x00 0x00 0x00 0x02 (auth required, type VNC)
            if (data.Length >= 20 && 
                data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x02)
            {
                byte[] challenge = new byte[16];
                Array.Copy(data, 4, challenge, 0, 16);
                string challengeHex = BitConverter.ToString(challenge).Replace("-", "").ToUpper();

                return new CramMd5Hash
                {
                    Protocol = "VNC",
                    HashType = "VNC Challenge",
                    Challenge = challengeHex,
                    Hash = challengeHex,
                    Source = dst,
                    Destination = src
                };
            }

            return null;
        }

        private NetworkLayerObject ExtractVncFromSession(byte[] data, string src, string dst, int sp, int dp)
        {
            if (data == null || data.Length < 50) return null;

            // Search for VNC auth handshake in the stream
            for (int i = 0; i < data.Length - 20; i++)
            {
                // Challenge-response pair: security result + challenge
                if (data[i] == 0x00 && data[i + 1] == 0x00 && 
                    data[i + 2] == 0x00 && data[i + 3] == 0x02 &&
                    i + 20 <= data.Length)
                {
                    byte[] challenge = new byte[16];
                    Array.Copy(data, i + 4, challenge, 0, 16);
                    string challengeHex = BitConverter.ToString(challenge).Replace("-", "").ToUpper();

                    // Look for the response (16 bytes after challenge)
                    // The response from the client follows: 16 bytes DES-encrypted
                    string responseHex = "";
                    if (i + 36 <= data.Length)
                    {
                        byte[] response = new byte[16];
                        Array.Copy(data, i + 20, response, 0, 16);
                        responseHex = BitConverter.ToString(response).Replace("-", "").ToUpper();
                    }

                    // VNC hashcat format: $vnc$*challenge*response (mode 24900)
                    string hashcatHash = $"$vnc$*{challengeHex}*{responseHex}";

                    return new CramMd5Hash
                    {
                        Protocol = "VNC",
                        HashType = "VNC Authentication",
                        Challenge = challengeHex,
                        Hash = hashcatHash,
                        Source = dst,
                        Destination = src
                    };
                }
            }

            return null;
        }
    }
}
