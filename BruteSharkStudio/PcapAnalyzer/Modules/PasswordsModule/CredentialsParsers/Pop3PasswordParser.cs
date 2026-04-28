// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// POP3 Password Parser for BruteShark Studio.
// Extracts cleartext POP3 credentials (port 110/995).
// POP3 authentication: USER <username> + PASS <password> in cleartext.

using System;
using System.Text.RegularExpressions;

namespace PcapAnalyzer
{
    public class Pop3PasswordParser : IPasswordParser
    {
        // POP3 USER command: "USER username\r\n"
        private static readonly Regex UserRegex = new Regex(
            @"^USER\s+(?<Username>\S+)", 
            RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

        // POP3 PASS command: "PASS password\r\n"
        private static readonly Regex PassRegex = new Regex(
            @"^PASS\s+(?<Password>\S+)", 
            RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

        // POP3 APOP auth: APOP username md5hash
        private static readonly Regex ApopRegex = new Regex(
            @"^APOP\s+(?<Username>\S+)\s+(?<Hash>\S+)",
            RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

        // Challenge from server: +OK <timestamp@domain> challenge
        private static readonly Regex ChallengeRegex = new Regex(
            @"^\+OK\s+<(?<Challenge>[^>]+)>",
            RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

        public NetworkLayerObject Parse(UdpPacket udpPacket) => null;
        public NetworkLayerObject Parse(TcpPacket tcpPacket) => null;

        public NetworkLayerObject Parse(TcpSession tcpSession)
        {
            if (tcpSession.Data == null || tcpSession.Data.Length < 10) return null;

            try
            {
                string session = System.Text.Encoding.ASCII.GetString(tcpSession.Data);

                // Try APOP first (more common on modern servers)
                var apopMatch = ApopRegex.Match(session);
                if (apopMatch.Success)
                {
                    // Try to extract the challenge from server greeting
                    string challenge = "";
                    var chalMatch = ChallengeRegex.Match(session);
                    if (chalMatch.Success)
                        challenge = chalMatch.Groups["Challenge"].Value;

                    string hashcatFormat = string.IsNullOrEmpty(challenge) 
                        ? $"$apop${apopMatch.Groups["Username"].Value}${apopMatch.Groups["Hash"].Value}"
                        : $"$apop${apopMatch.Groups["Hash"].Value}${challenge}";

                    return new CramMd5Hash
                    {
                        Protocol = "POP3",
                        HashType = "POP3 APOP",
                        Hash = hashcatFormat,
                        Challenge = challenge,
                        Source = tcpSession.SourceIp,
                        Destination = tcpSession.DestinationIp
                    };
                }

                // Try cleartext USER/PASS
                var userMatch = UserRegex.Match(session);
                var passMatch = PassRegex.Match(session);

                if (userMatch.Success && passMatch.Success)
                {
                    return new NetworkPassword
                    {
                        Protocol = "POP3",
                        Username = userMatch.Groups["Username"].Value,
                        Password = passMatch.Groups["Password"].Value,
                        Source = tcpSession.SourceIp,
                        Destination = tcpSession.DestinationIp
                    };
                }
            }
            catch { }

            return null;
        }
    }
}
