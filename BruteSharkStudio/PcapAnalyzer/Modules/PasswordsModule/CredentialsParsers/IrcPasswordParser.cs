using System;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapAnalyzer
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // Extracts cleartext credentials from IRC protocol traffic.
    // Handles NICK, USER, and PASS commands per RFC 1459.
    // Ported from PCredz's cleartext extraction algorithm.
    public class IrcPasswordParser : IPasswordParser
    {
        // IRC messages are lines ending with \r\n
        // NICK <nickname>
        // USER <username> <hostname> <servername> :<realname>
        // PASS <password>

        private static readonly Regex NickRegex = new Regex(
            @"^NICK\s+(?<Nick>\S+)", 
            RegexOptions.IgnoreCase | RegexOptions.Multiline);

        private static readonly Regex UserRegex = new Regex(
            @"^USER\s+(?<User>\S+)", 
            RegexOptions.IgnoreCase | RegexOptions.Multiline);

        private static readonly Regex PassRegex = new Regex(
            @"^PASS\s+(?<Password>.+?)(?:\r\n|\r|\n)", 
            RegexOptions.IgnoreCase | RegexOptions.Multiline);

        private static readonly Regex IrcOperRegex = new Regex(
            @"^OPER\s+(?<User>\S+)\s+(?<Password>\S+)",
            RegexOptions.IgnoreCase | RegexOptions.Multiline);

        private static readonly Regex NickServIdentify = new Regex(
            @"^PRIVMSG\s+NickServ\s+:\s*IDENTIFY\s+(?<Password>\S+)",
            RegexOptions.IgnoreCase | RegexOptions.Multiline);

        // IRC servers typically run on ports 6660-7000, 6697 (SSL)
        private static bool IsIrcPort(int port)
        {
            return (port >= 6660 && port <= 6670) || port == 6697 || port == 7000 || port == 194;
        }

        public NetworkLayerObject Parse(UdpPacket udpPacket) => null;

        public NetworkLayerObject Parse(TcpPacket tcpPacket) => null;

        public NetworkLayerObject Parse(TcpSession tcpSession)
        {
            // Quick check: only process likely IRC traffic
            if (!IsIrcPort(tcpSession.SourcePort) && !IsIrcPort(tcpSession.DestinationPort))
                return null;

            try
            {
                string sessionData = Encoding.ASCII.GetString(tcpSession.Data);
                string[] lines = sessionData.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

                string currentNick = null;
                string currentUser = null;

                foreach (string line in lines)
                {
                    string trimmedLine = line.Trim();

                    // NICK command
                    var nickMatch = NickRegex.Match(trimmedLine);
                    if (nickMatch.Success)
                    {
                        currentNick = nickMatch.Groups["Nick"].Value;
                        continue;
                    }

                    // USER command
                    var userMatch = UserRegex.Match(trimmedLine);
                    if (userMatch.Success)
                    {
                        currentUser = userMatch.Groups["User"].Value;
                        continue;
                    }

                    // PASS command
                    var passMatch = PassRegex.Match(trimmedLine);
                    if (passMatch.Success && (currentNick != null || currentUser != null))
                    {
                        string username = currentNick ?? currentUser;
                        string password = passMatch.Groups["Password"].Value.Trim();

                        return new NetworkPassword()
                        {
                            Protocol = "IRC",
                            Username = username,
                            Password = password,
                            Source = tcpSession.SourceIp,
                            Destination = tcpSession.DestinationIp
                        };
                    }

                    // OPER command (IRC operator login)
                    var operMatch = IrcOperRegex.Match(trimmedLine);
                    if (operMatch.Success)
                    {
                        return new NetworkPassword()
                        {
                            Protocol = "IRC OPER",
                            Username = operMatch.Groups["User"].Value,
                            Password = operMatch.Groups["Password"].Value,
                            Source = tcpSession.SourceIp,
                            Destination = tcpSession.DestinationIp
                        };
                    }

                    // NickServ IDENTIFY
                    var nickservMatch = NickServIdentify.Match(trimmedLine);
                    if (nickservMatch.Success)
                    {
                        return new NetworkPassword()
                        {
                            Protocol = "IRC NickServ",
                            Username = currentNick ?? "(unknown)",
                            Password = nickservMatch.Groups["Password"].Value,
                            Source = tcpSession.SourceIp,
                            Destination = tcpSession.DestinationIp
                        };
                    }
                }
            }
            catch { }

            return null;
        }
    }
}
