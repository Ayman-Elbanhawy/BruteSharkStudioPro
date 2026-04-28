using System;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapAnalyzer
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // Extracts password-like fields from HTTP POST bodies and query strings.
    // Ported from PCredz's HTTP password field detection algorithm.
    // Searches for common password/form parameter names in HTTP requests.
    public class HttpFormPasswordParser : IPasswordParser
    {
        // Regex to match password/credential-like field names in HTTP POST bodies
        // and query parameters. Matches field=value pairs.
        private static readonly Regex PasswordFieldRegex = new Regex(
            @"(?:^|[&\r\n])(password|pass|_password|passwd|session_password|" +
            @"sessionpassword|login_password|loginpassword|form_pw|pw|" +
            @"userpassword|pwd|upassword|passwort|passwrd|wppassword|" +
            @"j_password|admin_password|admin_pass|secret|api_key|token|key|auth|" +
            @"access_token|bearer|apikey|credential)" +
            @"\s*[=:]\s*([^&\s""\r\n]+)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Match username/email fields next to password for context
        private static readonly Regex UsernameNearPassword = new Regex(
            @"(?:username|user|login|email|uname|user_name|userid|uid)\s*[=:]\s*([^&\s""\r\n]+)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex HttpPostRegex = new Regex(
            @"^(POST|PUT|PATCH)\s",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public NetworkLayerObject Parse(UdpPacket udpPacket) => null;

        public NetworkLayerObject Parse(TcpPacket tcpPacket)
        {
            return ExtractFormPassword(tcpPacket.Data, tcpPacket.SourceIp, tcpPacket.DestinationIp);
        }

        public NetworkLayerObject Parse(TcpSession tcpSession)
        {
            if (tcpSession.Data == null || tcpSession.Data.Length < 10)
                return null;

            // Search through the entire TCP session for HTTP POST bodies
            string sessionText = null;
            try { sessionText = Encoding.UTF8.GetString(tcpSession.Data); }
            catch { return null; }

            if (sessionText == null)
                return null;

            // Check if this is an HTTP POST/PUT/PATCH
            var postMatch = HttpPostRegex.Match(sessionText);
            if (!postMatch.Success)
                return null;

            // Find the double-CRLF that separates headers from body
            int bodyStart = sessionText.IndexOf("\r\n\r\n");
            if (bodyStart < 0)
                bodyStart = sessionText.IndexOf("\n\n");
            if (bodyStart < 0)
                return null;

            string body = sessionText.Substring(bodyStart);

            var pwMatch = PasswordFieldRegex.Match(body);
            if (pwMatch.Success)
            {
                string passwordValue = pwMatch.Groups[2].Value;
                
                // Only report if the password value looks meaningful
                if (passwordValue.Length > 2 && passwordValue.Length < 256)
                {
                    // Try to find a nearby username
                    string username = "(unknown)";
                    var userMatch = UsernameNearPassword.Match(body);
                    if (userMatch.Success)
                    {
                        username = userMatch.Groups[1].Value;
                    }

                    return new NetworkPassword()
                    {
                        Protocol = $"HTTP POST ({pwMatch.Groups[1].Value})",
                        Username = username,
                        Password = passwordValue,
                        Source = tcpSession.SourceIp,
                        Destination = tcpSession.DestinationIp
                    };
                }
            }

            return null;
        }

        private NetworkLayerObject ExtractFormPassword(byte[] packetData, string sourceIp, string destinationIp)
        {
            if (packetData == null || packetData.Length < 10)
                return null;

            string text = null;
            try { text = Encoding.UTF8.GetString(packetData); }
            catch { return null; }

            if (text == null)
                return null;

            var pwMatch = PasswordFieldRegex.Match(text);
            if (pwMatch.Success)
            {
                string passwordValue = pwMatch.Groups[2].Value;
                if (passwordValue.Length > 2 && passwordValue.Length < 256)
                {
                    return new NetworkPassword()
                    {
                        Protocol = $"HTTP Form ({pwMatch.Groups[1].Value})",
                        Username = "(from form)",
                        Password = passwordValue,
                        Source = sourceIp,
                        Destination = destinationIp
                    };
                }
            }

            return null;
        }
    }
}
