using System;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace BruteSharkDesktop
{
    /// <summary>
    /// Simple hex dump viewer — paste raw hex or select bytes to view.
    /// </summary>
    public class PacketHexViewerUserControl : UserControl
    {
        private RichTextBox hexBox;
        private RichTextBox asciiBox;
        private TextBox inputBox;
        private Button applyButton;
        private Label offsetLabel;

        public PacketHexViewerUserControl()
        {
            this.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);
            this.Dock = DockStyle.Fill;

            var topPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 40,
                BackColor = Color.FromArgb(0x25, 0x25, 0x40)
            };

            inputBox = new TextBox
            {
                Location = new Point(8, 8),
                Width = 400,
                Height = 24,
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                BorderStyle = BorderStyle.FixedSingle,
                PlaceholderText = "Paste hex bytes (e.g. 48 65 6C 6C 6F) or text..."
            };

            applyButton = new Button
            {
                Text = "Parse",
                Location = new Point(416, 7),
                Width = 70,
                Height = 26,
                BackColor = Color.FromArgb(0x45, 0x47, 0x5A),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                FlatStyle = FlatStyle.Flat
            };
            applyButton.Click += (s, e) => ParseHex(inputBox.Text);

            topPanel.Controls.Add(inputBox);
            topPanel.Controls.Add(applyButton);

            offsetLabel = new Label
            {
                Location = new Point(8, 44),
                Width = 70,
                Height = 20,
                Text = "Offset(h)",
                ForeColor = Color.FromArgb(0x89, 0xB4, 0xFA),
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                Font = new Font("Consolas", 9f, FontStyle.Bold)
            };

            hexBox = new RichTextBox
            {
                Location = new Point(78, 42),
                Width = 520,
                Height = 300,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                Font = new Font("Consolas", 10f),
                BackColor = Color.FromArgb(0x25, 0x25, 0x40),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                ReadOnly = true,
                WordWrap = false,
                BorderStyle = BorderStyle.None
            };

            asciiBox = new RichTextBox
            {
                Location = new Point(600, 42),
                Width = 160,
                Height = 300,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Right,
                Font = new Font("Consolas", 10f),
                BackColor = Color.FromArgb(0x25, 0x25, 0x40),
                ForeColor = Color.FromArgb(0xA6, 0xE3, 0xA1),
                ReadOnly = true,
                WordWrap = false,
                BorderStyle = BorderStyle.None
            };

            var hexLabel = new Label
            {
                Text = "HEX",
                Location = new Point(78, 24),
                Width = 50,
                ForeColor = Color.FromArgb(0x89, 0xB4, 0xFA),
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                Font = new Font("Segoe UI", 9f, FontStyle.Bold)
            };

            var asciiLabel = new Label
            {
                Text = "ASCII",
                Location = new Point(600, 24),
                Width = 50,
                ForeColor = Color.FromArgb(0xA6, 0xE3, 0xA1),
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                Font = new Font("Segoe UI", 9f, FontStyle.Bold)
            };

            this.Controls.Add(topPanel);
            this.Controls.Add(hexBox);
            this.Controls.Add(asciiBox);
            this.Controls.Add(hexLabel);
            this.Controls.Add(asciiLabel);
            this.Controls.Add(offsetLabel);
        }

        public void ParseHex(string input)
        {
            hexBox.Clear();
            asciiBox.Clear();

            input = input.Replace(" ", "").Replace("\r", "").Replace("\n", "").Replace("0x", "").Replace(",", "");
            if (input.Length % 2 != 0) input = input.Substring(0, input.Length - 1);

            var sbHex = new StringBuilder();
            var sbAscii = new StringBuilder();
            for (int i = 0; i < input.Length; i += 2)
            {
                if (i % 32 == 0)
                {
                    if (i > 0) { sbHex.AppendLine(); sbAscii.AppendLine(); }
                    sbHex.Append($"{i / 2:X8}  ");
                }
                try
                {
                    byte b = Convert.ToByte(input.Substring(i, 2), 16);
                    sbHex.Append($"{b:X2} ");
                    char c = b >= 32 && b < 127 ? (char)b : '.';
                    sbAscii.Append(c);
                }
                catch { sbHex.Append("?? "); sbAscii.Append('?'); }
            }

            hexBox.Text = sbHex.ToString();
            asciiBox.Text = sbAscii.ToString();

            // Sync scroll
            hexBox.VScroll += (s, e) =>
            {
                var pos = Win32.GetScrollPos(hexBox.Handle, Win32.SB_VERT);
                Win32.SetScrollPos(asciiBox.Handle, Win32.SB_VERT, pos, true);
                Win32.SendMessage(asciiBox.Handle, Win32.WM_VSCROLL, (IntPtr)(4 + 0x10000 * pos), IntPtr.Zero);
            };
        }

        public void LoadBytes(byte[] data)
        {
            if (data == null || data.Length == 0) return;
            ParseHex(BitConverter.ToString(data).Replace("-", " "));
        }
    }

    internal static class Win32
    {
        public const int SB_VERT = 1;
        public const int WM_VSCROLL = 0x115;
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern int GetScrollPos(IntPtr hWnd, int nBar);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern int SetScrollPos(IntPtr hWnd, int nBar, int nPos, bool bRedraw);
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
    }
}
