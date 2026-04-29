using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace BruteSharkDesktop
{
    /// <summary>
    /// Protocol statistics dashboard — protocol distribution, top talkers, connection summary.
    /// </summary>
    public class ProtocolStatsUserControl : UserControl
    {
        private DataGridView statsGrid;
        private DataGridView topTalkersGrid;
        private Label summaryLabel;
        private List<Control> barPanels;

        public ProtocolStatsUserControl()
        {
            this.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);
            this.Dock = DockStyle.Fill;
            barPanels = new List<Control>();

            summaryLabel = new Label
            {
                Location = new Point(12, 12),
                AutoSize = true,
                ForeColor = Color.FromArgb(0x89, 0xB4, 0xFA),
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                Font = new Font("Segoe UI", 11f, FontStyle.Bold),
                Text = "Protocol Distribution"
            };

            statsGrid = new DataGridView
            {
                Location = new Point(12, 170),
                Width = 350,
                Height = 250,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left,
                BackgroundColor = Color.FromArgb(0x25, 0x25, 0x40),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                GridColor = Color.FromArgb(0x45, 0x47, 0x5A),
                BorderStyle = BorderStyle.None,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
            };
            statsGrid.Columns.Add("Protocol", "Protocol");
            statsGrid.Columns.Add("Count", "Count");
            statsGrid.Columns.Add("Pct", "%");

            topTalkersGrid = new DataGridView
            {
                Location = new Point(380, 170),
                Width = 450,
                Height = 250,
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                BackgroundColor = Color.FromArgb(0x25, 0x25, 0x40),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                GridColor = Color.FromArgb(0x45, 0x47, 0x5A),
                BorderStyle = BorderStyle.None,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill
            };
            topTalkersGrid.Columns.Add("Source", "Source");
            topTalkersGrid.Columns.Add("Destination", "Destination");
            topTalkersGrid.Columns.Add("Packets", "Packets");

            var topLabel = new Label
            {
                Text = "Top Talkers",
                Location = new Point(380, 148),
                AutoSize = true,
                ForeColor = Color.FromArgb(0x89, 0xB4, 0xFA),
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                Font = new Font("Segoe UI", 10f, FontStyle.Bold)
            };

            this.Controls.Add(summaryLabel);
            this.Controls.Add(statsGrid);
            this.Controls.Add(topTalkersGrid);
            this.Controls.Add(topLabel);

            StyleGrid(statsGrid);
            StyleGrid(topTalkersGrid);
        }

        public void UpdateStats(CommonUi.NetworkContext ctx)
        {
            statsGrid.Rows.Clear();
            topTalkersGrid.Rows.Clear();
            foreach (var p in barPanels) this.Controls.Remove(p);
            barPanels.Clear();

            if (ctx == null) return;

            var protocols = new Dictionary<string, int>();
            foreach (var pw in ctx.Passwords) AddProto(protocols, pw.Protocol);
            foreach (var c in ctx.Connections) AddProto(protocols, "TCP");
            foreach (var v in ctx.VoipCalls) AddProto(protocols, "VoIP/SIP");
            foreach (var h in ctx.HttpTransactions) AddProto(protocols, "HTTP");
            foreach (var d in ctx.DhcpLeases) AddProto(protocols, "DHCP");
            foreach (var t in ctx.TlsCertificates) AddProto(protocols, "TLS");
            foreach (var s in ctx.SshFingerprints) AddProto(protocols, "SSH");

            int total = protocols.Values.Sum();
            if (total == 0) return;

            // Bar chart — simple colored panels
            int y = 40;
            var colors = new[] {
                Color.FromArgb(0x89, 0xB4, 0xFA), Color.FromArgb(0xA6, 0xE3, 0xA1),
                Color.FromArgb(0xFA, 0xB3, 0x87), Color.FromArgb(0xCB, 0xA6, 0xF7),
                Color.FromArgb(0xF3, 0x8B, 0xA8), Color.FromArgb(0x94, 0xE2, 0xD5),
                Color.FromArgb(0xFA, 0xE3, 0x72), Color.FromArgb(0xB4, 0xBE, 0xFE)
            };
            int ci = 0;
            foreach (var kvp in protocols.OrderByDescending(k => k.Value))
            {
                double pct = (double)kvp.Value / total * 100;
                int w = Math.Max(8, (int)(300 * pct / 100));
                var bar = new Panel
                {
                    Location = new Point(12, y), Width = w, Height = 14,
                    BackColor = colors[ci % colors.Length],
                    Tag = $"{kvp.Key}: {kvp.Value} ({pct:F1}%)"
                };
                bar.MouseHover += (s, e) => {
                    var tt = new ToolTip(); tt.SetToolTip(bar, bar.Tag.ToString());
                };
                var label = new Label
                {
                    Text = $"{kvp.Key}: {kvp.Value} ({pct:F1}%)",
                    Location = new Point(w + 20, y - 1),
                    AutoSize = true,
                    ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                    BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                    Font = new Font("Segoe UI", 9f)
                };
                this.Controls.Add(bar);
                this.Controls.Add(label);
                barPanels.Add(bar);
                barPanels.Add(label);
                y += 18;
                ci++;

                statsGrid.Rows.Add(kvp.Key, kvp.Value, $"{pct:F1}");
            }

            // Top talkers from connections
            var talkers = new Dictionary<string, int>();
            foreach (var c in ctx.Connections)
            {
                var key = $"{c.Source} → {c.Destination}";
                if (talkers.ContainsKey(key)) talkers[key]++; else talkers[key] = 1;
            }
            foreach (var kvp in talkers.OrderByDescending(k => k.Value).Take(20))
                topTalkersGrid.Rows.Add(kvp.Key.Split('→')[0].Trim(), kvp.Key.Split('→')[1].Trim(), kvp.Value);

            int nodeCount = 0;
            try { nodeCount = ctx.GetAllNodes().Count; } catch { }
            summaryLabel.Text = $"Connections: {ctx.Connections.Count} | Unique Hosts: {nodeCount} | Passwords: {ctx.Passwords.Count}";
        }

        private void AddProto(Dictionary<string, int> d, string proto)
        {
            if (string.IsNullOrEmpty(proto)) proto = "Unknown";
            if (!d.ContainsKey(proto)) d[proto] = 0;
            d[proto]++;
        }

        private void StyleGrid(DataGridView g)
        {
            g.DefaultCellStyle.BackColor = Color.FromArgb(0x25, 0x25, 0x40);
            g.DefaultCellStyle.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
            g.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(0x45, 0x47, 0x5A);
            g.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
            g.EnableHeadersVisualStyles = false;
        }
    }
}
