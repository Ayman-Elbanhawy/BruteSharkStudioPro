using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace BruteSharkDesktop
{
    public class CaptureCompareUserControl : UserControl
    {
        private Label titleLabel, leftLabel, rightLabel, leftStats, rightStats, diffLabel;
        private Button leftBrowseBtn, rightBrowseBtn, compareBtn;
        private TextBox leftFileBox, rightFileBox;
        private Panel resultsPanel;
        private CommonUi.NetworkContext _leftCtx, _rightCtx;

        static readonly Color Bg = Color.FromArgb(0x1E, 0x1E, 0x2E);
        static readonly Color Panel = Color.FromArgb(0x25, 0x25, 0x40);
        static readonly Color Text = Color.FromArgb(0xCD, 0xD6, 0xF4);
        static readonly Color Border = Color.FromArgb(0x45, 0x47, 0x5A);
        static readonly Color Green = Color.FromArgb(0xA6, 0xE3, 0xA1);
        static readonly Color Orange = Color.FromArgb(0xFA, 0xB3, 0x87);

        public CaptureCompareUserControl()
        {
            BackColor = Bg; Dock = DockStyle.Fill;

            titleLabel = new Label { Text = "Capture Comparison — Side-by-Side PCAP Analysis", Location = new Point(12, 12),
                AutoSize = true, ForeColor = Text, Font = new Font("Segoe UI", 14f, FontStyle.Bold), BackColor = Bg };

            // Left side
            leftBrowseBtn = new Button { Text = "Browse...", Location = new Point(12, 50), Width = 80, Height = 28,
                BackColor = Border, ForeColor = Text, FlatStyle = FlatStyle.Flat };
            leftBrowseBtn.Click += (s,e) => { using var d = new OpenFileDialog { Filter = "PCAP Files|*.pcap;*.pcapng;*.cap" };
                if (d.ShowDialog() == DialogResult.OK) leftFileBox.Text = d.FileName; };

            leftFileBox = new TextBox { Location = new Point(100, 50), Width = 350, Height = 28,
                BackColor = Panel, ForeColor = Text, BorderStyle = BorderStyle.FixedSingle, ReadOnly = true };
            leftLabel = new Label { Text = "PCAP A (Left)", Location = new Point(12, 85), AutoSize = true,
                ForeColor = Green, Font = new Font("Segoe UI", 10f, FontStyle.Bold), BackColor = Bg };

            // Right side
            rightBrowseBtn = new Button { Text = "Browse...", Location = new Point(12, 115), Width = 80, Height = 28,
                BackColor = Border, ForeColor = Text, FlatStyle = FlatStyle.Flat };
            rightBrowseBtn.Click += (s,e) => { using var d = new OpenFileDialog { Filter = "PCAP Files|*.pcap;*.pcapng;*.cap" };
                if (d.ShowDialog() == DialogResult.OK) rightFileBox.Text = d.FileName; };

            rightFileBox = new TextBox { Location = new Point(100, 115), Width = 350, Height = 28,
                BackColor = Panel, ForeColor = Text, BorderStyle = BorderStyle.FixedSingle, ReadOnly = true };
            rightLabel = new Label { Text = "PCAP B (Right)", Location = new Point(12, 150), AutoSize = true,
                ForeColor = Green, Font = new Font("Segoe UI", 10f, FontStyle.Bold), BackColor = Bg };

            compareBtn = new Button { Text = "🔍 Compare Captures", Location = new Point(100, 185), Width = 180, Height = 36,
                BackColor = Border, ForeColor = Text, FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 11f, FontStyle.Bold) };
            compareBtn.Click += OnCompare;

            leftStats = new Label { Location = new Point(12, 235), AutoSize = true, ForeColor = Text,
                Font = new Font("Consolas", 10f), BackColor = Bg, Text = "Load two PCAPs and click Compare" };
            rightStats = new Label { Location = new Point(450, 235), AutoSize = true, ForeColor = Text,
                Font = new Font("Consolas", 10f), BackColor = Bg };
            diffLabel = new Label { Location = new Point(12, 380), AutoSize = true, ForeColor = Orange,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold), BackColor = Bg };

            Controls.AddRange(new Control[] { titleLabel, leftBrowseBtn, leftFileBox, leftLabel,
                rightBrowseBtn, rightFileBox, rightLabel, compareBtn, leftStats, rightStats, diffLabel });
        }

        private void OnCompare(object sender, EventArgs e)
        {
            if (!File.Exists(leftFileBox.Text) || !File.Exists(rightFileBox.Text))
            { MessageBox.Show("Select two valid PCAP files."); return; }

            var proc = new PcapProcessor.Processor { BuildTcpSessions = true, BuildUdpSessions = true };
            var leftAnalyzer = new PcapAnalyzer.Analyzer();
            var rightAnalyzer = new PcapAnalyzer.Analyzer();
            _leftCtx = new CommonUi.NetworkContext(); _rightCtx = new CommonUi.NetworkContext();

            foreach (var n in leftAnalyzer.AvailableModulesNames) leftAnalyzer.AddModule(n);
            foreach (var n in rightAnalyzer.AvailableModulesNames) rightAnalyzer.AddModule(n);

            leftAnalyzer.ParsedItemDetected += (s, ev) => { if (ev.ParsedItem is PcapAnalyzer.NetworkPassword p) _leftCtx.AddPassword(p); };
            rightAnalyzer.ParsedItemDetected += (s, ev) => { if (ev.ParsedItem is PcapAnalyzer.NetworkPassword p) _rightCtx.AddPassword(p); };

            proc.UdpPacketArived += (s, ev) => { leftAnalyzer.Analyze(CommonUi.Casting.CastProcessorUdpPacketToAnalyzerUdpPacket(ev.Packet)); };
            proc.TcpPacketArived += (s, ev) => { leftAnalyzer.Analyze(CommonUi.Casting.CastProcessorTcpPacketToAnalyzerTcpPacket(ev.Packet)); };

            var done = new System.Threading.ManualResetEventSlim(false);
            proc.ProcessingFinished += (s, ev) => done.Set();
            new System.Threading.Thread(() => proc.ProcessPcaps(new HashSet<string> { leftFileBox.Text })).Start();
            done.Wait(System.TimeSpan.FromMinutes(1));

            int lPwd = _leftCtx.Passwords.Count, lConns = _leftCtx.Connections.Count;

            // Process right
            _leftCtx = new CommonUi.NetworkContext();
            done.Reset();
            new System.Threading.Thread(() => proc.ProcessPcaps(new HashSet<string> { rightFileBox.Text })).Start();
            done.Wait(System.TimeSpan.FromMinutes(1));
            int rPwd = _leftCtx.Passwords.Count, rConns = _leftCtx.Connections.Count;

            // Display comparison
            leftStats.Text = $"LEFT:  Passwords: {lPwd}  |  Connections: {lConns}";
            rightStats.Text = $"RIGHT: Passwords: {rPwd}  |  Connections: {rConns}";

            var diffs = new List<string>();
            if (lPwd != rPwd) diffs.Add($"Passwords differ: {lPwd} vs {rPwd}");
            if (lConns != rConns) diffs.Add($"Connections differ: {lConns} vs {rConns}");
            diffLabel.Text = diffs.Any() ? $"⚠ Differences: {string.Join(" | ", diffs)}" : "✅ No significant differences found";
            diffLabel.ForeColor = diffs.Any() ? Orange : Green;
        }
    }
}
