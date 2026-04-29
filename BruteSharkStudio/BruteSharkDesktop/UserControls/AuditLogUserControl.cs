using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace BruteSharkDesktop
{
    /// <summary>
    /// Audit trail / activity log viewer for forensic accountability.
    /// </summary>
    public class AuditLogUserControl : UserControl
    {
        private readonly ListBox logList;
        private readonly List<string> _entries = new();
        private const int MaxEntries = 5000;

        public AuditLogUserControl()
        {
            this.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);
            this.Dock = DockStyle.Fill;

            var topPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 36,
                BackColor = Color.FromArgb(0x25, 0x25, 0x40)
            };

            var label = new Label
            {
                Text = "Activity Log (latest first) — double-click to copy",
                Location = new Point(8, 10),
                AutoSize = true,
                ForeColor = Color.FromArgb(0x89, 0xB4, 0xFA),
                BackColor = Color.FromArgb(0x25, 0x25, 0x40),
                Font = new Font("Segoe UI", 9f)
            };

            var clearBtn = new Button
            {
                Text = "Clear",
                Location = new Point(300, 5),
                Width = 60,
                Height = 26,
                BackColor = Color.FromArgb(0x45, 0x47, 0x5A),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                FlatStyle = FlatStyle.Flat
            };
            clearBtn.Click += (s, e) => { _entries.Clear(); logList.Items.Clear(); };

            topPanel.Controls.Add(label);
            topPanel.Controls.Add(clearBtn);

            logList = new ListBox
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                BorderStyle = BorderStyle.None,
                Font = new Font("Consolas", 9f),
                HorizontalScrollbar = true
            };
            logList.MouseDoubleClick += (s, e) =>
            {
                if (logList.SelectedItem != null)
                    Clipboard.SetText(logList.SelectedItem.ToString());
            };

            this.Controls.Add(logList);
            this.Controls.Add(topPanel);
        }

        public void AddEntry(string level, string message)
        {
            var entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";
            _entries.Insert(0, entry);
            if (_entries.Count > MaxEntries) _entries.RemoveAt(_entries.Count - 1);
            logList.Items.Clear();
            foreach (var e in _entries) logList.Items.Add(e);
        }

        public void Info(string msg) => AddEntry("INFO", msg);
        public void Warn(string msg) => AddEntry("WARN", msg);
        public void Error(string msg) => AddEntry("ERROR", msg);
    }
}
