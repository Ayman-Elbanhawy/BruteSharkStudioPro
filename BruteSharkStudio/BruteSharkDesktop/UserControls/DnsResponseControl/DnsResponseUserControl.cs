using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Text;
using System.Windows.Forms;
using PcapAnalyzer;

namespace BruteSharkDesktop
{
    public partial class DnsResponseUserControl : UserControl
    {
        private BindingSource _queriesBindingSource;
        public int AnswerCount => this.queriesDataGridView.RowCount;

        public DnsResponseUserControl()
        {
            InitializeComponent();

            // Initialize the answers gridview.
            _queriesBindingSource = new BindingSource();
            this.queriesDataGridView.DataSource = _queriesBindingSource;
            this.queriesDataGridView.AllowUserToAddRows = false;

            ApplyDarkTheme();
        }

        private void ApplyDarkTheme()
        {
            var panel = Color.FromArgb(0x25, 0x25, 0x40);
            var text = Color.FromArgb(0xCD, 0xD6, 0xF4);
            var border = Color.FromArgb(0x45, 0x47, 0x5A);

            this.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);
            queriesDataGridView.BackgroundColor = panel;
            queriesDataGridView.ForeColor = text;
            queriesDataGridView.GridColor = border;
            queriesDataGridView.BorderStyle = BorderStyle.None;
            queriesDataGridView.DefaultCellStyle.BackColor = panel;
            queriesDataGridView.DefaultCellStyle.ForeColor = text;
            queriesDataGridView.DefaultCellStyle.SelectionBackColor = border;
            queriesDataGridView.DefaultCellStyle.SelectionForeColor = text;
            queriesDataGridView.ColumnHeadersDefaultCellStyle.BackColor = border;
            queriesDataGridView.ColumnHeadersDefaultCellStyle.ForeColor = text;
            queriesDataGridView.EnableHeadersVisualStyles = false;
            queriesDataGridView.RowHeadersVisible = false;
            queriesDataGridView.ScrollBars = ScrollBars.Both;
            queriesDataGridView.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCellsExceptHeader;
        }

        internal void AddNameMapping(DnsNameMapping mapping)
        {
            this.SuspendLayout();

            _queriesBindingSource.Add(mapping);

            this.ResumeLayout();
        }
    }
}