using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using PcapProcessor;

namespace BruteSharkDesktop
{
    public partial class SessionViewerUserControl : UserControl
    {
        public SessionViewerUserControl()
        {
            InitializeComponent();
            ApplyDarkTheme();
        }

        private void ApplyDarkTheme()
        {
            var bg = Color.FromArgb(0x1E, 0x1E, 0x2E);
            var panel = Color.FromArgb(0x25, 0x25, 0x40);
            var text = Color.FromArgb(0xCD, 0xD6, 0xF4);
            var border = Color.FromArgb(0x45, 0x47, 0x5A);

            this.BackColor = bg;

            // Split container
            mainSplitContainer.BackColor = border;
            mainSplitContainer.Panel1.BackColor = bg;
            mainSplitContainer.Panel2.BackColor = bg;

            // Rich text box (hex viewer)
            sessionDataRichTextBox.BackColor = panel;
            sessionDataRichTextBox.ForeColor = text;
            sessionDataRichTextBox.BorderStyle = BorderStyle.None;

            // Group box
            sessionDetailsGroupBox.ForeColor = text;
            sessionDetailsGroupBox.BackColor = bg;

            // Labels
            foreach (var lbl in new[] { sourceIpLabel, destinationIpLabel, sourcePortLabel, destinationPortLabel, dataLengthLabel })
            {
                lbl.ForeColor = text;
            }
        }

        public void SetSessionView(TransportLayerSession session)
        {
            SetSessionDetails(session);
            AddColoredSessionData(session);
        }

        private void SetSessionDetails(TransportLayerSession session)
        {
            this.sourceIpLabel.Text = "Source Ip: " + session.SourceIp;
            this.destinationIpLabel.Text = "Destination IP: " + session.DestinationIp;
            this.sourcePortLabel.Text = "Source Port: " + session.SourcePort.ToString();
            this.destinationPortLabel.Text = "Destination Port: " + session.DestinationPort.ToString();
            this.dataLengthLabel.Text = "Data Length (Bytes): " + session.Data.Length.ToString();
        }

        private void AddColoredSessionData(TransportLayerSession session)
        {
            this.sessionDataRichTextBox.Clear();

            foreach (var packet in session.Packets)
            {
                // TODO: add encoding type
                SetSessionData(
                    this.sessionDataRichTextBox, 
                    Encoding.ASCII.GetString(packet.Data),
                    packet.SourceIp == session.SourceIp ? Color.Blue : Color.Red);
            }
        }

        public void SetSessionData(RichTextBox richTextBox, string text, Color color)
        {
            richTextBox.SelectionStart = richTextBox.TextLength;
            richTextBox.SelectionLength = 0;
            richTextBox.SelectionColor = color;
            richTextBox.AppendText(text);
            richTextBox.SelectionColor = richTextBox.ForeColor;
        }
    }
}
