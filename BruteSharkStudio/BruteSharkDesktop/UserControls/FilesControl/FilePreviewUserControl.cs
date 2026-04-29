using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;

namespace BruteSharkDesktop
{
    public partial class FilePreviewUserControl : UserControl
    {
        private readonly List<string> _imagesFilesExtentions = new List<string> {"jpg", "png", "gif"};

        public FilePreviewUserControl()
        {
            InitializeComponent();
            ApplyDarkTheme();
        }

        private void ApplyDarkTheme()
        {
            var bg = Color.FromArgb(0x1E, 0x1E, 0x2E);
            var panel = Color.FromArgb(0x25, 0x25, 0x40);
            var text = Color.FromArgb(0xCD, 0xD6, 0xF4);

            this.BackColor = bg;
            mainSplitContainer.BackColor = Color.FromArgb(0x45, 0x47, 0x5A);
            mainSplitContainer.Panel1.BackColor = bg;
            mainSplitContainer.Panel2.BackColor = bg;
            filePreviewSplitContainer.BackColor = Color.FromArgb(0x45, 0x47, 0x5A);
            filePreviewSplitContainer.Panel1.BackColor = bg;
            filePreviewSplitContainer.Panel2.BackColor = bg;
            headerLabel.ForeColor = text;
        }

        public void PreviewFile(byte[] data, string extention)
        {
            try
            {
                if (_imagesFilesExtentions.Contains(extention))
                {
                    this.filePreviewSplitContainer.Panel2.Controls.Clear();
                    this.filePreviewSplitContainer.Panel2.BackgroundImageLayout = ImageLayout.Center;
                    this.filePreviewSplitContainer.Panel2.BackgroundImage = byteArrayToImage(data);
                }
            }
            catch 
            { 
            
            }
        }


        private static Image GetImage(byte[] data)
        {
            using (MemoryStream ms = new MemoryStream(data))
            {
                return (Image.FromStream(ms));
            }
        }

        public Image byteArrayToImage(byte[] byteArrayIn)
        {
            System.Drawing.ImageConverter converter = new System.Drawing.ImageConverter();
            Image img = (Image)converter.ConvertFrom(byteArrayIn);

            return img;
        }

    }
}
