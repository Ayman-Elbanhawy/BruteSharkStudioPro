using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BruteSharkDesktop
{
    public partial class GenericTableUserControl : UserControl
    {
        public event EventHandler SelectionChanged
        {
            add { this.mainDataGridView.SelectionChanged += value; }
            remove { this.mainDataGridView.SelectionChanged += value; }
        }

        private HashSet<object> _dataHashSet;
        private BindingSource _dataGridViewBindingSource;

        public HashSet<object> ItemsHashSet
        {
            get
            {
                return _dataHashSet;
            }
            private set { }
        }

        public IEnumerable<object> Items
        {
            get
            {
                return _dataHashSet;
            }
            private set { }
        }

        public object SelectedRowBoundItem
        {
            get
            {
                return this.mainDataGridView.SelectedRows.Count > 0 ? this.mainDataGridView.SelectedRows[0].DataBoundItem : null;
            }
        }

        public int ItemsCount => _dataHashSet.Count;


        public GenericTableUserControl()
        {
            InitializeComponent();
            _dataHashSet = new HashSet<object>();
            _dataGridViewBindingSource = new BindingSource();
            this.mainDataGridView.DataSource = _dataGridViewBindingSource;
            this.mainDataGridView.AutoGenerateColumns = true;
            this.mainDataGridView.AllowUserToAddRows = false;
            ApplyDarkTheme();
        }

        private void ApplyDarkTheme()
        {
            var panel = Color.FromArgb(0x25, 0x25, 0x40);
            var text = Color.FromArgb(0xCD, 0xD6, 0xF4);
            var border = Color.FromArgb(0x45, 0x47, 0x5A);

            this.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);
            mainDataGridView.BackgroundColor = panel;
            mainDataGridView.ForeColor = text;
            mainDataGridView.GridColor = border;
            mainDataGridView.BorderStyle = BorderStyle.None;
            mainDataGridView.DefaultCellStyle.BackColor = panel;
            mainDataGridView.DefaultCellStyle.ForeColor = text;
            mainDataGridView.DefaultCellStyle.SelectionBackColor = border;
            mainDataGridView.DefaultCellStyle.SelectionForeColor = text;
            mainDataGridView.ColumnHeadersDefaultCellStyle.BackColor = border;
            mainDataGridView.ColumnHeadersDefaultCellStyle.ForeColor = text;
            mainDataGridView.EnableHeadersVisualStyles = false;
            mainDataGridView.RowHeadersVisible = false;
            mainDataGridView.ScrollBars = ScrollBars.Both;
            mainDataGridView.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCellsExceptHeader;
        }

        public GenericTableUserControl(IEnumerable<object> data) : this()
        {
            FillDataGridView(data);
        }

        public void FillDataGridView(IEnumerable<object> data)
        {
            // NOTE: BindingSource is usefull for cases the data is collection of derived types.
            _dataGridViewBindingSource.DataSource = data;

            // Resize the DataGridView columns to fit the newly loaded content.
            this.mainDataGridView.AutoResizeColumns(DataGridViewAutoSizeColumnsMode.AllCellsExceptHeader);
        }

        public void SetTableDataType(Type objectDesiredType)
        {
            _dataGridViewBindingSource.DataSource = objectDesiredType;
        }

        public void AddDataToTable(object row)
        {
            if (_dataHashSet.Add(row))
            {
                this.SuspendLayout();

                _dataGridViewBindingSource.Add(row);

                this.ResumeLayout();
            }
        }
    }
}
