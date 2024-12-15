using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using Microsoft.Win32;

namespace Flow.Launcher.Plugin.KeePass2Flow.Settings;

public partial class DatabaseSettingWindow
{
    private DatabaseSetting? _oldDatabaseSetting;
    private EditMode _editMode;
    private DatabaseSetting _databaseSetting;

    private ObservableCollection<DatabaseSetting> _knownDatabases;
    private PluginInitContext _context;

    public DatabaseSettingWindow(ObservableCollection<DatabaseSetting> knownDatabases, PluginInitContext context) :
        this(knownDatabases, context, new DatabaseSetting("", ""))
    {
        _editMode = EditMode.Add;
    }

    public DatabaseSettingWindow(ObservableCollection<DatabaseSetting> knownDatabases, PluginInitContext context, DatabaseSetting oldDatabaseSetting)
    {
        InitializeComponent();

        _editMode = EditMode.Edit;

        _oldDatabaseSetting = oldDatabaseSetting;
        _databaseSetting = oldDatabaseSetting.ShallowClone();
        _knownDatabases = knownDatabases;
        _context = context;

        DataContext = new DatabaseSettingViewModel(_databaseSetting);
    }

    private void OnCancelButtonClick(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void OnConfirmButtonClick(object sender, RoutedEventArgs e)
    {
        if (_editMode == EditMode.Add)
        {
            var existing = _knownDatabases.FirstOrDefault(db => db.Name == _databaseSetting.Name);

            if (existing is not null)
            {
                MessageBox.Show("A database with that name already exists", "Error", MessageBoxButton.OK);
                return;
            }

            _knownDatabases.Add(_databaseSetting);
        }
        else if (_editMode == EditMode.Edit)
        {
            var existingIndex = _knownDatabases.IndexOf(_oldDatabaseSetting!);
            _knownDatabases[existingIndex] = _databaseSetting;
        }

        Close();
    }

    private void BrowseDatabase(object sender, RoutedEventArgs e)
    {
        const string filter = "KeePass Database (*.kbdx) | *.kdbx";
        var dialog = new OpenFileDialog { Filter = filter };
        var result = dialog.ShowDialog();

        if (result != true) return;

        _databaseSetting.Path = dialog.FileName;
        DatabasePathInput.Text = dialog.FileName;
    }
}

enum EditMode
{
    Add, Edit
}
