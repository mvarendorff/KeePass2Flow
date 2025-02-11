using System;
using System.Windows;
using System.Windows.Controls;
using System.ComponentModel;
using System.Windows.Data;
using System.Windows.Input;
using Microsoft.Win32;

namespace Flow.Launcher.Plugin.KeePass2Flow.Settings;

/// <summary>
/// Interaction logic for WebSearchesSetting.xaml
/// </summary>
public partial class SettingsControl
{
    private readonly Settings _settings;
    private readonly PluginInitContext _context;

    public SettingsControl(PluginInitContext context, SettingsViewModel viewModel)
    {
        InitializeComponent();
        _context = context;
        _settings = viewModel.Settings;
        DataContext = viewModel;
    }

    private void OnAddDatabaseClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var setting = new DatabaseSettingWindow(_settings.Databases, _context);
            setting.ShowDialog();
        }
        catch (Exception ex)
        {
            _context.API.LogException(nameof(SettingsControl), "Yikes", ex);
        }
    }

    private void OnDeleteDatabaseClick(object sender, RoutedEventArgs e)
    {
        if (_settings.SelectedDatabase == null) return;

        var selected = _settings.SelectedDatabase;
        var formatted = $"Are you sure you want to delete {selected.Name}";

        var result = MessageBox.Show(formatted, string.Empty, MessageBoxButton.YesNo);
        if (result != MessageBoxResult.Yes) return;

        _settings.Databases.Remove(selected);
    }

    private void OnEditDatabaseClick(object sender, RoutedEventArgs e)
    {
        if (_settings.SelectedDatabase == null) return;

        var webSearch = new DatabaseSettingWindow
        (
            _settings.Databases, _context, _settings.SelectedDatabase
        );

        webSearch.ShowDialog();
    }

    GridViewColumnHeader? _lastHeaderClicked;
    ListSortDirection _lastDirection = ListSortDirection.Ascending;
    private void SortByColumn(object sender, RoutedEventArgs e)
    {
        ListSortDirection direction;

        if (e.OriginalSource is not GridViewColumnHeader headerClicked)
        {
            return;
        }

        if (headerClicked.Role == GridViewColumnHeaderRole.Padding)
        {
            return;
        }

        if (headerClicked != _lastHeaderClicked)
        {
            direction = ListSortDirection.Ascending;
        }
        else
        {
            if (_lastDirection == ListSortDirection.Ascending)
            {
                direction = ListSortDirection.Descending;
            }
            else
            {
                direction = ListSortDirection.Ascending;
            }
        }

        var columnBinding = headerClicked.Column.DisplayMemberBinding as Binding;
        var sortBy = columnBinding?.Path.Path ?? headerClicked.Column.Header as string;

        if (sortBy == null) return;
        Sort(sortBy, direction);

        if (direction == ListSortDirection.Ascending)
        {
            headerClicked.Column.HeaderTemplate =
                Resources["HeaderTemplateArrowUp"] as DataTemplate;
        }
        else
        {
            headerClicked.Column.HeaderTemplate =
                Resources["HeaderTemplateArrowDown"] as DataTemplate;
        }

        // Remove arrow from previously sorted header
        if (_lastHeaderClicked != null && _lastHeaderClicked != headerClicked)
        {
            _lastHeaderClicked.Column.HeaderTemplate = null;
        }

        _lastHeaderClicked = headerClicked;
        _lastDirection = direction;
    }
    private void Sort(string sortBy, ListSortDirection direction)
    {
        var dataView = CollectionViewSource.GetDefaultView(DatabasesListView.ItemsSource);
        dataView.SortDescriptions.Clear();
        SortDescription sd = new(sortBy, direction);
        dataView.SortDescriptions.Add(sd);
        dataView.Refresh();
    }

    private void MouseDoubleClickItem(object sender, MouseButtonEventArgs e)
    {
        if (((FrameworkElement)e.OriginalSource).DataContext is DatabaseSetting && _settings.SelectedDatabase != null)
        {
            var webSearch = new DatabaseSettingWindow(
                _settings.Databases, _context, _settings.SelectedDatabase
            );

            webSearch.ShowDialog();
        }
    }

    private void BrowseKeePass(object sender, RoutedEventArgs e)
    {
        const string filter = "KeePass.exe | KeePass.exe | KeePassXC.exe";
        var dialog = new OpenFileDialog { Filter = filter };
        var result = dialog.ShowDialog();

        if (result != true) return;

        _settings.KeePassPath = dialog.FileName;
        // Requires manual setting of the text because the binding information is lost when updating the string directly
        KeePassPathInput.Text = dialog.FileName;
        Keyboard.ClearFocus();
    }
}
