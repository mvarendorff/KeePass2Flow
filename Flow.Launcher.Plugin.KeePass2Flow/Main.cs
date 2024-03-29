using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;
using System.Windows.Input;
using Flow.Launcher.Plugin.KeePass2Flow.Settings;
using Flow.Launcher.Plugin.SharedCommands;

namespace Flow.Launcher.Plugin.KeePass2Flow;

public class KeePass2Flow : IAsyncPlugin, ISettingProvider, IDisposable
{
    private PluginInitContext _context = default!;
    private SettingsViewModel _settingsViewModel = default!;
    
    // TODO update when one is closed outside of Flow Launcher
    // TODO Instead of DatabaseSetting, use an ActiveDatabase class that contains the code to communicate with the RPC client
    private HashSet<DatabaseSetting> _activeDbs = new();

    private Settings.Settings Settings => _settingsViewModel.Settings;
    
    public async Task InitAsync(PluginInitContext context)
    {
        _context = context;
        
        _context.API.SavePluginSettings();
        var settings = _context.API.LoadSettingJsonStorage<Settings.Settings>();
        _settingsViewModel = new SettingsViewModel(settings);
    }

    public async Task<List<Result>> QueryAsync(Query query, CancellationToken ct)
    {
        if (query.FirstSearch?.ToLower() == "open")
        {
            // TODO integrate _context.API.FuzzySearch
            
            return Settings.Databases
                .Where(db => db.Name.ToLower().StartsWith(query.SecondSearch.ToLower()))
                .Select(db => new Result {
                Title = db.Name,
                SubTitle = $"Open {db.Name}",
                AutoCompleteText = $"{_context.CurrentPluginMetadata.ActionKeyword} open {db.Name}",
                Action = _ =>
                {
                    var keePassPath = Settings.KeePassPath;
                    _context.API.ShellRun($"\"{db.Path}\"", keePassPath);
                    _context.API.ChangeQuery(_context.CurrentPluginMetadata.ActionKeyword);
                    return true;
                },
                Score = 0,
            }).ToList();
        }
        
        return new List<Result> {
            new()
            {
                Title = "open",
                SubTitle = "Open a database",
                AutoCompleteText = $"{_context.CurrentPluginMetadata.ActionKeyword} open ",
                Action = _ =>
                {
                    _context.API.ChangeQuery($"{_context.CurrentPluginMetadata.ActionKeyword} open ");
                    return false;
                },
                Score = 0,
            },
        };
    }

    public Control CreateSettingPanel()
    {
        return new SettingsControl(_context, _settingsViewModel);
    }

    public void Dispose()
    {
        // TODO close the websocket and all other clients here
        throw new NotImplementedException();
    }
}
