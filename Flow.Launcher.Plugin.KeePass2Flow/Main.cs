using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Flow.Launcher.Plugin.KeePass2Flow.KeePass;
using Flow.Launcher.Plugin.KeePass2Flow.Settings;
using Keepass2Client;
using Keepass2Client.Entities;
using Keepass2Client.Setup;

namespace Flow.Launcher.Plugin.KeePass2Flow;

public class KeePass2Flow : IAsyncPlugin, ISettingProvider, IAsyncDisposable
{
    private const string KpUsername = "kp2flow2";

    private PluginInitContext _context = default!;
    private SettingsViewModel _settingsViewModel = default!;
    
    // TODO update when one is closed outside of Flow Launcher
    // TODO Instead of DatabaseSetting, use an ActiveDatabase class that contains the code to communicate with the RPC client
    private HashSet<DatabaseSetting> _activeDbs = new();

    private Settings.Settings Settings => _settingsViewModel.Settings;

    private KeePass2Client _keePass2Client;
    private KeePassPasswordFromFlowProvider _passwordFromFlowProvider;

    public async Task InitAsync(PluginInitContext context)
    {
        // Console.SetOut(new StreamWriter(context.CurrentPluginMetadata.PluginDirectory + Path.DirectorySeparatorChar + "ze.log"));
        
        _context = context;

        _passwordFromFlowProvider = new KeePassPasswordFromFlowProvider(context);
        _keePass2Client = new KeePass2Client(
            new KeePassSrp {Username = KpUsername},
            new KeePassKeyFileStorage(KpUsername, context.CurrentPluginMetadata.PluginDirectory),
            _passwordFromFlowProvider
        );

        // TODO improve UX here, show a message box when initializing so the user knows what to do
        // TODO expose the authentication through the settings panel as well
        // TODO ensure that keepass is actually running here; otherwise we run into an error
        _keePass2Client.InitAsync().ContinueWith(_ => _context.API.ShowMsg("Initialized!"));
        
        var settings = _context.API.LoadSettingJsonStorage<Settings.Settings>();
        _settingsViewModel = new SettingsViewModel(settings);
    }

    public async Task<List<Result>> QueryAsync(Query query, CancellationToken ct)
    {
        if (query.FirstSearch?.ToLower() == "open")
        {
            return Settings.Databases
                .Where(db => db.Name.ToLower().StartsWith(query.SecondSearch.ToLower()))
                .Select(db => new Result {
                Title = db.Name,
                SubTitle = $"Open {db.Name}",
                AutoCompleteText = $"{_context.CurrentPluginMetadata.ActionKeyword} open {db.Name}",
                Action = _ =>
                {
                    var keePassPath = Settings.KeePassPath;
                    // TODO replace this with a call to KeePassRPC if we're authenticated
                    _context.API.ShellRun($"\"{db.Path}\"", keePassPath);
                    _context.API.ChangeQuery(_context.CurrentPluginMetadata.ActionKeyword);
                    return true;
                },
                Score = 0,
            }).ToList();
        }
        
        var results = new List<Result> {
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

        if (query.FirstSearch?.ToLower() == "auth" && _passwordFromFlowProvider.RequestInProgress)
        {
            results.Add(new()
            {
                Title = "auth",
                SubTitle = "Authenticate the connection to KeePassRPC",
                Action = _ =>
                {
                    _passwordFromFlowProvider.SetPassword(query.SecondSearch);
                    return true;
                },
                Score = 10,
            });
        }

        if (await _keePass2Client.IsAuthenticated)
        {
            var entries = (await _keePass2Client.GetPasswords(query.Search)).ToList();

            results.AddRange(entries.Select(e => new Result
            {
                Title = e.Title,
                SubTitle = e.Username + " - " + e.Parent?.Title,
                Action = _ =>
                {
                    CopyToClipboard(e);
                    return true;
                },
                Icon = () => (ImageSource?) new ImageSourceConverter().ConvertFrom(e.Icon),
                Score = _context.API.FuzzySearch(query.Search, e.Title).Score,
            }));
        }

        return results;
    }

    private static async void CopyToClipboard(Entry entry)
    {
        var pw = entry.Password ?? "";
        Clipboard.SetText(pw);
        await Task.Delay(TimeSpan.FromSeconds(5));
        if (Clipboard.GetText() == pw) Clipboard.SetText("");
    }
    
    public Control CreateSettingPanel()
    {
        return new SettingsControl(_context, _settingsViewModel);
    }

    public async ValueTask DisposeAsync()
    {
        await _keePass2Client.Dispose();
    }
}
