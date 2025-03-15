using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Flow.Launcher.Plugin.KeePass2Flow.KeePass;
using Flow.Launcher.Plugin.KeePass2Flow.Settings;
using Keepass2Client;
using Keepass2Client.Setup;

namespace Flow.Launcher.Plugin.KeePass2Flow;

public class KeePass2Flow : IAsyncPlugin, ISettingProvider, IAsyncDisposable
{
	[DllImport("user32.dll", SetLastError = true)]
    static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    static extern bool CloseClipboard();

    private const string KpUsername = "kp2flow2";

    private PluginInitContext _context = null!;
    private SettingsViewModel _settingsViewModel = null!;

    private Settings.Settings Settings => _settingsViewModel.Settings;

    private KeePass2Client _keePass2Client = null!;
    private KeePassPasswordFromFlowProvider _passwordFromFlowProvider = null!;

    private Timer _initTimer = null!;

    public Task InitAsync(PluginInitContext context)
    {
        _context = context;

        _passwordFromFlowProvider = new KeePassPasswordFromFlowProvider(context);
        _keePass2Client = new KeePass2Client(
            new KeePassSrp { Username = KpUsername },
            new KeePassCredentialManagerKeyStorage(KpUsername),
            _passwordFromFlowProvider
        );

        // TODO expose the authentication through the settings panel as well
        _initTimer = new Timer(TryInit, null, TimeSpan.Zero, TimeSpan.FromSeconds(5));

        var settings = _context.API.LoadSettingJsonStorage<Settings.Settings>();
        _settingsViewModel = new SettingsViewModel(settings);

        return Task.CompletedTask;
    }

    private async void TryInit(object? sender)
    {
        if (_keePass2Client.ClientState != ClientState.Disconnected) return;

        try
        {
            await _keePass2Client.InitAsync();
        }
        catch (Exception e)
        {
            _context.API.LogException(nameof(KeePass2Flow), "Does this remedy thing?", e);
        }
    }

    public async Task<List<Result>> QueryAsync(Query query, CancellationToken ct)
    {
        if (query.FirstSearch?.ToLower() == "open")
        {
            return Settings.Databases
                .Where(db => db.Name.ToLower().StartsWith(query.SecondSearch.ToLower()))
                .Select(db => new Result
                {
                    Title = db.Name,
                    SubTitle = $"Open {db.Name}",
                    AutoCompleteText = $"{_context.CurrentPluginMetadata.ActionKeyword} open {db.Name}",
                    AsyncAction = async _ =>
                    {
                        await OpenDatabase(db.Path);
                        return true;
                    },
                    Score = 0,
                }).ToList();
        }

        var results = new List<Result> {
            # if DEBUG
            new ()
            {
                Title = "debug",
                SubTitle = "Dump debug information",
                AutoCompleteText = $"{_context.CurrentPluginMetadata.ActionKeyword} debug ",
                Action = _ =>
                {
                    var debugInformation = _keePass2Client.DumpDebugInformation();
                    _context.API.CopyToClipboard(debugInformation, showDefaultNotification: false);
                    _context.API.ShowMsg("KeePass2Flow", "Debug information copied to clipboard.");

                    return false;
                },
                Score = 0,
            },
            # endif
        };

        if (query.FirstSearch?.ToLower() != "auth")
        {
            results.Add(new()
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
            });

            results.Add(
                new()
                {
                    Title = "reconnect",
                    SubTitle = "Reset connection to KeePassRPC",
                    AutoCompleteText = $"{_context.CurrentPluginMetadata.ActionKeyword} reconnect ",
                    AsyncAction = async _ =>
                    {
                        await _keePass2Client.Disconnect();
                        TryInit(null);

                        return false;
                    },
                    Score = 0,
                }
            );
        }

        if (query.FirstSearch?.ToLower() == "auth" && _passwordFromFlowProvider.RequestInProgress)
        {
            results.Add(new()
            {
                Title = $"auth {query.SecondSearch}",
                SubTitle = "Authenticate the connection to KeePassRPC",
                Action = _ =>
                {
                    _passwordFromFlowProvider.SetPassword(query.SecondSearch);
                    return true;
                },
                Score = 10,
            });
        }

        if (await _keePass2Client.IsReady)
        {
            var entries = (await _keePass2Client.GetPasswords(query.Search)).ToList();

            results.AddRange(entries.Select(e => new Result
            {
                Title = e.Title,
                SubTitle = e.Username + " - " + e.Parent?.Title,
                Action = context =>
                {
                    CopyToClipboard((context.SpecialKeyState.CtrlPressed ? e.Username : e.Password) ?? "")
                        .ContinueWith(_ => { /* Ignore thrown errors */ }, ct);
                    return true;
                },
                Icon = () => (ImageSource?)new ImageSourceConverter().ConvertFrom(e.Icon),
                Score = _context.API.FuzzySearch(query.Search, e.Title).Score,
            }));
        }

        return results;
    }

    private static async Task CopyToClipboard(string content)
    {
        SetClipboard(content);
        await Task.Delay(TimeSpan.FromSeconds(5));
        if (Clipboard.GetText() == content) SetClipboard("");
    }

    private static void SetClipboard(string text)
    {
        for (byte i = 0; i < 10; i++)
        {
            try
            {
				OpenClipboard(IntPtr.Zero);
                EmptyClipboard();
                CloseClipboard();
				
                Clipboard.SetText(text);
                return;
            }
            catch
            {
                Thread.Sleep(10);
            }
        }
    }

    private async Task OpenDatabase(string path)
    {
        var keePassPath = Settings.KeePassPath;

        if (await _keePass2Client.IsReady)
        {
            await _keePass2Client.OpenAndFocusDatabase(path);
            return;
        }

        _context.API.ShellRun($"\"{path}\"", keePassPath);
        _context.API.ChangeQuery(_context.CurrentPluginMetadata.ActionKeyword);
    }

    public Control CreateSettingPanel()
    {
        return new SettingsControl(_context, _settingsViewModel);
    }

    public async ValueTask DisposeAsync()
    {
        await _initTimer.DisposeAsync();
        await _keePass2Client.Dispose();
    }
}