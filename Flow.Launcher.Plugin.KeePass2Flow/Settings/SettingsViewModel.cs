namespace Flow.Launcher.Plugin.KeePass2Flow.Settings;

public class SettingsViewModel
{
    public SettingsViewModel(Settings settings)
    {
        Settings = settings;
    }

    public Settings Settings { get; }
}