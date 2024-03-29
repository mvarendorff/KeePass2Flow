namespace Flow.Launcher.Plugin.KeePass2Flow.Settings;

public class DatabaseSettingViewModel : BaseModel
{
    public DatabaseSettingViewModel(DatabaseSetting? databaseSetting = null)
    {
        DatabaseSetting = databaseSetting ?? new DatabaseSetting("", "");
    }
    
    public DatabaseSetting DatabaseSetting { get; }
}