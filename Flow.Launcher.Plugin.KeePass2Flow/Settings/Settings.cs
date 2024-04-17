using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

namespace Flow.Launcher.Plugin.KeePass2Flow.Settings;

public class Settings : BaseModel
{
    public Settings()
    {
        if (Databases.Count > 0)
        {
            SelectedDatabase = Databases[0];
        }
    }

    public ObservableCollection<DatabaseSetting> Databases { get; set; } = new() ;

    [JsonIgnore] public DatabaseSetting? SelectedDatabase { get; set; }

    public string KeePassPath { get; set; } = "";
}

public class DatabaseSetting : BaseModel
{
    public string Path { get; set; }
    public string Name { get; init; }

    public DatabaseSetting(string name, string path)
    {
        Name = name;
        Path = path;
    }

    public DatabaseSetting ShallowClone() => new(Name, Path);
};
