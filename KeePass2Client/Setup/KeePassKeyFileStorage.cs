namespace Keepass2Client.Setup;

public class KeePassKeyFileStorage : KeePassKeyStorage
{
    private readonly string _path;
    
    public KeePassKeyFileStorage(string username, string basePath = "") : base(username)
    {
        var prependedPath = string.IsNullOrWhiteSpace(basePath) ? "" : basePath + Path.DirectorySeparatorChar;
        _path = $"{prependedPath}{username}_key.txt";
    }

    protected override async Task<string> GetStoredKeyAsync()
    {
        var fileExists = File.Exists(_path);
        if (!fileExists) throw new Exception($"File {_path} does not exist!");

        return await File.ReadAllTextAsync(_path);
    }

    public override async Task StoreKeyAsync(string key)
    {
        await File.WriteAllTextAsync(_path, key);
    }

    protected override Task DropKey()
    {
        try
        {
            File.Delete(_path);
        }
        catch
        {
            // Ignore
        }

        return Task.CompletedTask;
    }
}
