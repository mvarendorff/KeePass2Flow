using Keepass2Client.Extensions;

namespace Keepass2Client.Setup;

public abstract class KeePassKeyStorage
{
    protected readonly string Username;

    public string Cc { get; private set; } = new Random().NextBigInteger(32).ToString("x");
    private string? _sc;
    
    protected KeePassKeyStorage(string username)
    {
        Username = username;
    }

    protected abstract Task<string> GetStoredKeyAsync();
    public abstract Task StoreKeyAsync(string key);
    protected abstract Task DropKey();

    public async Task<string> GetKey() => await GetStoredKeyAsync();

    public async Task Reset()
    {
        await DropKey();
        _sc = null;
        Cc = new Random().NextBigInteger(32).ToString("x");
    }
    
    public async Task<bool> HasKey()
    {
        try
        {
            await GetStoredKeyAsync();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<string> GetCr(string sc)
    {
        _sc = sc;
        var key = await GetKey();
        return Utils.Hash("1" + key + sc + Cc);
    }

    public async Task<bool> ValidateSr(string sr)
    {
        if (_sc is null) throw new InvalidOperationException("Sr can only be validated after calculating Cr!");
        
        var key = await GetKey();
        var expectedSr = Utils.Hash("0" + key + _sc + Cc);

        return expectedSr == sr;
    }
}