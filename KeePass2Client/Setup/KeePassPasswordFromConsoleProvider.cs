namespace Keepass2Client.Setup;

public class KeePassPasswordFromConsoleProvider : IKeePassPasswordProvider
{
    public async Task<string> GetPassword()
    {
        await Console.Out.WriteLineAsync("Password:");
        var password = await Console.In.ReadLineAsync();

        return password ?? "";
    }
}