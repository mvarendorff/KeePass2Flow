namespace Keepass2Client.Setup;

public interface IKeePassPasswordProvider
{
    public Task<string> GetPassword();
}