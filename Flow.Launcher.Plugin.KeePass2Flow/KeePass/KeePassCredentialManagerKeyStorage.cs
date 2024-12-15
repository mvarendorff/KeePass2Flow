using System;
using System.Net;
using System.Threading.Tasks;
using AdysTech.CredentialManager;
using Keepass2Client.Setup;

namespace Flow.Launcher.Plugin.KeePass2Flow.KeePass;

public class KeePassCredentialManagerKeyStorage : KeePassKeyStorage
{
    private const string CredentialsKeyBase = "KeePass2Flow";
    private string CredentialsKey => CredentialsKeyBase + "-" + Username;

    public KeePassCredentialManagerKeyStorage(string username) : base(username)
    {
    }

    protected override Task<string> GetStoredKeyAsync()
    {
        var credential = CredentialManager.GetCredentials(CredentialsKey);
        if (credential is null || credential.UserName != Username) throw new KeyNotFoundException();

        return Task.FromResult(credential.Password);
    }

    public override Task StoreKeyAsync(string key)
    {
        var credential = new NetworkCredential { Password = key, UserName = Username };
        CredentialManager.SaveCredentials(CredentialsKey, credential);

        return Task.CompletedTask;
    }

    protected override Task DropKey()
    {
        try
        {
            CredentialManager.RemoveCredentials(CredentialsKey);
        }
        catch
        {
            // Ignore
        }

        return Task.CompletedTask;
    }
}

public class KeyNotFoundException : Exception { }
