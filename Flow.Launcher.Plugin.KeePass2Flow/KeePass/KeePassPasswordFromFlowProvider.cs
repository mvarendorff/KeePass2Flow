using System.Threading.Tasks;
using Keepass2Client.Setup;

namespace Flow.Launcher.Plugin.KeePass2Flow.KeePass;

public class KeePassPasswordFromFlowProvider : IKeePassPasswordProvider
{
    private readonly PluginInitContext _context;
    private TaskCompletionSource<string>? _passwordTaskSource;
    
    public KeePassPasswordFromFlowProvider(PluginInitContext context)
    {
        _context = context;
    }

    public bool RequestInProgress => _passwordTaskSource is not null;
    
    public async Task<string> GetPassword()
    {
        _passwordTaskSource = new TaskCompletionSource<string>();
        
        _context.API.ShowMsg("Action required!", "Use 'kp auth' with the password shown in KeePass2 to connect.");
        
        _context.API.ChangeQuery("kp auth ");

        var password = await _passwordTaskSource.Task;
        _passwordTaskSource = null;

        return password;
    }

    public void SetPassword(string password) => _passwordTaskSource?.SetResult(password);
}