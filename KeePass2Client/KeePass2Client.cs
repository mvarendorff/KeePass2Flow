using WebSocket4Net;

namespace Keepass2Client;

public class KeePass2Client
{
    private WebSocket _webSocket;
    private const string KpServerUri = "ws://127.0.0.1:12546";

    private TaskCompletionSource _onClosedTaskSource = new();

    public Task Closed => _onClosedTaskSource.Task;
    
    public KeePass2Client()
    {
        _webSocket = new WebSocket(KpServerUri, customHeaderItems: new List<KeyValuePair<string, string>> { new("Origin", "moz-extension://kpflow")});
    }

    public async Task InitAsync()
    {
        _webSocket.MessageReceived += OnMessage;
        _webSocket.Closed += OnClosed;
        _webSocket.Error += OnError;
        
        await _webSocket.OpenAsync();
    }

    private void OnMessage(object? sender, MessageReceivedEventArgs e)
    {
        Console.Out.WriteLine(e);
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        Console.Out.WriteLine(e);
        _onClosedTaskSource.SetResult();
    }

    private void OnError(object? sender, EventArgs e)
    {
        Console.Out.WriteLine(e);
    }
}
