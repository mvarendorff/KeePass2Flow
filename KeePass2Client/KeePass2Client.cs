using System.Text.Json;
using WebSocket4Net;
using ErrorEventArgs = SuperSocket.ClientEngine.ErrorEventArgs;

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
        Console.Out.WriteLine($"<< {e.Message}");

        var parsedMessage = JsonSerializer.Deserialize<JsonElement>(e.Message);
        var protocol = parsedMessage.GetProperty("protocol").GetString()!;
        HandleByProtocol(protocol, parsedMessage);
    }

    private void HandleByProtocol(string protocol, JsonElement parsedMessage)
    {
        switch (protocol)
        {
            case "setup": HandleSetup(parsedMessage);
                break;
        }
    }

    private void HandleSetup(JsonElement parsedMessage)
    {
        var stage = parsedMessage.GetProperty("srp").GetProperty("stage").GetString()!;
        if (stage == "identifyToClient")
        {
            
        }
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        if (e is ClosedEventArgs closedE)
        {
            Console.Out.WriteLine($"{closedE.Code} {closedE.Reason}");
        }
        _onClosedTaskSource.SetResult();
    }

    private void OnError(object? sender, EventArgs e)
    {
        if (e is ErrorEventArgs errorE)
        {
            Console.Out.WriteLine(errorE.Exception);
        }
        Console.Out.WriteLine("Error!");
    }

    public async Task Dispose()
    {
        await _webSocket.CloseAsync();
    }

    public void Send(string message)
    {
        Console.Out.WriteLine($">> {message}");
        _webSocket.Send(message);
    }
}
