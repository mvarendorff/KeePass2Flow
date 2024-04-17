using System.Diagnostics;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Keepass2Client.Crypto;
using Keepass2Client.Entities;
using Keepass2Client.Setup;
using WebSocket4Net;
using ErrorEventArgs = SuperSocket.ClientEngine.ErrorEventArgs;

namespace Keepass2Client;

public class KeePass2Client
{
    private readonly KeePassSrp _keePassSrp;
    private readonly KeePassKeyStorage _keyStorage;
    private readonly IKeePassPasswordProvider _passwordProvider;
    
    private WebSocket _webSocket;
    private const string KpServerUri = "ws://127.0.0.1:12546";

    private readonly Dictionary<string, TaskCompletionSource<JsonElement>> _results = new();
    
    private TaskCompletionSource _onClosedTaskSource = new();
    private TaskCompletionSource _onHandshakeCompleted = new();
    
    public Task Closed => _onClosedTaskSource.Task;
    public Task<bool> IsAuthenticated => _keyStorage.HasKey();
    
    public KeePass2Client(KeePassSrp keePassSrp, KeePassKeyStorage keyStorage, IKeePassPasswordProvider passwordProvider)
    {
        _keePassSrp = keePassSrp;
        _keyStorage = keyStorage;
        _passwordProvider = passwordProvider;
        _webSocket = new WebSocket(KpServerUri, customHeaderItems: new List<KeyValuePair<string, string>>
        {
            // KeePassRPC only allows special origins that indicate a browser extension, so we pretend to be one
            new("Origin", "moz-extension://kpflow")
        });
    }

    public async Task InitAsync()
    {
        _webSocket.MessageReceived += OnMessage;
        _webSocket.Closed += OnClosed;
        _webSocket.Error += OnError;
        
        await _webSocket.OpenAsync();

        await InitiateHandshake();

        await _onHandshakeCompleted.Task;
        await Console.Out.WriteLineAsync("Handshake complete, do whatever you please :)");
    }

    private async Task InitiateHandshake()
    {
        var setupMessage = new Dictionary<string, dynamic?>
        {
            {"protocol", "setup"},
            {"version", 69632},
            {"features", new[] {"KPRPC_FEATURE_VERSION_1_6"}},
            {"clientTypeId", "kpflow"},
            {"clientDisplayName", "KeePass2Flow"},
            {"clientDisplayDescription", "Connecting Flow Launcher to KeePass 2"}
        };

        var hasStoredKey = await _keyStorage.HasKey();
        if (hasStoredKey)
        {
            Console.Out.WriteLine("Using stored key!");
            setupMessage.Add("srp", null);
            setupMessage.Add("key", new Dictionary<string, dynamic>
            {
                {"username", _keePassSrp.Username},
                {"securityLevel", 2},
            });
        }
        else
        {
            Console.Out.WriteLine("Using fresh SRP setup, expect prompt!");
            setupMessage.Add("key", null);
            setupMessage.Add("srp", new Dictionary<string, dynamic>
            {
                {"stage", "identifyToServer"},
                {"I", _keePassSrp.Username},
                {"A", _keePassSrp.A.ToString("X")},
                {"securityLevel", 2}
            });
        }

        var setupJson = JsonSerializer.Serialize(setupMessage);
        Send(setupJson);
    }

    private void OnMessage(object? sender, MessageReceivedEventArgs e)
    {
        Console.Out.WriteLine($"<< {e.Message}");
        Console.Out.Flush();

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
            case "jsonrpc": HandleJsonRpc(parsedMessage);
                break;
        }
    }

    private void HandleSetup(JsonElement parsedMessage)
    {
        var isKey = parsedMessage.TryGetProperty("key", out var key);
        if (isKey)
        {
            var isChallenge1 = key.TryGetProperty("sc", out var sc);
            if (isChallenge1) KeyChallengeResponse1(sc.GetString()!).Wait();
            
            var isChallenge2 = key.TryGetProperty("sr", out var sr);
            if (isChallenge2) KeyChallengeResponse2(sr.GetString()!).Wait();
        }
        
        var isSrp = parsedMessage.TryGetProperty("srp", out var srp);
        if (isSrp)
        {
            var stage = srp.GetProperty("stage").GetString()!;
            if (stage == "identifyToClient") ProofToServer(parsedMessage).Wait();
            if (stage == "proofToClient") VerifyServerProof(parsedMessage);
        }
    }

    private void HandleJsonRpc(JsonElement parsedMessage)
    {
        var jsonrpc = parsedMessage.GetProperty("jsonrpc");
        var messageBase64 = jsonrpc.GetProperty("message").GetString()!;
        var ivBase64 = jsonrpc.GetProperty("iv").GetString()!;
        var hmacBase64 = jsonrpc.GetProperty("hmac").GetString()!;

        var encryptedMessage = new EncryptedMessage(messageBase64, ivBase64, hmacBase64);
        var decryptedMessage = KeePassCrypto.Decrypt(encryptedMessage, _keyStorage.GetKey().Result);

        var json = JsonSerializer.Deserialize<JsonElement>(decryptedMessage);
        if (!json.TryGetProperty("id", out var id)) return;

        if (id.ValueKind != JsonValueKind.String) return;
        
        var requestId = id.GetString();
        if (requestId is null) return;
            
        Console.Out.WriteLine(json);

        _results[requestId].SetResult(json);
    }
    
    private async Task KeyChallengeResponse1(string sc)
    {
        var cr = await _keyStorage.GetCr(sc);
        var keyChallenge = new Dictionary<string, dynamic>
        {
            {"protocol", "setup"},
            {"key", new Dictionary<string, dynamic>
            {
                {"cc", _keyStorage.Cc},
                {"cr", cr},
                {"securityLevel", 2},
            }},
            {"version", 69632}
        };
        var keyChallengeJson = JsonSerializer.Serialize(keyChallenge);
        Send(keyChallengeJson);
    }

    private async Task KeyChallengeResponse2(string sr)
    {
        var validated = await _keyStorage.ValidateSr(sr);
        if (!validated) throw new Exception("Key challenge response 2 mismatch!");
        
        _onHandshakeCompleted.SetResult();
    }

    private async Task ProofToServer(JsonElement parsedMessage)
    {
        var serverPublicEphemeral = parsedMessage.GetProperty("srp").GetProperty("B").GetString()!;
        var serverSalt = parsedMessage.GetProperty("srp").GetProperty("s").GetString()!;

        var password = await _passwordProvider.GetPassword();
        var sessionM = _keePassSrp.SetupSession(password, serverPublicEphemeral, serverSalt);

        var proofMessage = new Dictionary<string, dynamic>
        {
            {"protocol", "setup"},
            {"srp", new Dictionary<string, dynamic>
            {
                { "stage", "proofToServer" },
                { "M", sessionM },
                { "securityLevel", 2 }
            }},
            {"version", 69632}
        };
        var proofMessageJson = JsonSerializer.Serialize(proofMessage);
        Send(proofMessageJson);
    }

    private void VerifyServerProof(JsonElement parsedMessage)
    {
        var m2Exists = parsedMessage.GetProperty("srp").TryGetProperty("M2", out var m2);

        if (!m2Exists)
        {
            Console.Out.WriteLine(_keePassSrp.DumpState());
            return;
        }
        
        var serverM2 = parsedMessage.GetProperty("srp").GetProperty("M2").GetString()!;
        _keePassSrp.ValidateServerProof(serverM2);

        _keyStorage.StoreKeyAsync(_keePassSrp.GetKey()).Wait();
     
        _onHandshakeCompleted.SetResult();
    }
    
    private void OnClosed(object? sender, EventArgs e)
    {
        if (e is ClosedEventArgs closedE)
        {
            Console.Out.WriteLine($"CLOSED: {closedE.Code} {closedE.Reason}");
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
        if (_webSocket.State != WebSocketState.Closing && _webSocket.State != WebSocketState.Closed)
        {
            await _webSocket.CloseAsync();
        }
    }

    public async Task<JsonElement> SendEncryptedJsonRpc(Dictionary<string, dynamic> payload)
    {
        Debug.Assert(!payload.ContainsKey("Id"), "Payload may not contain an ID!");
        
        var requestId = Guid.NewGuid().ToString();
        payload["id"] = requestId;

        var serializedPayload = JsonSerializer.Serialize(payload);
        
        var encryptedMessage = KeePassCrypto.Encrypt(serializedPayload, _keyStorage.GetKey().Result);
        var data = new Dictionary<string, dynamic?>
        {
            { "protocol", "jsonrpc" },
            { "srp", null },
            { "key", null },
            { "error", null },
            { "jsonrpc", encryptedMessage },
            // TODO figure out how to get the correct version and where to store it :)
            { "version", 69632 }
        };
        var serializerOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        var dataJson = JsonSerializer.Serialize(data, serializerOptions);
        Send(dataJson);
        
        _results[requestId] = new TaskCompletionSource<JsonElement>();

        return await _results[requestId].Task;
    }

    public async Task<IEnumerable<Entry>> GetPasswords(string search)
    {
        var data = new Dictionary<string, dynamic>
        {
            {"jsonrpc", "2.0"},
            {"params", new object?[]{Array.Empty<string>(), null, null, "LSTnoForms", false, null, null, search, null}},
            {"method", "FindLogins"},
            {"id", 42},
        };

        var serializerOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new JsonStringEnumConverter() }
        };

        var result = await SendEncryptedJsonRpc(data);

        return result.GetProperty("result").Deserialize<IEnumerable<Entry>>(serializerOptions) ?? Array.Empty<Entry>();
    }
    
    public void Send(string message)
    {
        Console.Out.WriteLine($">> {message}");
        _webSocket.Send(message);
    }
}
