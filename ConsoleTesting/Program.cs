// See https://aka.ms/new-console-template for more information

using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;
using Keepass2Client;
using SecureRemotePassword;


var client = new KeePass2Client();
await client.InitAsync();

string input;

var nStr =
    "d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43";

var srpClient = new SrpClient(new SrpParameters(() => new HMACSHA256(), nStr));
var salt = srpClient.GenerateSalt();

var username = "example";

var srpSetup = new Dictionary<string, dynamic>
{
    {"stage", "identifyToServer"},
    {"I", username},
    {"A", salt},
    {"securityLevel", 2}
};

var setupMessage = new Dictionary<string, dynamic?>
{
    { "protocol", "setup" },
    { "srp", srpSetup },
    { "key", null },
    {"version", 69632},
    {"features", new[] {"KPRPC_FEATURE_VERSION_1_6"}},
    {"clientTypeId", "kpflow"},
    {"clientDisplayName", "KeePass2Flow"},
    {"clientDisplayDescription", "Client-Display-Description-TODO"}
};

var setupJson = JsonSerializer.Serialize(setupMessage);
client.Send(setupJson);

// do
// {
//     input = await Console.In.ReadLineAsync() ?? "break";
//     client.Send(input);
// } while (!input.StartsWith("break"));

await client.Dispose();
await client.Closed;
