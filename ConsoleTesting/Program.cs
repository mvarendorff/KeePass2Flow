using Keepass2Client;
using Keepass2Client.Setup;

var srp = new KeePassSrp
{
    Username = "example"
};

var keyStorage = new KeePassKeyFileStorage(srp.Username);

var client = new KeePass2Client(srp, keyStorage, new KeePassPasswordFromConsoleProvider());
await client.InitAsync();

string input;
do
{
    Console.Out.WriteLine("JSON-RPC Payload:");
    input = await Console.In.ReadLineAsync() ?? "break";
    if (input.StartsWith("break")) break;

    var entries = await client.GetPasswords(input);
    Console.Out.WriteLine("");
    Console.Out.WriteLine("I found these awesome passwords: " + string.Join(", ", entries.Select(e => "\"" + e.Password + "\"")));
    Console.Out.WriteLine("");
} while (true);

await client.Dispose();
await client.Closed;
