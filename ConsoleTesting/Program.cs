// See https://aka.ms/new-console-template for more information

using Keepass2Client;

var client = new KeePass2Client();
await client.InitAsync();

await client.Closed;
