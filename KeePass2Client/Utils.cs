using System.Security.Cryptography;
using System.Text;

namespace Keepass2Client;

public static class Utils
{
    public static string Hash(string data)
    {
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var hashedBytes = SHA256.HashData(dataBytes);
        return Convert.ToHexString(hashedBytes).ToLower();
    }
}