using System.Security.Cryptography;
using System.Text;

namespace Keepass2Client.Crypto;

public class KeePassCrypto
{
    public static EncryptedMessage Encrypt(string message, string key)
    {
        var random = new Random();
        var iv = new byte[16];
        random.NextBytes(iv);

        var messageBytes = Encoding.UTF8.GetBytes(message);
        var keyBytes = Convert.FromHexString(key);

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Key = keyBytes;

        var encryptedBytes = aes.EncryptCbc(messageBytes, iv);
        var keyHashBytes = SHA1.HashData(keyBytes);

        var hmac = new byte[20 + encryptedBytes.Length + 16];
        Array.Copy(keyHashBytes, hmac, keyHashBytes.Length);
        Array.Copy(encryptedBytes, 0, hmac, keyHashBytes.Length, encryptedBytes.Length);
        Array.Copy(iv, 0, hmac, encryptedBytes.Length + keyHashBytes.Length, iv.Length);

        var hashedHMacBytes = SHA1.HashData(hmac);

        var encryptedBase64 = Convert.ToBase64String(encryptedBytes);
        var ivBase64 = Convert.ToBase64String(iv);
        var hmacBase64 = Convert.ToBase64String(hashedHMacBytes);

        return new EncryptedMessage(encryptedBase64, ivBase64, hmacBase64);
    }

    public static string Decrypt(EncryptedMessage message, string key)
    {
        var keyBytes = Convert.FromHexString(key);

        using var aes = Aes.Create();
        aes.Key = keyBytes;

        var messageBytes = Convert.FromBase64String(message.Message);
        var ivBytes = Convert.FromBase64String(message.Iv);

        // TODO validate hmac
        var hmacBytes = Convert.FromBase64String(message.Hmac);

        var decrypted = aes.DecryptCbc(messageBytes, ivBytes);

        return Encoding.UTF8.GetString(decrypted);
    }
}

public record EncryptedMessage(string Message, string Iv, string Hmac);
