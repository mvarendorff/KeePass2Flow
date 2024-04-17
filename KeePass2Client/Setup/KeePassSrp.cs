// ReSharper disable InconsistentNaming - inconsistent casing is due to this being a (mostly) close port of an existing implementation.

using System.Globalization;
using System.Numerics;
using Keepass2Client.Extensions;

namespace Keepass2Client.Setup;

/*
 * KeePass has an SRP implementation that is not compatible with either BouncyCastle nor the SecureRemotePassword package.
 *
 * So we implement it in here as a port of https://github.com/kee-org/browser-addon/blob/master/src/background/SRP.ts
 */
public class KeePassSrp
{
    public readonly BigInteger A;
    private readonly BigInteger a;

    private BigInteger? B;
    private string? s;
    private string? MStr;
    
    public required string Username;
    
    private const string NStr =
        "0d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43";

    private readonly BigInteger N = BigInteger.Parse(NStr, NumberStyles.HexNumber);
    private readonly BigInteger g = new(2);
    private readonly BigInteger k = BigInteger.Parse("0b7867f1299da8cc24ab93e08986ebc4d6a478ad0", NumberStyles.HexNumber);

    private BigInteger? S;
    private string? _key;
    
    private string? M2Str;

    public KeePassSrp()
    {
        var random = new Random();
        a = random.NextBigInteger(32);
        A = BigInteger.ModPow(g, a, N);
        while (A % N == 0)
        {
            a = random.NextBigInteger(32);
            A = BigInteger.ModPow(g, a, N);
        }
    }

    public string SetupSession(string password, string BStr, string serverSalt)
    {
        var AStr = A.ToString("X");
        var B = BigInteger.Parse("0" + BStr, NumberStyles.HexNumber);
        this.B = B;
        this.s = serverSalt;

        var u = BigInteger.Parse("0" + Utils.Hash(AStr + BStr), NumberStyles.HexNumber);
        var x = BigInteger.Parse("0" + Utils.Hash(serverSalt + password), NumberStyles.HexNumber);

        var kgx = k * BigInteger.ModPow(g, x, N);
        var aux = a + u * x;

        S = BigInteger.ModPow(B - kgx, aux, N);
        var MStr = Utils.Hash(AStr + BStr + S.Value.ToString("X"));
        this.MStr = MStr;
        M2Str = Utils.Hash(AStr + MStr + S.Value.ToString("X")).ToUpper();

        return MStr;
    }

    public void ValidateServerProof(string serverM2Str)
    {
        if (serverM2Str != M2Str) throw new Exception("Server key does not match!");
    }

    public string GetKey()
    {
        return _key ??= Utils.Hash(S!.Value.ToString("X"));
    }

    public string DumpState()
    {
        return $"""
               A = {A.ToString("X")}
               a = {a.ToString("X")}
               B = {B?.ToString("X")}
               s = {s}
               S = {S?.ToString("X")}
               M = {MStr}
               """;
    }
    
}
