// ReSharper disable InconsistentNaming - inconsistent casing is due to this being a (mostly) close port of an existing implementation.

using System.Globalization;
using System.Numerics;
using System.Text.Json;
using Keepass2Client.Extensions;

namespace Keepass2Client.Setup;

/*
 * KeePass has an SRP implementation that is not compatible with either BouncyCastle nor the SecureRemotePassword package.
 *
 * So we implement it in here as a port of https://github.com/kee-org/browser-addon/blob/master/src/background/SRP.ts
 */
public class KeePassSrp
{
    private BigInteger A;
    private BigInteger a;

    # region stored for debug
    private string BStr = "unset";
    private BigInteger B = BigInteger.MinusOne;
    private string MStr = "unset";
    private string SrpPassword = "unset";
    # endregion stored for debug

    public required string Username;

    private const string NStr =
        "0d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43";

    private readonly BigInteger N = BigInteger.Parse(NStr, NumberStyles.HexNumber);
    private readonly BigInteger g = new(2);
    private readonly BigInteger k = BigInteger.Parse("0b7867f1299da8cc24ab93e08986ebc4d6a478ad0", NumberStyles.HexNumber);

    private BigInteger? S;

    private string? M2Str;

    public string AStr => A.ToString("X").TrimStart('0');

    public KeePassSrp()
    {
        GenerateKeypair();
    }

    private void GenerateKeypair()
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

    public string GetDebugInfoJson()
    {
        var state = new
        {
            bigA = A.ToString("X").TrimStart('0'),
            smallA = a.ToString("X").TrimStart('0'),
            BStr,
            B = B.ToString("X").TrimStart('0'),
            MStr,
            M2Str,
            SrpPassword,
        };

        return JsonSerializer.Serialize(state);
    }

    private BigInteger CustomParse(string hex)
    {
        var bytes = Convert.FromHexString(hex).Reverse().ToArray();
        return new BigInteger(bytes, true);
    }

    public string SetupSession(string password, string BStr, string serverSalt)
    {
        var B = BigInteger.Parse("0" + BStr, NumberStyles.HexNumber);

        var u = CustomParse(Utils.Hash(AStr + BStr));
        var x = CustomParse(Utils.Hash(serverSalt + password));

        var kgx = k * BigInteger.ModPow(g, x, N);
        var aux = a + u * x;

        S = BigInteger.ModPow(B - kgx, aux, N);

        var SStr = S.Value.ToString("X").TrimStart('0');

        var MStr = Utils.Hash(AStr + BStr + SStr);
        M2Str = Utils.Hash(AStr + MStr + SStr).ToUpper();

        this.B = B;
        this.BStr = BStr;
        this.MStr = MStr;
        this.SrpPassword = password;

        return MStr;
    }

    public void ValidateServerProof(string serverM2Str)
    {
        if (serverM2Str != M2Str) throw new Exception("Server key does not match!");
    }

    public string GetKey()
    {
        return Utils.Hash(S!.Value.ToString("X").TrimStart('0'));
    }

    public void Reset()
    {
        GenerateKeypair();
        B = BigInteger.MinusOne;
        BStr = "unset";
        MStr = "unset";
        SrpPassword = "unset";
    }
}
