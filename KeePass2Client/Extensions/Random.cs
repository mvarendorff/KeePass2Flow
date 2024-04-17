using System.Numerics;

namespace Keepass2Client.Extensions;

public static class RandomBigIntegerExtensions
{
    public static BigInteger NextBigInteger(this Random random, int byteCount)
    {
        var data = new byte[byteCount];
        random.NextBytes(data);
        return new BigInteger(data, isUnsigned: true);
    }
}
