using CryptoShark.Utilities;
using Org.BouncyCastle.Math;

namespace CryptoSharkTests;

public class ECDsaSignatureTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void SerialiationTest()
    {
        BigInteger r = Org.BouncyCastle.Utilities.BigIntegers.CreateRandomInRange(
            BigInteger.Zero, new BigInteger(Int32.MaxValue.ToString()),
            new Org.BouncyCastle.Security.SecureRandom());

        BigInteger s = Org.BouncyCastle.Utilities.BigIntegers.CreateRandomInRange(
            BigInteger.Zero, new BigInteger(Int32.MaxValue.ToString()),
            new Org.BouncyCastle.Security.SecureRandom());

        var signature = new ECDsaSignature(r, s);
        Assert.That(signature, Is.Not.Null);

        var data = signature.ToArray();
        Assert.That(data.Length, Is.GreaterThan(0));
        
        var restoredignature = ECDsaSignature.FromByteArray(data);
        Assert.That(restoredignature, Is.Not.Null);
        Assert.That(restoredignature.r, Is.EqualTo(r));
        Assert.That(restoredignature.s, Is.EqualTo(s));
    }
}
