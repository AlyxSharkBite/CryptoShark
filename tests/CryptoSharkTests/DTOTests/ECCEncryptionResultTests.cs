using CryptoShark.Dto;
using CryptoShark.Enums;

namespace CryptoSharkTests.DTOTests;

internal class ECCEncryptionResultTests
{
    private byte[] _eccTestPublicKey = [0x01, 0x02, 0x03, 0x04, 0x05];
    private byte[] _eccTestSignature = [0x06, 0x07, 0x08];
    private byte[] _gmcTestNonce = [0x09, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
    private byte[] _encryptedTestData = Enumerable.Repeat<byte>(0x01, 256).ToArray();

    [SetUp]
    public void Setup()
    {
    }

    [TestCaseSource("GetSerializationMethods")]
    public void ECCEncryptionResultSerializationTest(SerializationMethod method)
    {
        ECCEncryptionResult encryptionResult = new ECCEncryptionResult(eccPublicKey: _eccTestPublicKey,
            eccSignature: _eccTestSignature, gcmNonce: _gmcTestNonce, encryptedData: _encryptedTestData,
            algorithm: EncryptionAlgorithm.Aes);

        var data = encryptionResult.SerializeResult(method);

        Assert.That(data.Length, Is.GreaterThan(0));

        var encryptionResult2 = (ECCEncryptionResult)ECCEncryptionResult.Deserialize(data, method);

        Assert.That(encryptionResult2, Is.Not.EqualTo(null));
        Assert.That(encryptionResult2.EncryptedData.SequenceEqual(_encryptedTestData), Is.True);
        Assert.That(encryptionResult2.ECCPublicKey.SequenceEqual(_eccTestPublicKey), Is.True);
        Assert.That(encryptionResult2.ECCSignature.SequenceEqual(_eccTestSignature), Is.True);
        Assert.That(encryptionResult2.GcmNonce.SequenceEqual(_gmcTestNonce), Is.True);
        Assert.That(encryptionResult2.Algorithm == EncryptionAlgorithm.Aes, Is.True);

    }

    private static Array GetSerializationMethods()
    {
        return Enum.GetValues(typeof(CryptoShark.Enums.SerializationMethod));
    }
}