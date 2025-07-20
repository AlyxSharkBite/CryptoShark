using CryptoShark.CryptographicProviders;
using CryptoShark.Enums;
using CryptoShark.Options;
using CryptoShark.Requests;
using Microsoft.Extensions.Logging;
using Moq;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace CryptoSharkTests;

public class CryptoSharkRsaCryptographyTests
{
    private static Mock<ILogger> _mockLogger = new Mock<ILogger>();
    private readonly string _password = "Abc123";
    private  ReadOnlyMemory<byte> _sampleData;
    private static RsaHelper _rsaHelper = new RsaHelper();

    [SetUp]
    public void Setup()
    {
        SecureRandom random = new SecureRandom();
        byte[] sample = new byte[1024 * 10]; // 10Mb
        random.NextBytes(sample);
        _sampleData = sample.AsMemory();        
    }

    [Test]
    public void CreateWithLoggerTests()
    {
        var provider = CryptoSharkEccCryptography.Create(_mockLogger.Object);

        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void CreateWithoutLoggerTests()
    {
        var provider = CryptoSharkEccCryptography.Create();

        Assert.That(provider, Is.Not.Null);
    }

    [TestCaseSource(nameof(GetTestData))]
    public void EncryptionSuccessTests(RsaTestData rsaTestData)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPrivateKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPublicKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            _password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(GetTestData))]
    public void EncryptionFailNullParamsTests(RsaTestData rsaTestData)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPrivateKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPublicKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = default(AsymetricEncryptionRequest);

        Assert.Throws<ArgumentNullException>(() => provider.Encrypt(request));

    }

    [TestCaseSource(nameof(GetTestData))]
    public void EncryptionFailInvalidParamsTests(RsaTestData rsaTestData)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = new ReadOnlyMemory<byte>(new byte[256]);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = new ReadOnlyMemory<byte>(new byte[256]);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            _password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        Assert.Throws<CryptographicException>(() => provider.Encrypt(request));

    }

    [TestCaseSource(nameof(GetTestData))]
    public void DecryptionSuccessTests(RsaTestData rsaTestData)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPrivateKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPublicKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            _password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);

        var decrypted = provider.Decrypt(encrypted, privateKey, utilities.StringToSecureString(_password));
        Assert.That(decrypted.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(GetTestData))]
    public void DecryptionFailNullParamTests(RsaTestData rsaTestData)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPrivateKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPublicKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            _password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);        

        Assert.Throws<CryptographicException>(() => provider.Decrypt(ReadOnlyMemory<byte>.Empty, privateKey,
            utilities.StringToSecureString(_password)));

    }

    [TestCaseSource(nameof(GetTestData))]
    public void DecryptionFailInvalidParamTests(RsaTestData rsaTestData)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPrivateKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPublicKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            _password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var privateKeyArray = new byte[privateKey.Length];

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);

        Assert.Throws<CryptographicException>(() => provider.Decrypt(encrypted, privateKeyArray,
            utilities.StringToSecureString(_password)));

    }

    private static Array CreateLoggers()
    {
        return new[] { _mockLogger.Object, null };        
    }

    private static Array GetRsaKeySizes()
    {
        return Enum.GetValues(typeof(CryptoShark.Enums.RsaKeySize));
    }

    private static IEnumerable<RsaTestData> GetTestData() 
    { 
        List<RsaTestData> rsaTestData = new List<RsaTestData>();

        foreach(var keyData in _rsaHelper.RsaKeyData) 
        {
            rsaTestData.Add(new RsaTestData
            {
                RsaKeyData = keyData,
                Logger = null
            });

            rsaTestData.Add(new RsaTestData
            {
                RsaKeyData = keyData,
                Logger = _mockLogger.Object
            });
        }

        return rsaTestData;

    }
}
