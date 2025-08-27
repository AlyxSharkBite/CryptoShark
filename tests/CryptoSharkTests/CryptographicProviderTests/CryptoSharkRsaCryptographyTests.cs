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
    private char[] _password = new char[] { 'A', 'b', 'c', '1', '2', '3' };
    private byte[] _sampleData;
    private static RsaHelper _rsaHelper = new RsaHelper();

    [SetUp]
    public void Setup()
    {
        SecureRandom random = new SecureRandom();
        _sampleData = new byte[1024 * 100]; // 100kb
        random.NextBytes(_sampleData);               
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
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPrivateKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPublicKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(GetTestData))]
    public void EncryptionFailNullParamsTests(RsaTestData rsaTestData)
    {
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

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
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = new ReadOnlyMemory<byte>(new byte[256]);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = new ReadOnlyMemory<byte>(new byte[256]);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        Assert.Throws<CryptographicException>(() => provider.Encrypt(request));

    }

    [TestCaseSource(nameof(GetTestData))]
    public void DecryptionSuccessTests(RsaTestData rsaTestData)
    {
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = rsaTestData.RsaKeyData.RsaPrivateKey;
        Assert.That(privateKey.Length, Is.GreaterThan(0));

        var publicKey = rsaTestData.RsaKeyData.RsaPublicKey;
        Assert.That(publicKey.Length, Is.GreaterThan(0));

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);
        
        Array.Copy(_password, password, _password.Length);

        var decrypted = provider.Decrypt(encrypted, privateKey, utilities.StringToSecureString(password));
        Assert.That(decrypted.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(GetTestData))]
    public void DecryptionFailNullParamTests(RsaTestData rsaTestData)
    {
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = rsaTestData.RsaKeyData.RsaPrivateKey;
        Assert.That(privateKey.Length, Is.GreaterThan(0));

        var publicKey = rsaTestData.RsaKeyData.RsaPublicKey;
        Assert.That(publicKey.Length, Is.GreaterThan(0));

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);
                
        Array.Copy(_password, password, _password.Length);

        Assert.Throws<CryptographicException>(() => provider.Decrypt(ReadOnlyMemory<byte>.Empty, privateKey,
            utilities.StringToSecureString(password)));

    }

    [TestCaseSource(nameof(GetTestData))]
    public void DecryptionFailInvalidParamTests(RsaTestData rsaTestData)
    {
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(rsaTestData.Logger);
        var provider = CryptoSharkRsaCryptography.Create(rsaTestData.Logger);

        var privateKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPrivateKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = new ReadOnlyMemory<byte>(rsaTestData.RsaKeyData.RsaPublicKey);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var privateKeyArray = new byte[privateKey.Length];

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);
                
        Array.Copy(_password, password, _password.Length);

        Assert.Throws<CryptographicException>(() => provider.Decrypt(encrypted, privateKeyArray,
            utilities.StringToSecureString(password)));

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
