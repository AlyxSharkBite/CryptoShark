using CryptoShark.CryptographicProviders;
using CryptoShark.Options;
using CryptoShark.Requests;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Cryptography;

namespace CryptoSharkTests;

public class CryptoSharkRsaCryptographyTests
{
    private static Mock<ILogger> _mockLogger = new Mock<ILogger>();
    private readonly string _password = "Abc123";
    private readonly byte[] _sampleData = new byte[7514];

    [SetUp]
    public void Setup()
    {
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

    [TestCaseSource(nameof(CreateLoggers))]
    public void EncryptionSuccessTests(ILogger logger)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkRsaCryptography.Create(logger);

        using var keyParams = new RsaKeyParameters(_password, CryptoShark.Enums.RsaKeySize.KeySize2048);

        var privateKey = utilities.CreateAsymetricKey(keyParams);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(_password),
            CryptoShark.Enums.CryptographyType.RivestShamirAdlemanCryptography);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            _password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void EncryptionFailNullParamsTests(ILogger logger)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkRsaCryptography.Create(logger);

        using var keyParams = new RsaKeyParameters(_password, CryptoShark.Enums.RsaKeySize.KeySize2048);

        var privateKey = utilities.CreateAsymetricKey(keyParams);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(_password),
            CryptoShark.Enums.CryptographyType.RivestShamirAdlemanCryptography);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = default(AsymetricEncryptionRequest);

        Assert.Throws<ArgumentNullException>(() => provider.Encrypt(request));

    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void EncryptionFailInvalidParamsTests(ILogger logger)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkRsaCryptography.Create(logger);

        using var keyParams = new EccKeyParameters(_password, ECCurve.NamedCurves.nistP256);
        var privateKey = utilities.CreateAsymetricKey(keyParams);

        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(_password),
            CryptoShark.Enums.CryptographyType.EllipticalCurveCryptography);        
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            _password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        Assert.Throws<CryptographicException>(() => provider.Encrypt(request));

    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void DecryptionSuccessTests(ILogger logger)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkRsaCryptography.Create(logger);

        using var keyParams = new RsaKeyParameters(_password, CryptoShark.Enums.RsaKeySize.KeySize2048);

        var privateKey = utilities.CreateAsymetricKey(keyParams);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(_password),
            CryptoShark.Enums.CryptographyType.RivestShamirAdlemanCryptography);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            _password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);

        var decrypted = provider.Decrypt(encrypted, privateKey, utilities.StringToSecureString(_password));
        Assert.That(decrypted.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void DecryptionFailNullParamTests(ILogger logger)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkRsaCryptography.Create(logger);

        using var keyParams = new RsaKeyParameters(_password, CryptoShark.Enums.RsaKeySize.KeySize2048);

        var privateKey = utilities.CreateAsymetricKey(keyParams);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(_password),
            CryptoShark.Enums.CryptographyType.RivestShamirAdlemanCryptography);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            _password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var privateKeyArray = privateKey.ToArray();

        Assert.Throws<CryptographicException>(() => provider.Decrypt(ReadOnlyMemory<byte>.Empty, privateKeyArray,
            utilities.StringToSecureString(_password)));

    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void DecryptionFailInvalidParamTests(ILogger logger)
    {
        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkRsaCryptography.Create(logger);

        using var keyParams = new RsaKeyParameters(_password, CryptoShark.Enums.RsaKeySize.KeySize2048);

        var privateKey = utilities.CreateAsymetricKey(keyParams);
        Assert.That(privateKey.IsEmpty, Is.False);

        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(_password),
            CryptoShark.Enums.CryptographyType.RivestShamirAdlemanCryptography);
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
}
