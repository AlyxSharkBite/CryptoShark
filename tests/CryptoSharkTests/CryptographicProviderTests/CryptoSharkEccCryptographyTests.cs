using CryptoShark.CryptographicProviders;
using CryptoShark.Interfaces;
using CryptoShark.Options;
using CryptoShark.Requests;
using CryptoShark.Utilities;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security;
using System.Security.Cryptography;

namespace CryptoSharkTests;

public class CryptoSharkEccCryptographyTests
{
    private static Mock<ILogger> _mockLogger = new Mock<ILogger>();
    private char[] _password = new char[] { 'A', 'b', 'c', '1', '2', '3' };
    private byte[] _sampleData = new byte[7514];

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
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkEccCryptography.Create(logger);

        using var keyParams = new EccKeyParameters(password, ECCurve.NamedCurves.nistP256);

        var privateKey = utilities.CreateAsymetricKey(keyParams);
        Assert.That(privateKey.IsEmpty, Is.False);

        Array.Copy(_password, password, _password.Length);
        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(password), 
            CryptoShark.Enums.CryptographyType.EllipticalCurveCryptography);
        Assert.That(privateKey.IsEmpty, Is.False);

        Array.Copy(_password, password, _password.Length);
        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData, 
            password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void EncryptionFailNullParamsTests(ILogger logger)
    {
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkEccCryptography.Create(logger);

        using var keyParams = new EccKeyParameters(password, ECCurve.NamedCurves.nistP256);

        var privateKey = utilities.CreateAsymetricKey(keyParams);
        Assert.That(privateKey.IsEmpty, Is.False);

        Array.Copy(_password, password, _password.Length);
        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(password),
            CryptoShark.Enums.CryptographyType.EllipticalCurveCryptography);
        Assert.That(privateKey.IsEmpty, Is.False);

        var request = default(AsymetricEncryptionRequest);

        Assert.Throws<ArgumentNullException>(() => provider.Encrypt(request));
        
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void EncryptionFailInvalidParamsTests(ILogger logger)
    {
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkEccCryptography.Create(logger);

        using var keyParams = new RsaKeyParameters(password, CryptoShark.Enums.RsaKeySize.KeySize1024);

        var privateKey = utilities.CreateAsymetricKey(keyParams);
        Assert.That(privateKey.IsEmpty, Is.False);

        Array.Copy(_password, password, _password.Length);
        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(password),
            CryptoShark.Enums.CryptographyType.RivestShamirAdlemanCryptography);
        Assert.That(privateKey.IsEmpty, Is.False);

        Array.Copy(_password, password, _password.Length);
        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        Assert.Throws<CryptographicException>(() => provider.Encrypt(request));

    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void DecryptionSuccessTests(ILogger logger)
    {
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkEccCryptography.Create(logger);

        using var keyParams = new EccKeyParameters(password, ECCurve.NamedCurves.nistP256);
        var privateKey = utilities.CreateAsymetricKey(keyParams);

        Array.Copy(_password, password, _password.Length);
        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(password),
            CryptoShark.Enums.CryptographyType.EllipticalCurveCryptography);

        Array.Copy(_password, password, _password.Length);
        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);

        Array.Copy(_password, password, _password.Length);
        var decrypted = provider.Decrypt(encrypted, privateKey, utilities.StringToSecureString(password));
        Assert.That(decrypted.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void DecryptionFailNullParamTests(ILogger logger)
    {
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkEccCryptography.Create(logger);

        using var keyParams = new EccKeyParameters(password, ECCurve.NamedCurves.nistP256);
        var privateKey = utilities.CreateAsymetricKey(keyParams);

        Array.Copy(_password, password, _password.Length);

        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(password),
            CryptoShark.Enums.CryptographyType.EllipticalCurveCryptography);

        Array.Copy(_password, password, _password.Length);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);

        var privateKeyArray = privateKey.ToArray();

        Array.Copy(_password, password, _password.Length);

        Assert.Throws<CryptographicException>(() => provider.Decrypt(ReadOnlyMemory<byte>.Empty, privateKeyArray, 
            utilities.StringToSecureString(password)));
        
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void DecryptionFailInvalidParamTests(ILogger logger)
    {
        var password = new char[_password.Length];
        Array.Copy(_password, password, _password.Length);

        var utilities = CryptoSharkCryptographyUtilities.Create(logger);
        var provider = CryptoSharkEccCryptography.Create(logger);

        using var keyParams = new EccKeyParameters(password, ECCurve.NamedCurves.nistP256);
        var privateKey = utilities.CreateAsymetricKey(keyParams);

        Array.Copy(_password, password, _password.Length);
        var publicKey = utilities.GetAsymetricPublicKey(privateKey, utilities.StringToSecureString(password),
            CryptoShark.Enums.CryptographyType.EllipticalCurveCryptography);

        var request = AsymetricEncryptionRequest.CreateRequest(publicKey.ToArray(), privateKey.ToArray(), _sampleData,
            password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);

        var privateKeyArray = new byte[privateKey.Length];
        
        Array.Copy(_password, password, _password.Length);
        Assert.Throws<CryptographicException>(() => provider.Decrypt(encrypted, privateKeyArray,
            utilities.StringToSecureString(password)));

    }

    private static Array CreateLoggers()
    {
        return new[] { _mockLogger.Object, null };
    }    
}
