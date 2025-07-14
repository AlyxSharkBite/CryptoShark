using CryptoShark.CryptographicProviders;
using CryptoShark.Requests;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security;
using System.Security.Cryptography;

namespace CryptoSharkTests;

public class CryptoSharkPasswordCryptographyTests
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
        var provider = CryptoSharkPasswordCryptography.Create(_mockLogger.Object);

        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void CreateWithOutLoggerTests()
    {
        var provider = CryptoSharkPasswordCryptography.Create();

        Assert.That(provider, Is.Not.Null);
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void EncryptionSuccessTests(ILogger logger)
    {
        var provider = CryptoSharkPasswordCryptography.Create(logger);
        var request = SemetricEncryptionRequest.CreateRequest(_sampleData, _password, CryptoShark.Enums.EncryptionAlgorithm.Aes);

        var encrypted = provider.Encrypt(request);
        Assert.That(encrypted.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void EncryptionFailsNullParamsTests(ILogger logger)
    {
        var provider = CryptoSharkPasswordCryptography.Create(logger);
        var request = default(SemetricEncryptionRequest);

        Assert.Throws<ArgumentNullException>(() => provider.Encrypt(request));        
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void EncryptionFailsInvalidParamsTests(ILogger logger)
    {
        var provider = CryptoSharkPasswordCryptography.Create(logger);
        var request = SemetricEncryptionRequest.CreateRequest(_sampleData, _password, (CryptoShark.Enums.EncryptionAlgorithm) 15);

        Assert.Throws<CryptographicException>(() => provider.Encrypt(request));
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void DecryptionSuccessTests(ILogger logger)
    {
        var provider = CryptoSharkPasswordCryptography.Create(logger);
        var request = SemetricEncryptionRequest.CreateRequest(_sampleData, _password, CryptoShark.Enums.EncryptionAlgorithm.Aes);
        var encrypted = provider.Encrypt(request);

        var decrypted = provider.Decrypt(encrypted, StringToSecureString(_password));
        Assert.That(decrypted.IsEmpty, Is.False);
       
    }    

    [TestCaseSource(nameof(CreateLoggers))]
    public void DecryptionFailsInvalidParamsTests(ILogger logger)
    {
        var provider = CryptoSharkPasswordCryptography.Create(logger);
        Assert.Throws<CryptographicException>(() => provider.Decrypt(ReadOnlyMemory<byte>.Empty, StringToSecureString(_password)));
    }

    private static Array CreateLoggers()
    {
        return new[] { _mockLogger.Object, null };
    }

    private static SecureString StringToSecureString(string s)
    {
        var ss = new SecureString();
        foreach (var c in s.ToCharArray())
            ss.AppendChar(c);

        ss.MakeReadOnly();

        return ss;
    }
}
