using CryptoShark.CryptographicProviders;
using CryptoShark.Interfaces;
using CryptoShark.Options;
using CryptoSharkTests.MockItems;
using Microsoft.Extensions.Logging;
using Moq;
using System.Security.Cryptography;

namespace CryptoSharkTests;

public class Create
{    
    private static Mock<ILogger> _mockLogger = new Mock<ILogger>();
    private readonly string _password = "Abc123";
    private readonly byte[] _sampleData = new byte[7514];

    [SetUp]
    public void Setup()
    {       
    }

    [Test]
    public void CreateWithLoggerTest()
    {
        var provider = CryptoSharkCryptographyUtilities.Create(_mockLogger.Object);
        Assert.That(provider, Is.Not.Null);
    }

    [Test]
    public void CreateWithoutLoggerTest()
    {
        var provider = CryptoSharkCryptographyUtilities.Create();
        Assert.That(provider, Is.Not.Null);
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void CreateEccKeySuccessTest(ILogger logger)
    {
        var provider = CryptoSharkCryptographyUtilities.Create();

        var parameters = new EccKeyParameters(_password, ECCurve.NamedCurves.nistP384);
        Assert.That(parameters, Is.Not.Null);

        var key = provider.CreateAsymetricKey(parameters);
        Assert.That(key.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void CreateEccKeyFailNullParamsTest(ILogger logger)
    {
        var provider = CryptoSharkCryptographyUtilities.Create();

        EccKeyParameters parameters = default;
        Assert.That(parameters, Is.Null);

        Assert.Throws<ArgumentNullException>(()=> provider.CreateAsymetricKey(parameters));        
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void CreateEccKeyFailInvalidParamsTest(ILogger logger)
    {
        var provider = CryptoSharkCryptographyUtilities.Create();
        var mockParams = new MockAsymmetricKeyParameter();        

        Assert.Throws<CryptographicException>(() => provider.CreateAsymetricKey(mockParams));        
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void HashBytesToStringSuccess(ILogger logger)
    {
        var provider = CryptoSharkCryptographyUtilities.Create();
        var hash = provider.HashBytes(_sampleData, CryptoShark.Enums.HashAlgorithm.SHA3_256, CryptoShark.Enums.StringEncoding.Hex);

        Assert.That(String.IsNullOrEmpty(hash), Is.False);
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void HashBytesToStringFails(ILogger logger)
    {
        var provider = CryptoSharkCryptographyUtilities.Create();

        Assert.Throws<CryptographicException>(() => provider.HashBytes(_sampleData, (CryptoShark.Enums.HashAlgorithm)16, CryptoShark.Enums.StringEncoding.Hex));
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void HashBytesSuccess(ILogger logger)
    {
        var provider = CryptoSharkCryptographyUtilities.Create();
        var hash = provider.HashBytes(_sampleData, CryptoShark.Enums.HashAlgorithm.SHA3_256);

        Assert.That(hash.IsEmpty, Is.False);
    }

    [TestCaseSource(nameof(CreateLoggers))]
    public void HashBytesFails(ILogger logger)
    {
        var provider = CryptoSharkCryptographyUtilities.Create();

        Assert.Throws<CryptographicException>(() => provider.HashBytes(_sampleData, (CryptoShark.Enums.HashAlgorithm)16));
    }

    private static Array CreateLoggers()
    {
        return new[] { _mockLogger.Object, null };
    }
}
