using CryptoShark;
using CryptoShark.Enums;
using CryptoShark.Utilities;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.EngineTests
{
    public class PbEncryptionEngineTests
    {
        private static SecureStringUtilities _secureStringUtilities = new SecureStringUtilities();

        private ReadOnlyMemory<byte> _sampleData;
        private CryptoSharkUtilities _cryptoSharkUtilities;
        private Mock<ILogger> _mockLogger;
        private SecureString _password;

        [SetUp]
        public void Setup()
        {
            _mockLogger = new Mock<ILogger>(MockBehavior.Loose);
            _cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);
            _sampleData = Encoding.UTF8.GetBytes("EncryptionEngineTests Data");
            _password = StringToSecureString("Abc123");
        }

        [TearDown]
        public void Teardown()
        {
            _password.Dispose();
        }

        [TestCaseSource(nameof(GetEncryptionAlgorithms))]
        public void PbEncryptionTest(EncryptionAlgorithm encryptionAlgorithm)
        {
            PBEncryption rsaEncryption = new PBEncryption(_mockLogger.Object);           

            var encrypted = rsaEncryption.Encrypt(_sampleData, encryptionAlgorithm, HashAlgorithm.SHA3_256, _password);

            Assert.That(encrypted.IsSuccess, Is.True);
            Assert.That(encrypted.Value, Is.Not.Null);
            Assert.That(encrypted.Value.EncryptionAlgorithm, Is.EqualTo(encryptionAlgorithm));
            Assert.That(encrypted.Value.Nonce, Is.Not.Null);
            Assert.That(encrypted.Value.Hash, Is.Not.Null);
            Assert.That(encrypted.Value.Salt, Is.Not.Null);
            Assert.That(encrypted.Value.EncryptedData, Is.Not.Null);
            Assert.That(encrypted.Value.Iterations, Is.GreaterThan(0));

            var decrypted = rsaEncryption.Decrypt(encrypted.Value.EncryptedData, _password, encryptionAlgorithm,
                encrypted.Value.HashAlgorithm, encrypted.Value.Nonce, encrypted.Value.Salt, encrypted.Value.Hash, 
                encrypted.Value.Iterations);

            Assert.That(encrypted.IsSuccess, Is.True);
            Assert.That(decrypted.Value.Span.SequenceEqual(_sampleData.Span), Is.True);
        }

        private static Array GetEncryptionAlgorithms()
        {
            return Enum.GetValues(typeof(CryptoShark.Enums.EncryptionAlgorithm));
        }

        private static SecureString StringToSecureString(string s)
        {
            return _secureStringUtilities.StringToSecureString(s);
        }
    }
}
