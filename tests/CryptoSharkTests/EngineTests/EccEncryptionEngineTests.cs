using CryptoShark;
using CryptoShark.Engine;
using CryptoShark.Enums;
using CryptoShark.Utilities;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.EngineTests
{
    internal class EccEncryptionEngineTests
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
        public void EccEncryptionTestNoCompression(EncryptionAlgorithm encryptionAlgorithm)
        {
            EccEncryption eccEncryption = new EccEncryption(_mockLogger.Object);
            var eccPrivateKey = _cryptoSharkUtilities.CreateEccKey(ECCurve.NamedCurves.nistP384, _password).Value;
            var eccPublicKey = _cryptoSharkUtilities.GetEccPublicKey(eccPrivateKey, _password).Value;

            var encrypted = eccEncryption.Encrypt(_sampleData, eccPublicKey, eccPrivateKey, encryptionAlgorithm,
                CryptoShark.Enums.HashAlgorithm.SHA3_256, _password, false);

            Assert.That(encrypted.IsSuccess, Is.True);
            Assert.That(encrypted.Value, Is.Not.Null);
            Assert.That(encrypted.Value.EncryptionAlgorithm, Is.EqualTo(encryptionAlgorithm));
            Assert.That(encrypted.Value.Nonce, Is.Not.Null);
            Assert.That(encrypted.Value.PublicKey, Is.Not.Null);
            Assert.That(encrypted.Value.EncryptedData, Is.Not.Null);
            Assert.That(encrypted.Value.Signature, Is.Not.Null);

            var decrypted = eccEncryption.Decrypt(encrypted.Value.EncryptedData, eccPublicKey, eccPrivateKey, 
                encryptionAlgorithm, encrypted.Value.HashAlgorithm, encrypted.Value.Nonce, encrypted.Value.Signature, _password);

            Assert.That(encrypted.IsSuccess, Is.True);
            Assert.That(decrypted.Value.Span.SequenceEqual(_sampleData.Span), Is.True);
        }

        [TestCaseSource(nameof(GetEncryptionAlgorithms))]
        public void EccEncryptionTestCompression(EncryptionAlgorithm encryptionAlgorithm)
        {
            EccEncryption eccEncryption = new EccEncryption(_mockLogger.Object);
            var eccPrivateKey = _cryptoSharkUtilities.CreateEccKey(ECCurve.NamedCurves.nistP384, _password).Value;
            var eccPublicKey = _cryptoSharkUtilities.GetEccPublicKey(eccPrivateKey, _password).Value;

            var encrypted = eccEncryption.Encrypt(_sampleData, eccPublicKey, eccPrivateKey, encryptionAlgorithm,
                CryptoShark.Enums.HashAlgorithm.SHA3_256, _password, true);

            Assert.That(encrypted.IsSuccess, Is.True);
            Assert.That(encrypted.Value, Is.Not.Null);
            Assert.That(encrypted.Value.EncryptionAlgorithm, Is.EqualTo(encryptionAlgorithm));
            Assert.That(encrypted.Value.Nonce, Is.Not.Null);
            Assert.That(encrypted.Value.PublicKey, Is.Not.Null);
            Assert.That(encrypted.Value.EncryptedData, Is.Not.Null);
            Assert.That(encrypted.Value.Signature, Is.Not.Null);

            var decrypted = eccEncryption.Decrypt(encrypted.Value.EncryptedData, eccPublicKey, eccPrivateKey,
                encryptionAlgorithm, encrypted.Value.HashAlgorithm, encrypted.Value.Nonce, encrypted.Value.Signature, _password);

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
