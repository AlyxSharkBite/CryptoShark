﻿using CryptoShark;
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
    public class RsaEncryptionEngineTests
    {
        private static SecureStringUtilities _secureStringUtilities = new SecureStringUtilities();

        private byte[] _sampleData;
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
        public void RsaEncryptionTest(EncryptionAlgorithm encryptionAlgorithm)
        {
            RsaEncryption rsaEncryption = new RsaEncryption(_mockLogger.Object);
            var rsaPrivateKey = _cryptoSharkUtilities.CreateRsaKey(RsaKeySize.KeySize1024, _password).Value;
            var rsaPublicKey = _cryptoSharkUtilities.GetRsaPublicKey(rsaPrivateKey, _password).Value;

            var encrypted = rsaEncryption.Encrypt(_sampleData, rsaPublicKey, rsaPrivateKey, encryptionAlgorithm, HashAlgorithm.SHA3_256,
                _password, null);

            Assert.That(encrypted.IsSuccess, Is.True);
            Assert.That(encrypted.Value, Is.Not.Null);
            Assert.That(encrypted.Value.EncryptionAlgorithm, Is.EqualTo(encryptionAlgorithm));
            Assert.That(encrypted.Value.Nonce, Is.Not.Null);
            Assert.That(encrypted.Value.EncryptionKey, Is.Not.Null);
            Assert.That(encrypted.Value.EncryptedData, Is.Not.Null);
            Assert.That(encrypted.Value.Signature, Is.Not.Null);
            Assert.That(encrypted.Value.PublicKey, Is.Not.Null);

            var decrypted = rsaEncryption.Decrypt(encrypted.Value.EncryptedData, rsaPublicKey, rsaPrivateKey, encryptionAlgorithm,
                encrypted.Value.HashAlgorithm, encrypted.Value.Nonce, encrypted.Value.Signature, encrypted.Value.EncryptionKey,
                _password, null);

            Assert.That(encrypted.IsSuccess, Is.True);
            Assert.That(decrypted.Value.SequenceEqual(_sampleData), Is.True);
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
