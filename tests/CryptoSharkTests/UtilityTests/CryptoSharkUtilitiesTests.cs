using CryptoShark.Enums;
using CryptoShark.Utilities;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.UtilityTests
{
    public class CryptoSharkUtilitiesTests
    {
        private static SecureStringUtilities _secureStringUtilities = new SecureStringUtilities();

        private byte[] _sampleData;        
        private Mock<ILogger> _mockLogger;
        private SecureString _password;
        private static readonly object _lock = new object();

        [SetUp]
        public void Setup()
        {
            _mockLogger = new Mock<ILogger>(MockBehavior.Loose);            
            _sampleData = Encoding.UTF8.GetBytes("EncryptionEngineTests Data");
            _password = StringToSecureString("Abc123");
        }

        [TearDown]
        public void Teardown()
        {
            _password.Dispose();
        }

        [TestCaseSource(nameof(GetEccCurves))]
        public void CreateEccPrivateKeyTests(ECCurve curve)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);

            var privateKeyResult = cryptoSharkUtilities.CreateEccKey(curve, _password);
            Assert.That(privateKeyResult.IsSuccess, Is.True);
            Assert.That(privateKeyResult.Value, Is.Not.Null);
        }

        [TestCaseSource(nameof(GetEccCurves))]
        public void GetEccPublicKeyTests(ECCurve curve)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);

            var privateKey = cryptoSharkUtilities.CreateEccKey(curve, _password).Value;

            var publicKeyResult = cryptoSharkUtilities.GetEccPublicKey(privateKey, _password);
            Assert.That(publicKeyResult.IsSuccess, Is.True);
            Assert.That(publicKeyResult.Value, Is.Not.Null);
        }

        [TestCaseSource(nameof(GetRsaKeySizes))]
        public void CreateRsaPrivateKeyTests(RsaKeySize rsaKeySize)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);

            var keyResult = cryptoSharkUtilities.CreateRsaKey(rsaKeySize, _password);
            Assert.That(keyResult.IsSuccess, Is.True);
            Assert.That(keyResult.Value, Is.Not.Null);
        }

        [TestCaseSource(nameof(GetRsaKeySizes))]
        public void GetRsaPublicKeyTests(RsaKeySize rsaKeySize)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);

            var privateKey = cryptoSharkUtilities.CreateRsaKey(rsaKeySize, _password).Value;

            var publicKeyResult = cryptoSharkUtilities.GetRsaPublicKey(privateKey, _password);
            Assert.That(publicKeyResult.IsSuccess, Is.True);
            Assert.That(publicKeyResult.Value, Is.Not.Null);
        }

        [TestCaseSource(nameof(GetHashAlgorithms))]
        public void HashToStringTests(CryptoShark.Enums.HashAlgorithm hashAlgorithm)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);
            foreach(StringEncoding enoding in GetStringEncodings())
            {
                var hashResult = cryptoSharkUtilities.Hash(_sampleData.AsMemory(), enoding, hashAlgorithm);
                Assert.That(hashResult.IsSuccess, Is.True);
                Assert.That(String.IsNullOrEmpty(hashResult.Value), Is.False);
            }

            foreach (StringEncoding enoding in GetStringEncodings())
            {
                var hashResult = cryptoSharkUtilities.Hash(_sampleData.AsSpan(), enoding, hashAlgorithm);
                Assert.That(hashResult.IsSuccess, Is.True);
                Assert.That(String.IsNullOrEmpty(hashResult.Value), Is.False);
            }
        }

        [TestCaseSource(nameof(GetHashAlgorithms))]
        public void HashToBytesTests(CryptoShark.Enums.HashAlgorithm hashAlgorithm)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);

            var hashResult = cryptoSharkUtilities.Hash(_sampleData.AsMemory(), hashAlgorithm);
            Assert.That(hashResult.IsSuccess, Is.True);
            Assert.That(hashResult.Value, Is.Not.Null);

            hashResult = cryptoSharkUtilities.Hash(_sampleData.AsSpan(), hashAlgorithm);
            Assert.That(hashResult.IsSuccess, Is.True);
            Assert.That(hashResult.Value, Is.Not.Null);
        }

        [TestCaseSource(nameof(GetHashAlgorithms))]
        public void HmacToStringTests(CryptoShark.Enums.HashAlgorithm hashAlgorithm)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);
            var key = GetKey();

            foreach (StringEncoding enoding in GetStringEncodings())
            {
                var hashResult = cryptoSharkUtilities.Hmac(_sampleData.AsMemory(), key, enoding, hashAlgorithm);
                Assert.That(hashResult.IsSuccess, Is.True);
                Assert.That(String.IsNullOrEmpty(hashResult.Value), Is.False);
            }

            foreach (StringEncoding enoding in GetStringEncodings())
            {
                var hashResult = cryptoSharkUtilities.Hmac(_sampleData.AsSpan(), key, enoding, hashAlgorithm);
                Assert.That(hashResult.IsSuccess, Is.True);
                Assert.That(String.IsNullOrEmpty(hashResult.Value), Is.False);
            }
        }

        [TestCaseSource(nameof(GetHashAlgorithms))]
        public void HmacToBytesTests(CryptoShark.Enums.HashAlgorithm hashAlgorithm)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);
            var key = GetKey();

            var hashResult = cryptoSharkUtilities.Hmac(_sampleData.AsMemory(), key, hashAlgorithm);
            Assert.That(hashResult.IsSuccess, Is.True);
            Assert.That(hashResult.Value, Is.Not.Null);

            hashResult = cryptoSharkUtilities.Hmac(_sampleData.AsSpan(), key, hashAlgorithm);
            Assert.That(hashResult.IsSuccess, Is.True);
            Assert.That(hashResult.Value, Is.Not.Null);

        }

        private static ReadOnlySpan<byte> GetKey()
        {
            byte[] key = null;
            lock (_lock)
            {
                using var aesCng = AesCng.Create();
                aesCng.KeySize = 256;
                aesCng.GenerateKey();
                key = aesCng.Key;
            }
            return new ReadOnlySpan<byte>(key);
        }

        private static Array GetStringEncodings()
        {
            return Enum.GetValues(typeof(CryptoShark.Enums.StringEncoding));
        }

        private static Array GetRsaKeySizes()
        {
            return Enum.GetValues(typeof(CryptoShark.Enums.RsaKeySize));
        }

        private static Array GetHashAlgorithms()
        {
            return Enum.GetValues(typeof(CryptoShark.Enums.HashAlgorithm));
        }

        private static Array GetEccCurves()
        {
            var curves = new List<ECCurve>();

            foreach (PropertyInfo property in typeof(ECCurve.NamedCurves).GetProperties())
            {
                var curve = property.GetValue(null);
                if (curve == null)
                    continue;

                if (curve.GetType() == typeof(ECCurve))
                    curves.Add((ECCurve)curve);
            }

            return curves.ToArray();
        }

        private static SecureString StringToSecureString(string s)
        {
            return _secureStringUtilities.StringToSecureString(s);
        }
    }
}
