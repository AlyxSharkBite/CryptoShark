using CryptoShark.Enums;
using CryptoShark.Utilities;
using Microsoft.Extensions.Logging;
using Moq;
using Org.BouncyCastle.Security;
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
        private static RsaHelper _rsaHelper = new RsaHelper();

        private ReadOnlyMemory<byte> _sampleData;        
        private Mock<ILogger> _mockLogger;
        private SecureString _password;       
        private SecureRandom _random;
        
        [SetUp]
        public void Setup()
        {
            byte[] sample = new byte[1024 * 10]; // 10Mb
            _random = new SecureRandom();
            _random.NextBytes(sample);
            _sampleData = sample.ToArray();
            _mockLogger = new Mock<ILogger>(MockBehavior.Loose);                        
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
            Assert.That(privateKeyResult.Value.IsEmpty, Is.False);
        }

        [TestCaseSource(nameof(GetEccCurves))]
        public void GetEccPublicKeyTests(ECCurve curve)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);

            var privateKey = cryptoSharkUtilities.CreateEccKey(curve, _password).Value;

            var publicKeyResult = cryptoSharkUtilities.GetEccPublicKey(privateKey, _password);
            Assert.That(publicKeyResult.IsSuccess, Is.True);
            Assert.That(publicKeyResult.Value.IsEmpty, Is.False);
        }

        [TestCaseSource(nameof(GetRsaKeySizes))]
        public void CreateRsaPrivateKeyTestsBouncyCastle(RsaKeySize rsaKeySize)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);

            var keyResult = cryptoSharkUtilities.CreateRsaKey(rsaKeySize, _password, false);
            Assert.That(keyResult.IsSuccess, Is.True);
            Assert.That(keyResult.Value.IsEmpty, Is.False);
        }

        [TestCaseSource(nameof(GetRsaKeySizes))]
        public void CreateRsaPrivateKeyTestsDotNet(RsaKeySize rsaKeySize)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);

            var keyResult = cryptoSharkUtilities.CreateRsaKey(rsaKeySize, _password, true);
            Assert.That(keyResult.IsSuccess, Is.True);
            Assert.That(keyResult.Value.IsEmpty, Is.False);
        }

        [TestCaseSource(nameof(GetRsaKeySizes))]
        public void GetRsaPublicKeyTests(RsaKeySize rsaKeySize)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);

            var privateKey = new ReadOnlyMemory<byte>(_rsaHelper
                    .RsaKeyData
                    .First(x=>x.RsaKeySize == rsaKeySize)
                .RsaPrivateKey);                

            var publicKeyResult = cryptoSharkUtilities.GetRsaPublicKey(privateKey, _password);
            Assert.That(publicKeyResult.IsSuccess, Is.True);
            Assert.That(publicKeyResult.Value.IsEmpty, Is.False);
        }

        [TestCaseSource(nameof(GetHashAlgorithms))]
        public void HashToStringTests(CryptoShark.Enums.HashAlgorithm hashAlgorithm)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);
            foreach(StringEncoding enoding in GetStringEncodings())
            {
                var hashResult = cryptoSharkUtilities.Hash(_sampleData, enoding, hashAlgorithm);
                Assert.That(hashResult.IsSuccess, Is.True);
                Assert.That(String.IsNullOrEmpty(hashResult.Value), Is.False);
            }

            foreach (StringEncoding enoding in GetStringEncodings())
            {
                var hashResult = cryptoSharkUtilities.Hash(_sampleData, enoding, hashAlgorithm);
                Assert.That(hashResult.IsSuccess, Is.True);
                Assert.That(String.IsNullOrEmpty(hashResult.Value), Is.False);
            }
        }

        [TestCaseSource(nameof(GetHashAlgorithms))]
        public void HashToBytesTests(CryptoShark.Enums.HashAlgorithm hashAlgorithm)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);

            var hashResult = cryptoSharkUtilities.Hash(_sampleData, hashAlgorithm);
            Assert.That(hashResult.IsSuccess, Is.True);
            Assert.That(hashResult.Value.IsEmpty, Is.False);

            hashResult = cryptoSharkUtilities.Hash(_sampleData, hashAlgorithm);
            Assert.That(hashResult.IsSuccess, Is.True);
            Assert.That(hashResult.Value.IsEmpty, Is.False);
        }

        [TestCaseSource(nameof(GetHashAlgorithms))]
        public void HmacToStringTests(CryptoShark.Enums.HashAlgorithm hashAlgorithm)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);
            var key = GetKey();

            foreach (StringEncoding enoding in GetStringEncodings())
            {
                var hashResult = cryptoSharkUtilities.Hmac(_sampleData, key, enoding, hashAlgorithm);
                Assert.That(hashResult.IsSuccess, Is.True);
                Assert.That(String.IsNullOrEmpty(hashResult.Value), Is.False);
            }

            foreach (StringEncoding enoding in GetStringEncodings())
            {
                var hashResult = cryptoSharkUtilities.Hmac(_sampleData, key, enoding, hashAlgorithm);
                Assert.That(hashResult.IsSuccess, Is.True);
                Assert.That(String.IsNullOrEmpty(hashResult.Value), Is.False);
            }
        }

        [TestCaseSource(nameof(GetHashAlgorithms))]
        public void HmacToBytesTests(CryptoShark.Enums.HashAlgorithm hashAlgorithm)
        {
            CryptoSharkUtilities cryptoSharkUtilities = new CryptoSharkUtilities(_mockLogger.Object);
            var key = GetKey();

            var hashResult = cryptoSharkUtilities.Hmac(_sampleData, key, hashAlgorithm);
            Assert.That(hashResult.IsSuccess, Is.True);
            Assert.That(hashResult.Value.IsEmpty, Is.False);

            hashResult = cryptoSharkUtilities.Hmac(_sampleData, key, hashAlgorithm);
            Assert.That(hashResult.IsSuccess, Is.True);
            Assert.That(hashResult.Value.IsEmpty, Is.False);

        }

        private static ReadOnlyMemory<byte> GetKey()
        {
            ReadOnlyMemory<byte> key = null;

            using (var aesCng = AesCng.Create())
            {
                aesCng.KeySize = 256;
                aesCng.GenerateKey();
                key = aesCng.Key;
            }
            
            return key;
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
