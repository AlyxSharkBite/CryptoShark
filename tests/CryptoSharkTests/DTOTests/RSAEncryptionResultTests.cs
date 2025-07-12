using CryptoShark.Dto;
using CryptoShark.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.DTOTests
{
    internal class RSAEncryptionResultTests
    {
        private byte[] _rsaTestPublicKey = [0x01, 0x02, 0x03, 0x04, 0x05];
        private byte[] _rsaTestSignature = [0x06, 0x07, 0x08];
        private byte[] _gmcTestNonce = [0x09, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
        private byte[] _encryptionTestKey = [0x13, 0x14, 0x15, 0x16];
        private byte[] _encryptedTestData = Enumerable.Repeat<byte>(0x01, 256).ToArray();

        [SetUp]
        public void Setup()
        {
        }

        [TestCaseSource("GetSerializationMethods")]
        public void RSAEncryptionResultSerializationTest(SerializationMethod method)
        {
            RSAEncryptionResult encryptionResult = new RSAEncryptionResult(rsaPublicKey: _rsaTestPublicKey,
                rsaSignature: _rsaTestSignature, gcmNonce: _gmcTestNonce, encryptedData: _encryptedTestData,
                encryptionKey: _encryptionTestKey, algorithm: EncryptionAlgorithm.Aes);

            var data = encryptionResult.SerializeResult(method);

            Assert.That(data.Length, Is.GreaterThan(0));

            var encryptionResult2 = (RSAEncryptionResult)RSAEncryptionResult.Deserialize(data, method);

            Assert.That(encryptionResult2, Is.Not.EqualTo(null));
            Assert.That(encryptionResult2.EncryptedData.SequenceEqual(_encryptedTestData), Is.True);
            Assert.That(encryptionResult2.RSAPublicKey.SequenceEqual(_rsaTestPublicKey), Is.True);
            Assert.That(encryptionResult2.RSAPublicKey.SequenceEqual(_rsaTestPublicKey), Is.True);
            Assert.That(encryptionResult2.GcmNonce.SequenceEqual(_gmcTestNonce), Is.True);
            Assert.That(encryptionResult2.EncryptionKey.SequenceEqual(_encryptionTestKey), Is.True);
            Assert.That(encryptionResult2.Algorithm == EncryptionAlgorithm.Aes, Is.True);

        }

        private static Array GetSerializationMethods()
        {
            return Enum.GetValues(typeof(CryptoShark.Enums.SerializationMethod));
        }
    }
}
