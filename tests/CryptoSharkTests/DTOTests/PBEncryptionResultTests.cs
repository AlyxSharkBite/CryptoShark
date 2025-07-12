using CryptoShark.Dto;
using CryptoShark.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.DTOTests
{
    internal class PBEncryptionResultTests
    {
        private byte[] _sha384HmacTest = [0x01, 0x02, 0x03, 0x04, 0x05];
        private byte[] _pbkdfSaltTest = [0x06, 0x07, 0x08];
        private byte[] _gmcTestNonce = [0x09, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
        private byte[] _encryptedTestData = Enumerable.Repeat<byte>(0x01, 256).ToArray();
        private int _iterations = 1;

        [SetUp]
        public void Setup()
        {
        }

        [TestCaseSource("GetSerializationMethods")]
        public void PBEncryptionResultSerializationTest(SerializationMethod method)
        {
            PBEncryptionResult encryptionResult = new PBEncryptionResult(sha384Hmac: _sha384HmacTest, pbkdfSalt: _pbkdfSaltTest,
                encryptedData: _encryptedTestData, gcmNonce: _gmcTestNonce, encryptionAlgorithm: EncryptionAlgorithm.Aes, 
                iterations: _iterations);

            var data = encryptionResult.SerializeResult(method);

            Assert.That(data.Length, Is.GreaterThan(0));

            var encryptionResult2 = (PBEncryptionResult)PBEncryptionResult.Deserialize(data, method);

            Assert.That(encryptionResult2, Is.Not.EqualTo(null));
            Assert.That(encryptionResult2.EncryptedData.SequenceEqual(_encryptedTestData), Is.True);
            Assert.That(encryptionResult2.Sha384Hmac.SequenceEqual(_sha384HmacTest), Is.True);
            Assert.That(encryptionResult2.PbkdfSalt.SequenceEqual(_pbkdfSaltTest), Is.True);
            Assert.That(encryptionResult2.GcmNonce.SequenceEqual(_gmcTestNonce), Is.True);
            Assert.That(encryptionResult2.Algorithm == EncryptionAlgorithm.Aes, Is.True);
            Assert.That(encryptionResult2.Iterations == _iterations, Is.True);
        }

        private static Array GetSerializationMethods()
        {
            return Enum.GetValues(typeof(CryptoShark.Enums.SerializationMethod));
        }
    }
}
