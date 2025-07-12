using CryptoShark;
using CryptoShark.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.EngineTests
{
    internal class PbEncryptionEngineTests
    {        
        private const string PBE_PW = "Abc123";
        private byte[] _sampleData;        

        [SetUp]
        public void Setup()
        {
            _sampleData = Encoding.UTF8.GetBytes("EncryptionEngineTests Data");            
        }

        [TestCaseSource("GetSerializationMethods")]
        public void PBEncryptionTest(EncryptionAlgorithm encryptionAlgorithm)
        {
            PBEncryption pbEncryption = new PBEncryption();

            var encrypted = pbEncryption.Encrypt(_sampleData, PBE_PW, encryptionAlgorithm);
            Assert.That(encrypted.EncryptedData, Is.Not.EqualTo(null));
            Assert.That(encrypted.Sha384Hmac, Is.Not.EqualTo(null));
            Assert.That(encrypted.GcmNonce, Is.Not.EqualTo(null));
            Assert.That(encrypted.PbkdfSalt, Is.Not.EqualTo(null));
            Assert.That(encrypted.Iterations, Is.GreaterThan(1));

            var decrypted = pbEncryption.Decrypt(encrypted.EncryptedData, PBE_PW, encrypted.Algorithm,
                encrypted.GcmNonce, encrypted.PbkdfSalt, encrypted.Sha384Hmac, encrypted.Iterations);

            Assert.That(decrypted.SequenceEqual(_sampleData), Is.True);
        }

        private static Array GetSerializationMethods()
        {
            return Enum.GetValues(typeof(CryptoShark.Enums.EncryptionAlgorithm));
        }
    }
}
