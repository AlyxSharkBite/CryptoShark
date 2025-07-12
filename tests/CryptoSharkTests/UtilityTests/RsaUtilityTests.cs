using CryptoShark;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.UtilityTests
{
    internal class RsaUtilityTests
    {
        private const string PRIVATE_KEY_PW = "PrivatePassword";

        [SetUp]
        public void Setup()
        {
        }

        [Test, Sequential]
        public void RsaKeyGenerationTest()
        {
            var rsaPrivateKey = RsaEncryption.RSAUtilities.CreateRsaKey(4096);
            Assert.That(rsaPrivateKey.IsEmpty, Is.False);

            var rsaPublicKey = RsaEncryption.RSAUtilities.GetRsaPublicKey(rsaPrivateKey);
            Assert.That(rsaPublicKey.IsEmpty, Is.False);
        }

        [Test, Sequential]
        public void EncryptRsaKeyTest()
        {
            var rsaPrivateKey = RsaEncryption.RSAUtilities.CreateRsaKey(4096);
            var encryptedKey = RsaEncryption.RSAUtilities.EncryptRsaKey(rsaPrivateKey, PRIVATE_KEY_PW);
            Assert.That(encryptedKey.IsEmpty, Is.False);           

            var rsaPublicKey = RsaEncryption.RSAUtilities.GetRsaPublicKey(encryptedKey, PRIVATE_KEY_PW);
            Assert.That(rsaPublicKey.IsEmpty, Is.False);
        }
    }
}
