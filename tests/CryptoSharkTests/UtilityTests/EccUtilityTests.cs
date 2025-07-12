using CryptoShark;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.UtilityTests
{
    internal class EccUtilityTests
    {
        private const string PRIVATE_KEY_PW = "PrivatePassword";

        [SetUp]
        public void Setup()
        {
        }

        [Test, Sequential]
        public void EccKeyGenerationTest()
        {
            var eccPrivateKey = EccEncryption.ECCUtilities.CreateEccKey(ECCurve.NamedCurves.brainpoolP384t1);
            Assert.That(eccPrivateKey.IsEmpty, Is.False);

            var eccPublicKey = EccEncryption.ECCUtilities.GetEccPublicKey(eccPrivateKey);
            Assert.That(eccPublicKey.IsEmpty, Is.False);
        }

        [Test, Sequential]
        public void EncryptEccKeyDefaultTest()
        {
            var eccPrivateKey = EccEncryption.ECCUtilities.CreateEccKey(ECCurve.NamedCurves.brainpoolP384t1);
            var encryptedKey = EccEncryption.ECCUtilities.EncryptEccKey(eccPrivateKey, PRIVATE_KEY_PW);
            Assert.That(encryptedKey.IsEmpty, Is.False);

            var eccPublicKey = EccEncryption.ECCUtilities.GetEccPublicKey(eccPrivateKey, PRIVATE_KEY_PW);
            Assert.That(eccPublicKey.IsEmpty, Is.False);
        }
    }
}
