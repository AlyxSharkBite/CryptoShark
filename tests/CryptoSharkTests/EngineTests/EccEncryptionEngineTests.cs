using CryptoShark;
using CryptoShark.Engine;
using CryptoShark.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.EngineTests
{
    internal class EccEncryptionEngineTests
    {
        private const string ECC_PRIVATE_KEY = "MIHOAgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCq/HeGtUABO0VumKoySesZSCTEyDDE1x89lqNIoA/jgL/WGF+Pf+zZpNOJTDRz0R6gBwYFK4EEACKhZANiAAQRZEwUyyoSg5eEs4RFAA7yiKlW84MtM9HqXiJatEnnhd50TBd9Sddk8DXZoVjazS5+WBlr42WNFOAe4EYxbRFkaudaHWKJyC5sndRx65CwCd4zitiiVRRzGpAhe60/IiagDTALBgNVHQ8xBAMCAIg=";
          
        private byte[] _sampleData;        
        private byte[] _eccPrivateKey;
        private byte[] _eccPublicKey;        

        [SetUp]
        public void Setup()
        {
            _sampleData = Encoding.UTF8.GetBytes("EncryptionEngineTests Data");           
            _eccPrivateKey = Convert.FromBase64String(ECC_PRIVATE_KEY);
            _eccPublicKey = EccEncryption.ECCUtilities.GetEccPublicKey(_eccPrivateKey).ToArray();            
        }

        [TestCaseSource("GetSerializationMethods")]
        public void EccEncryptionTest(EncryptionAlgorithm encryptionAlgorithm)
        {
            EccEncryption eccEncryption = new EccEncryption();

            var encrypted = eccEncryption.Encrypt(_sampleData, _eccPublicKey, _eccPrivateKey, encryptionAlgorithm);
            Assert.That(encrypted, Is.Not.EqualTo(null));
            Assert.That(encrypted.EncryptedData, Is.Not.EqualTo(null));
            Assert.That(encrypted.ECCSignature, Is.Not.EqualTo(null));
            Assert.That(encrypted.GcmNonce, Is.Not.EqualTo(null));

            var decrypted = eccEncryption.Decrypt(encrypted.EncryptedData, _eccPublicKey, _eccPrivateKey, 
                encryptionAlgorithm, encrypted.GcmNonce, encrypted.ECCSignature);
            
            Assert.That(decrypted.SequenceEqual(_sampleData), Is.True);
        }

        private static Array GetSerializationMethods()
        {
            return Enum.GetValues(typeof(CryptoShark.Enums.EncryptionAlgorithm));
        }
    }
}
