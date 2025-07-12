using CryptoShark;
using CryptoShark.Interfaces;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.UtilityTests
{
    internal class HashUtilitiesTests
    {
        private IHash _hash = Utilities.Instance;        
        private byte[] _sampleData;
        private byte[] _key;   

        [SetUp]
        public void Setup()
        {
            _sampleData = Enumerable.Repeat<byte>(0x01, 256).ToArray();
            _sampleData = Enumerable.Repeat<byte>(0x01, 32).ToArray();
        }

        [TestCaseSource("GetHashAlgorithms")]        
        public void HashStringValueTests(CryptoShark.Enums.HashAlgorithm algorithm)
        {
            // Base64
            var hashBase64 = _hash.Hash(
                data: _sampleData,
                encoding: CryptoShark.Enums.StringEncoding.Base64,
                hashAlgorithm: algorithm);

            // UrlBase64
            var hashBase64Url = _hash.Hash(
                data: _sampleData,
                encoding: CryptoShark.Enums.StringEncoding.UrlBase64,
                hashAlgorithm: algorithm);

            // UrlBase64
            var hashHex = _hash.Hash(
                data: _sampleData,
                encoding: CryptoShark.Enums.StringEncoding.Hex,
                hashAlgorithm: algorithm);

            Assert.That(String.IsNullOrEmpty(hashBase64), Is.False);
            Assert.That(String.IsNullOrEmpty(hashBase64Url), Is.False);
            Assert.That(String.IsNullOrEmpty(hashHex), Is.False);
        }
        
        [TestCaseSource("GetHashAlgorithms")]
        public void HashByteValueTests(CryptoShark.Enums.HashAlgorithm algorithm)
        {            
            var hashBytes = _hash.Hash(
                data: _sampleData,                
                hashAlgorithm: algorithm);

            Assert.That(hashBytes.IsEmpty, Is.False);
        }

        [TestCaseSource("GetHashAlgorithms")]
        public void HmacStringValueTests(CryptoShark.Enums.HashAlgorithm algorithm)
        {
            // Base64
            var hashBase64 = _hash.Hmac(
                data: _sampleData,
                key: _key,
                encoding: CryptoShark.Enums.StringEncoding.Base64,
                hashAlgorithm: algorithm);

            // UrlBase64
            var hashBase64Url = _hash.Hmac(
                data: _sampleData,
                key: _key,
                encoding: CryptoShark.Enums.StringEncoding.UrlBase64,
                hashAlgorithm: algorithm);

            // UrlBase64
            var hashHex = _hash.Hmac(
                data: _sampleData,
                key: _key,
                encoding: CryptoShark.Enums.StringEncoding.Hex,
                hashAlgorithm: algorithm);

            Assert.That(String.IsNullOrEmpty(hashBase64), Is.False);
            Assert.That(String.IsNullOrEmpty(hashBase64Url), Is.False);
            Assert.That(String.IsNullOrEmpty(hashHex), Is.False);
        }

        [TestCaseSource("GetHashAlgorithms")]
        public void HmacByteValueTests(CryptoShark.Enums.HashAlgorithm algorithm)
        {
            var hashBytes = _hash.Hmac(
                data: _sampleData,
                key: _key,
                hashAlgorithm: algorithm);

            Assert.That(hashBytes.IsEmpty, Is.False);
        }

        private static Array GetHashAlgorithms()
        {
            return Enum.GetValues(typeof(CryptoShark.Enums.HashAlgorithm));
        }
    }
}
