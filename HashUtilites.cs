using CryptoShark.Enums;
using CryptoShark.Interfaces;
using System;
namespace CryptoShark
{
    /// <summary>
    ///     Class for performing Hashing
    /// </summary>
    public sealed class HashUtilites : IHash
    { 
        private static IHash _hash => Utilities.Instance;

        ///<inheritdoc/>
        public string Hash(ReadOnlySpan<byte> data, StringEncoding encoding, HashAlgorithm hashAlgorithm)
        {
            return _hash.Hash(data, encoding, hashAlgorithm);
        }

        ///<inheritdoc/>
        public ReadOnlySpan<byte> Hash(ReadOnlySpan<byte> data, HashAlgorithm hashAlgorithm)
        {
            return _hash.Hash(data, hashAlgorithm);
        }

        ///<inheritdoc/>
        public ReadOnlySpan<byte> Hmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, HashAlgorithm hashAlgorithm)
        {
            return _hash.Hmac(data, key, hashAlgorithm);
        }

        ///<inheritdoc/>
        public string Hmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, StringEncoding encoding, HashAlgorithm hashAlgorithm)
        {
            return _hash.Hmac(data, key, encoding, hashAlgorithm);
        }
    }
}
