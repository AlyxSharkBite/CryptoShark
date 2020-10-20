using System;
namespace CryptoShark
{
    /// <summary>
    ///     Class for performing Hashing
    /// </summary>
    public sealed class HashUtilites
    { 
        private static Interfaces.IHash _hash => Utilities.Instance;

        /// <summary>
        ///     Hashes data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        public static string Hash(ReadOnlySpan<byte> data, StringEncoding encoding, HashAlgorithm hashAlgorithm)
        {
            return _hash.Hash(data, encoding, hashAlgorithm);
        }

        /// <summary>
        ///     Hashes Data 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        public static ReadOnlySpan<byte> Hash(ReadOnlySpan<byte> data, HashAlgorithm hashAlgorithm)
        {
            return _hash.Hash(data, hashAlgorithm);
        }
    }
}
