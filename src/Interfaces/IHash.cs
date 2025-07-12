using CryptoShark.Enums;
using System;
namespace CryptoShark.Interfaces
{
    /// <summary>
    ///     Hash Interface
    /// </summary>
    public interface IHash
    {
        /// <summary>
        ///     Hashes data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        string Hash(ReadOnlySpan<byte> data, StringEncoding encoding, HashAlgorithm hashAlgorithm);

        /// <summary>
        ///     Hashes Data 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        ReadOnlySpan<byte> Hash(ReadOnlySpan<byte> data, HashAlgorithm hashAlgorithm);

        /// <summary>
        ///     HMAC Hash
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        ReadOnlySpan<byte> Hmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, HashAlgorithm hashAlgorithm);

        /// <summary>
        ///     HMAC Hash
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        string Hmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, StringEncoding encoding, HashAlgorithm hashAlgorithm);
    }
}
