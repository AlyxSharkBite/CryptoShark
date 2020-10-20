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
    }
}
