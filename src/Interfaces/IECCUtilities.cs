using System;
namespace CryptoShark.Interfaces
{
    /// <summary>
    ///     Eliptical Curve Utilites 
    /// </summary>
    public interface IECCUtilities
    {
        /// <summary>
        ///     Creates and ECC Private Key in Pkcs8 Format
        ///     ** On Non Windows Platforms Only The NIST Curves are Supported
        /// </summary>
        /// <param name="curve">Curve to use</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> CreateEccKey(System.Security.Cryptography.ECCurve curve);

        /// <summary>
        ///     Ecrypts a Pkcs8 ECC Private Key to
        ///     Pkcs8Encrypted Format
        ///     Aes 192 CBC
        ///     Sha 384 Hash
        ///     10000 Iterations
        /// </summary>
        /// <param name="eccKey">Pkcs8 ECC Private Key</param>
        /// <param name="password">Password for the key</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> EncryptEccKey(ReadOnlySpan<byte> eccKey, string password);
       
        /// <summary>
        ///     Gets the ECC Public Key
        /// </summary>
        /// <param name="unencryptedEccKey">Pkcs8 ECC Private Key</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> GetEccPublicKey(ReadOnlySpan<byte> unencryptedEccKey);

        /// <summary>
        ///     Gets the ECC Public Key
        /// </summary>
        /// <param name="encryptedEccKey">Encrypted Pkcs8 ECC Key</param>
        /// <param name="password">Password for the key</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> GetEccPublicKey(ReadOnlySpan<byte> encryptedEccKey, string password);

        /// <summary>
        ///     Last Exception Thrown
        /// </summary>
        Exception LastException { get; }
    }
}
