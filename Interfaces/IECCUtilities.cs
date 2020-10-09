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
        /// </summary>
        /// <param name="curve">Curve to use</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> CreateEccKey(System.Security.Cryptography.ECCurve curve);

        /// <summary>
        ///     Ecrypts a Pkcs8 ECC Private Key to
        ///     Pkcs8Encrypted Format
        ///     Aes 192 CBC
        ///     Sha 384 Hash
        ///     10000 Itterations
        /// </summary>
        /// <param name="eccKey">Pkcs8 ECC Private Key</param>
        /// <param name="password">Password for the key</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> EncryptEccKey(ReadOnlySpan<byte> eccKey, string password);

        /// <summary>
        ///     Ecrypts a Pkcs8 ECC Private Key to
        ///     Pkcs8Encrypted Format
        /// </summary>
        /// <param name="eccKey">Pkcs8 ECC Private Key</param>
        /// <param name="password">Password for the key</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>
        /// <param name="hashAlgorithm">Hash Algorithm</param>
        /// <param name="itterations">Itteration Count</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> EncryptEccKey(ReadOnlySpan<byte> eccKey, string password, System.Security.Cryptography.PbeEncryptionAlgorithm encryptionAlgorithm, System.Security.Cryptography.HashAlgorithmName hashAlgorithm, int itterations);

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
