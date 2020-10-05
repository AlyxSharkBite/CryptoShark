using System;
namespace CryptoShark.Interfaces
{
    public interface IRSAUtilites
    {
        /// <summary>
        ///     Creates an RSA Private Key in Pkcs8 format
        /// </summary>
        /// <param name="keyLength">1024 to 16384 in icriments of 8</param>        
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> CreateRsaKey(int keyLength);

        /// <summary>
        ///     Ecrypts a Pkcs8 RSA Private Key to
        ///     Pkcs8Encrypted Format
        ///     Aes 192 CBC
        ///     Sha 384 Hash
        ///     10000 Itterations
        /// </summary>
        /// <param name="rsaKey">RSA Private Key</param>
        /// <param name="password">Encryption Password</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> EncryptRsaKey(ReadOnlySpan<byte> rsaKey, string password);

        /// <summary>
        ///     Ecrypts a Pkcs8 RSA Private Key to
        ///     Pkcs8Encrypted Format
        /// </summary>
        /// <param name="rsaKey">Unencrypted Pkcs8 RSA Key</param>
        /// <param name="password">Encryption Password</param>
        /// <param name="encryptionAlgorithm">Encryption Algorithm</param>
        /// <param name="hashAlgorithm">Hash Algorithm</param>
        /// <param name="itterations">Itteration Count</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> EncryptRsaKey(ReadOnlySpan<byte> rsaKey, string password, System.Security.Cryptography.PbeEncryptionAlgorithm encryptionAlgorithm, System.Security.Cryptography.HashAlgorithmName hashAlgorithm, int itterations);

        /// <summary>
        ///     Gets the RSA Public Key in Pcks1 Format
        /// </summary>
        /// <param name="unencryptedRsaKey">Unencrypted Pkcs8 RSA Key</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> GetRsaPublicKey(ReadOnlySpan<byte> unencryptedRsaKey);

        /// <summary>
        ///      Gets the RSA Public Key in Pcks1 Format
        /// </summary>
        /// <param name="encryptedRsaKey">Encrypted Pkcs8 RSA Key</param>
        /// <param name="password">Password for the key</param>
        /// <returns>Null on failure check LastEception</returns>
        ReadOnlySpan<byte> GetRsaPublicKey(ReadOnlySpan<byte> encryptedRsaKey, string password);

        /// <summary>
        ///     Last Exception Thrown
        /// </summary>
        Exception LastException { get; }
    }
}
