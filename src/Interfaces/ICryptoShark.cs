using CryptoShark.Enums;
using CryptoShark.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Interfaces
{
    /// <summary>
    /// Utilities for Hashing & Creating Asymetric Keys
    /// </summary>
    public interface ICryptoSharkCryptographyUtilities
    {
        /// <summary>
        /// Hashes Binary Data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        ReadOnlySpan<byte> HashBytes(ReadOnlyMemory<byte> data, Enums.HashAlgorithm hashAlgorithm);

        /// <summary>
        /// Hashes Binary Data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="hashAlgorithm"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        string HashBytes(ReadOnlySpan<byte> data, Enums.HashAlgorithm hashAlgorithm, Enums.StringEncoding encoding);

        /// <summary>
        /// Creates an Asymetric Private Key
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="CryptographicException"></exception>
        ReadOnlySpan<byte> CreateAsymetricKey(IAsymmetricKeyParameter parameters);

        /// <summary>
        /// Gets The Public Key For Given Private Key
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="password"></param>
        /// <param name="cryptographyType"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        /// <exception cref="ArgumentException"></exception>
        ReadOnlySpan<byte> GetAsymetricPublicKey(ReadOnlySpan<byte> privateKey, SecureString password, CryptographyType cryptographyType);

        /// <summary>
        /// Returns SecureString Containing The String Value
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        SecureString StringToSecureString(string value);
    }

    /// <summary>
    /// Symetric (Password) Encryption Class
    /// </summary>
    public interface ICryptoSharkSymmetricCryptography
    {
        /// <summary>
        /// Encrypts the specified data with specified algorithm        
        /// </summary>
        /// <param name="encryptionRequest"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        ReadOnlyMemory<byte> Encrypt(IEncryptionRequest encryptionRequest);

        /// <summary>
        /// Decrypts the previously encypted data        
        /// </summary>
        /// <param name="ecnryptedData"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> ecnryptedData, SecureString password);
    }

    /// <summary>
    /// Asymetric (Public/Private) Encryption Class
    /// </summary>
    public interface ICryptoSharkAsymmetricCryptography
    {
        /// <summary>
        /// Encrypts Data useing the Asymetric Keys Specified
        /// With specified encryption algorithm
        /// </summary>
        // <param name="encryptionRequest"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        ReadOnlyMemory<byte> Encrypt(IAsymetricEncryptionRequest encryptionRequest);

        /// <summary>
        /// Decrypts Previously Encrypted Data
        /// </summary>
        /// <param name="ecnryptedData"></param>
        /// <param name="privateKey"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> ecnryptedData, ReadOnlySpan<byte> privateKey, SecureString password);
    }
}
