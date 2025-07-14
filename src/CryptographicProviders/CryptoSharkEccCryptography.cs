using CryptoShark.Interfaces;
using CryptoShark.Record;
using CryptoShark.Utilities;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.CryptographicProviders
{
    /// <summary>
    /// Asymetric (Public/Private) ECC Encryption Class
    /// </summary>
    public sealed class CryptoSharkEccCryptography : ICryptoSharkAsymmetricCryptography
    {
        private readonly ILogger _logger;
        private readonly EccEncryption _encryptor;
        private readonly RecordSerializer _recordSerializer;

        public CryptoSharkEccCryptography(ILogger logger)
        {
            _logger = logger;
            _encryptor = new EccEncryption(logger);
            _recordSerializer = new RecordSerializer(logger);
        }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> ecnryptedData, ReadOnlySpan<byte> privateKey, SecureString password)
        {
            EccCryptographyRecord record = null;

            try
            {
                record = _recordSerializer.DeserializeRecord<EccCryptographyRecord>(ecnryptedData);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkEccCryptography:Decrypt {message}", ex.Message);
                throw new CryptographicException("Decryption Failed, see inner exception(s)", ex);
            }
            
            var decryptionResult = _encryptor.Decrypt(record.EncryptedData, record.PublicKey, privateKey, 
                record.Algorithm, record.Nonce, record.Signature, password);

            if (decryptionResult.IsFailure)
                throw new CryptographicException("Decryption Failed, see inner exception(s)", decryptionResult.Error);

            return decryptionResult.Value.AsMemory();
        }

        /// <summary>
        ///     Encrypts Data useing the ECC Keys Specified
        ///     With specified encryption algorithm
        /// </summary>
        // <param name="encryptionRequest"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public ReadOnlyMemory<byte> Encrypt(IAsymetricEncryptionRequest encryptionRequest)
        {
            if (encryptionRequest is null)
                throw new ArgumentNullException(nameof(encryptionRequest));

            var encryptionResult = _encryptor.Encrypt(encryptionRequest.ClearData, encryptionRequest.PublicKey,
                encryptionRequest.PrivateKey, encryptionRequest.Algorithm, encryptionRequest.Password);

            if (encryptionResult.IsFailure)
                throw new CryptographicException("Decryption Failed, see inner exception(s)", encryptionResult.Error);

            try
            {
                return _recordSerializer.SerializeRecord<EccCryptographyRecord>(encryptionResult.Value);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkEccCryptography:Encrypt {message}", ex.Message);
                throw new CryptographicException("Ecryption Failed, see inner exception(s)", ex);
            }
        }

        /// <summary>
        /// Creates a new CryptoSharkEccCryptography
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static ICryptoSharkAsymmetricCryptography Create(ILogger logger) 
            => new CryptoSharkEccCryptography(logger);


        /// <summary>
        /// Creates a new CryptoSharkEccCryptography
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static ICryptoSharkAsymmetricCryptography Create()
            => new CryptoSharkEccCryptography(null);

        
    }
}
