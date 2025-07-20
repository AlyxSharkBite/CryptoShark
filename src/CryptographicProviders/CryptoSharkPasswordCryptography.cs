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
    /// <inheritdoc />
    public sealed class CryptoSharkPasswordCryptography : ICryptoSharkSymmetricCryptography
    {
        private readonly ILogger _logger;
        private readonly PBEncryption _encryptor;
        private readonly RecordSerializer _recordSerializer;
        private readonly ICryptoSharkConfiguration _cryptoSharkConfiguration;

        public CryptoSharkPasswordCryptography(ILogger logger, ICryptoSharkConfiguration cryptoSharkConfiguration)
        {
            _logger = logger;
            _cryptoSharkConfiguration = cryptoSharkConfiguration;
            _encryptor = new PBEncryption(logger);
            _recordSerializer = new RecordSerializer(logger);            
        }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> ecnryptedData, SecureString password)
        {
            PbeCryptographyRecord record = null;

            try
            {
                record = _recordSerializer.DeserializeRecord<PbeCryptographyRecord>(ecnryptedData);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkPasswordCryptography:Decrypt {message}", ex.Message);
                throw new CryptographicException("Decryption Failed, see inner exception(s)", ex);
            }

            var decryptionResult = _encryptor.Decrypt(record.EncryptedData, password, record.EncryptionAlgorithm,
                record.HashAlgorithm, record.Nonce, record.Salt, record.Hash, record.Iterations);

            if (decryptionResult.IsFailure)
                throw new CryptographicException("Decryption Failed, see inner exception(s)", decryptionResult.Error);
         
            return decryptionResult.Value;
        }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> Encrypt(IEncryptionRequest encryptionRequest)
        {
            if (encryptionRequest is null)
                throw new ArgumentNullException(nameof(encryptionRequest));

            var encryptionResult = _encryptor.Encrypt(
                encryptionRequest.ClearData,
                GetEncryptionAlgorithm(encryptionRequest.EncryptionAlgorithm),
                GetHashAlgorithm(encryptionRequest.HashAlgorithm),
                encryptionRequest.Password,
                GetCompress(encryptionRequest));

            if (encryptionResult.IsFailure)
                throw new CryptographicException("Decryption Failed, see inner exception(s)", encryptionResult.Error);

            try
            {
                return _recordSerializer.SerializeRecord<PbeCryptographyRecord>(encryptionResult.Value);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkPasswordCryptography:Encrypt {message}", ex.Message);
                throw new CryptographicException("Ecryption Failed, see inner exception(s)", ex);
            }
        }

        private bool? GetCompress(IEncryptionRequest encryptionRequest)
        {
            if (_cryptoSharkConfiguration?.CompressBeforeEncryption is not null)
                return _cryptoSharkConfiguration.CompressBeforeEncryption;

            return encryptionRequest.CompressData;
        }

        private Enums.EncryptionAlgorithm GetEncryptionAlgorithm(Enums.EncryptionAlgorithm? algorithm)
        {
            if (_cryptoSharkConfiguration?.DefaultEncryptionAlgorithm is not null)
                return _cryptoSharkConfiguration.DefaultEncryptionAlgorithm.Value;
            else if (algorithm.HasValue)
                return algorithm.Value;
            else
                return Enums.EncryptionAlgorithm.TwoFish;
        }

        private Enums.HashAlgorithm GetHashAlgorithm(Enums.HashAlgorithm? algorithm)
        {
            if (_cryptoSharkConfiguration?.DefaultHashAlgorithm is not null)
                return _cryptoSharkConfiguration.DefaultHashAlgorithm.Value;
            else if (algorithm.HasValue)
                return algorithm.Value;
            else
                return Enums.HashAlgorithm.SHA_256;
        }

        /// <summary>
        /// Creates a new CryptoSharkPasswordCryptography
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="cryptoSharkConfiguration"></param>
        /// <returns></returns>
        public static ICryptoSharkSymmetricCryptography Create(ILogger logger, ICryptoSharkConfiguration cryptoSharkConfiguration)
            => new CryptoSharkPasswordCryptography(logger, cryptoSharkConfiguration);

        /// <summary>
        /// Creates a new CryptoSharkPasswordCryptography
        /// </summary>
        /// <param name="cryptoSharkConfiguration"></param>
        /// <returns></returns>
        public static ICryptoSharkSymmetricCryptography Create(ICryptoSharkConfiguration cryptoSharkConfiguration)
            => new CryptoSharkPasswordCryptography(null, cryptoSharkConfiguration);

        /// <summary>
        /// Creates a new CryptoSharkPasswordCryptography
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static ICryptoSharkSymmetricCryptography Create(ILogger logger)
            => new CryptoSharkPasswordCryptography(logger, null);

        /// <summary>
        /// Creates a new CryptoSharkPasswordCryptography
        /// </summary>        
        /// <returns></returns>
        public static ICryptoSharkSymmetricCryptography Create()
            => new CryptoSharkPasswordCryptography(null, null);
    }
}
