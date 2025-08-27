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
        private readonly ICryptoSharkConfiguration _cryptoSharkConfiguration;

        public CryptoSharkEccCryptography(ILogger logger, ICryptoSharkConfiguration configuration)
        {
            _logger = logger;
            _encryptor = new EccEncryption(logger);
            _recordSerializer = new RecordSerializer(logger);
            _cryptoSharkConfiguration = configuration;
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
                record.EncryptionAlgorithm, record.HashAlgorithm, record.Nonce, record.Signature, password);

            if (decryptionResult.IsFailure)
                throw new CryptographicException("Decryption Failed, see inner exception(s)", decryptionResult.Error);

            return decryptionResult.Value;
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

            var encryptionResult = _encryptor.Encrypt(
                encryptionRequest.ClearData,
                encryptionRequest.PublicKey,
                encryptionRequest.PrivateKey,
                GetEncryptionAlgorithm(encryptionRequest.EncryptionAlgorithm),
                GetHashAlgorithm(encryptionRequest.HashAlgorithm),
                encryptionRequest.Password,
                GetCompress(encryptionRequest));

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

        private bool? GetCompress(IEncryptionRequest encryptionRequest)
        {
            if (_cryptoSharkConfiguration?.CompressBeforeEncryption is not null)
                return _cryptoSharkConfiguration.CompressBeforeEncryption;

            return encryptionRequest.CompressData;
        }

        private Enums.EncryptionAlgorithm GetEncryptionAlgorithm(Enums.EncryptionAlgorithm? algorithm)
        {
            if(_cryptoSharkConfiguration?.DefaultEncryptionAlgorithm is not null)
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
        /// Creates a new CryptoSharkEccCryptography
        /// </summary>
        /// <param name="cryptoSharkConfiguration"></param>
        /// <returns></returns>
        public static ICryptoSharkAsymmetricCryptography Create(ICryptoSharkConfiguration cryptoSharkConfiguration)
            => new CryptoSharkEccCryptography(null, cryptoSharkConfiguration);

        /// <summary>
        /// Creates a new CryptoSharkEccCryptography
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="cryptoSharkConfiguration"></param>
        /// <returns></returns>
        public static ICryptoSharkAsymmetricCryptography Create(ILogger logger, ICryptoSharkConfiguration cryptoSharkConfiguration)
            => new CryptoSharkEccCryptography(logger, cryptoSharkConfiguration);

        /// <summary>
        /// Creates a new CryptoSharkEccCryptography
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static ICryptoSharkAsymmetricCryptography Create(ILogger logger) 
            => new CryptoSharkEccCryptography(logger, null);


        /// <summary>
        /// Creates a new CryptoSharkEccCryptography
        /// </summary>        
        /// <returns></returns>
        public static ICryptoSharkAsymmetricCryptography Create()
            => new CryptoSharkEccCryptography(null, null);

        
    }
}
