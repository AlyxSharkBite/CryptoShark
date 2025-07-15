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
    /// Asymetric (Public/Private) RSA Encryption Class
    /// </summary>
    public sealed class CryptoSharkRsaCryptography : ICryptoSharkAsymmetricCryptography
    {
        private readonly ILogger _logger;
        private readonly RsaEncryption _encryptor;
        private readonly RecordSerializer _recordSerializer;

        public CryptoSharkRsaCryptography(ILogger logger)
        {
            _logger = logger;
            _encryptor = new RsaEncryption(logger);
            _recordSerializer = new RecordSerializer(logger);
        }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> ecnryptedData, ReadOnlySpan<byte> privateKey, SecureString password)
        {
            RsaCryptographyRecord record = null;

            try
            {
                record = _recordSerializer.DeserializeRecord<RsaCryptographyRecord>(ecnryptedData);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkRsaCryptography:Decrypt {message}", ex.Message);
                throw new CryptographicException("Decryption Failed, see inner exception(s)", ex);
            }            

            var decryptionResult = _encryptor.Decrypt(record.EncryptedData, record.PublicKey, privateKey, record.EncryptionAlgorithm,
                record.HashAlgorithm, record.Nonce, record.Signature, record.EncryptionKey, password, record.RsaPadding);

            if (decryptionResult.IsFailure)
                throw new CryptographicException("Decryption Failed, see inner exception(s)", decryptionResult.Error);

            return decryptionResult.Value.AsMemory();
        }

        /// <summary>
        ///     Encrypts Data useing the ECC Keys Specified
        ///     With specified encryption algorithm
        /// </summary>
        /// <param name="encryptionRequest"></param>
        /// <returns></returns>
        /// <exception cref="CryptographicException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public ReadOnlyMemory<byte> Encrypt(IAsymetricEncryptionRequest encryptionRequest)
        {
            if (encryptionRequest is null)
                throw new ArgumentNullException(nameof(encryptionRequest));

            var encryptionResult = _encryptor.Encrypt(encryptionRequest.ClearData, encryptionRequest.PublicKey,
                encryptionRequest.PrivateKey, encryptionRequest.EncryptionAlgorithm, encryptionRequest.HashAlgorithm,
                encryptionRequest.Password, encryptionRequest.RsaPadding);

            if (encryptionResult.IsFailure)
                throw new CryptographicException("Decryption Failed, see inner exception(s)", encryptionResult.Error);

            try
            {
                return _recordSerializer.SerializeRecord<RsaCryptographyRecord>(encryptionResult.Value);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "CryptoShark:CryptoSharkRsaCryptography:Encrypt {message}", ex.Message);
                throw new CryptographicException("Ecryption Failed, see inner exception(s)", ex);
            }
        }

        /// <summary>
        /// Creates a new CryptoSharkRsaCryptography
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static ICryptoSharkAsymmetricCryptography Create(ILogger logger)
            => new CryptoSharkRsaCryptography(logger);

        /// <summary>
        /// Creates a new CryptoSharkRsaCryptography
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static ICryptoSharkAsymmetricCryptography Create()
            => new CryptoSharkRsaCryptography(null);
    }
}
