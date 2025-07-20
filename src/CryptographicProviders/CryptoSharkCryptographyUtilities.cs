using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CryptoShark.Options;
using CryptoShark.Utilities;
using CSharpFunctionalExtensions;
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
    public sealed class CryptoSharkCryptographyUtilities : ICryptoSharkCryptographyUtilities
    {
        private readonly ILogger _logger;
        private readonly CryptoSharkUtilities _cryptoSharkUtilities;
        private readonly SecureStringUtilities _secureStringUtilities;
        private readonly ICryptoSharkConfiguration _cryptoSharkConfiguration;

        public CryptoSharkCryptographyUtilities(ILogger logger, ICryptoSharkConfiguration configuration)
        {
            _logger = logger;
            _cryptoSharkUtilities = new CryptoSharkUtilities(logger);
            _secureStringUtilities = new SecureStringUtilities();
            _cryptoSharkConfiguration = configuration;
        }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> CreateAsymetricKey(IAsymmetricKeyParameter parameters)
        {
            if (parameters is null) 
                throw new ArgumentNullException(nameof(parameters));    

            Result<ReadOnlyMemory<byte>, Exception> keyResult;

            if (parameters.GetType() == typeof(EccKeyParameters)) 
            { 
                var eccParams = (EccKeyParameters)parameters;

                var curve = eccParams.Curve;
                if(!String.IsNullOrEmpty(_cryptoSharkConfiguration?.DefaultEccCurveOid) )
                {
                    var oidKeyResult = _cryptoSharkUtilities.ParseCurveFomOid(_cryptoSharkConfiguration.DefaultEccCurveOid);
                    if(oidKeyResult.IsSuccess)
                        curve = oidKeyResult.Value;
                }

                keyResult = _cryptoSharkUtilities.CreateEccKey(eccParams.Curve, eccParams.Password);
            }
            else if (parameters.GetType() == typeof(RsaKeyParameters))
            {
                var rsaParams = (RsaKeyParameters)parameters;
                var keySize = _cryptoSharkConfiguration?.DefaultRsaKeySize ?? rsaParams.KeySize;
                keyResult = _cryptoSharkUtilities.CreateRsaKey(
                    keySize, 
                    rsaParams.Password,
                    _cryptoSharkConfiguration?.PreferDotNetRsaKeyGeneration ?? false);
            }
            else
            {
                _logger?.LogError("CryptoShark:CryptoSharkCryptographyUtilities:CreateAsymetricKey {message}", $"Unknown Type {parameters.GetType().Name}");
                keyResult = Result.Failure<ReadOnlyMemory<byte>, Exception>(new Exception($"Unknown Type {parameters.GetType().Name}"));
            }

            if(keyResult.IsFailure)
                throw new CryptographicException("CreateAsymetricKey Failed, see inner exception(s)", keyResult.Error);

            return keyResult.Value;
        }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> HashBytes(ReadOnlyMemory<byte> data, Enums.HashAlgorithm hashAlgorithm)
        {
            var hashResult = _cryptoSharkUtilities.Hash(data, hashAlgorithm);
            if (hashResult.IsFailure)
                throw new CryptographicException("Hash Failed, see inner exception(s)", hashResult.Error);

            return hashResult.Value;
        }

        /// <inheritdoc />
        public ReadOnlyMemory<byte> HashBytes(ReadOnlyMemory<byte> data)
        {
            var hashResult = _cryptoSharkUtilities.Hash(data, _cryptoSharkConfiguration?.DefaultHashAlgorithm ?? Enums.HashAlgorithm.SHA_256);
            if (hashResult.IsFailure)
                throw new CryptographicException("Hash Failed, see inner exception(s)", hashResult.Error);

            return hashResult.Value;
        }

        /// <inheritdoc />
        public string HashBytes(ReadOnlyMemory<byte> data, Enums.HashAlgorithm hashAlgorithm, StringEncoding encoding)
        {
            var hashResult = _cryptoSharkUtilities.Hash(data, encoding, hashAlgorithm);
            if (hashResult.IsFailure)
                throw new CryptographicException("Hash Failed, see inner exception(s)", hashResult.Error);

            return hashResult.Value;
        }

        /// <inheritdoc />
        public string HashBytes(ReadOnlyMemory<byte> data, StringEncoding encoding)
        {
            var hashResult = _cryptoSharkUtilities.Hash(data, encoding, _cryptoSharkConfiguration?.DefaultHashAlgorithm ?? Enums.HashAlgorithm.SHA_256);
            if (hashResult.IsFailure)
                throw new CryptographicException("Hash Failed, see inner exception(s)", hashResult.Error);

            return hashResult.Value;
        }


        /// <inheritdoc />
        public ReadOnlyMemory<byte> GetAsymetricPublicKey(ReadOnlyMemory<byte> privateKey, SecureString password, 
            CryptographyType cryptographyType)
        {
            switch (cryptographyType)
            {
                case CryptographyType.EllipticalCurveCryptography:
                    {
                        var result = _cryptoSharkUtilities.GetEccPublicKey(privateKey, password);
                        if (result.IsFailure)
                            throw new CryptographicException("Failed to get public key, see inner exception(s)", result.Error);
                        return result.Value;
                    } 
                case CryptographyType.RivestShamirAdlemanCryptography:
                    {
                        var result = _cryptoSharkUtilities.GetRsaPublicKey(privateKey, password);
                        if (result.IsFailure)
                            throw new CryptographicException("Failed to get public key, see inner exception(s)", result.Error);
                        return result.Value;
                    }
                default:
                    throw new ArgumentException($"Invalid CryptographyType {cryptographyType}");
            }
        }

        /// <inheritdoc />
        public SecureString StringToSecureString(string value)
        {
            return _secureStringUtilities.StringToSecureString(value);
        }

        /// <summary>
        /// Creates a CryptoSharkCryptographyUtilities 
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="cryptoSharkConfiguration"></param>
        /// <returns></returns>
        public static ICryptoSharkCryptographyUtilities Create(ILogger logger, ICryptoSharkConfiguration cryptoSharkConfiguration)
            => new CryptoSharkCryptographyUtilities(logger, cryptoSharkConfiguration);

        /// <summary>
        /// Creates a CryptoSharkCryptographyUtilities 
        /// </summary>
        /// <param name="cryptoSharkConfiguration"></param>
        /// <returns></returns>
        public static ICryptoSharkCryptographyUtilities Create(ICryptoSharkConfiguration cryptoSharkConfiguration)
            => new CryptoSharkCryptographyUtilities(null, cryptoSharkConfiguration);

        /// <summary>
        /// Creates a CryptoSharkCryptographyUtilities 
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static ICryptoSharkCryptographyUtilities Create(ILogger logger)
            => new CryptoSharkCryptographyUtilities(logger, null);

        /// <summary>
        /// Creates a CryptoSharkCryptographyUtilities 
        /// </summary>
        /// <returns></returns>
        public static ICryptoSharkCryptographyUtilities Create()
            => new CryptoSharkCryptographyUtilities(null, null);


    }
}
