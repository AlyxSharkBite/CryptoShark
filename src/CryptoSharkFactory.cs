using CryptoShark.CryptographicProviders;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark
{
    /// <summary>
    /// CryptoSharkFactory For Creating CryptoSharkFactory Instances
    /// With Or Without Logging
    /// </summary>
    public class CryptoSharkFactory
    {
        private readonly ILogger _logger;
        private readonly ICryptoSharkConfiguration _cryptoSharkConfiguration;

        private CryptoSharkFactory(ILogger logger, ICryptoSharkConfiguration cryptoSharkConfiguration)
        {
            _logger = logger;
            _cryptoSharkConfiguration = cryptoSharkConfiguration;
        }        

        /// <summary>
        /// Creates a ICryptoSharkCryptographyUtilities Instance Without Logging
        /// </summary>
        /// <returns></returns>
        public ICryptoSharkCryptographyUtilities CreateCryptographyUtilities()
            => CryptoSharkCryptographyUtilities.Create(_logger, _cryptoSharkConfiguration);

        /// <summary>
        /// Creates a ICryptoSharkSymmetricCryptography Instance
        /// For The Specified CryptographyType With Logging
        /// </summary>                
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public ICryptoSharkSymmetricCryptography CreateSymmetricCryptography()
            => CryptoSharkPasswordCryptography.Create(_logger, _cryptoSharkConfiguration);
               

        /// <summary>
        /// Creates a ICryptoSharkAsymmetricCryptography Instance
        /// For The Specified CryptographyType With Logging
        /// </summary>        
        /// <param name="cryptographyType"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public ICryptoSharkAsymmetricCryptography CreateAsymmetricCryptography(
            CryptographyType cryptographyType)
        {
            switch (cryptographyType)
            {
                case CryptographyType.EllipticalCurveCryptography:
                    return CryptoSharkEccCryptography.Create(_logger, _cryptoSharkConfiguration);
                case CryptographyType.RivestShamirAdlemanCryptography:
                    return CryptoSharkRsaCryptography.Create(_logger, _cryptoSharkConfiguration);                
                default:
                    throw new ArgumentException($"Unsupprted CryptographyType {cryptographyType}"); ;
            }
        }

        /// <summary>
        /// Creates an instance of CryptoSharkFactory
        /// </summary>
        /// <returns></returns>
        public static CryptoSharkFactory CreateCryptoSharkFactory()
            => new CryptoSharkFactory(null, null);

        /// <summary>
        /// Creates an instance of CryptoSharkFactory 
        /// </summary>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static CryptoSharkFactory CreateCryptoSharkFactory(ILogger logger)
            => new CryptoSharkFactory(logger, null);

        /// <summary>
        /// Creates an instance of CryptoSharkFactory 
        /// </summary>
        /// <param name="cryptoSharkConfiguration"></param>
        /// <returns></returns>
        public static CryptoSharkFactory CreateCryptoSharkFactory(ICryptoSharkConfiguration cryptoSharkConfiguration)
            => new CryptoSharkFactory(null, cryptoSharkConfiguration);

        /// <summary>
        /// Creates an instance of CryptoSharkFactory 
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="cryptoSharkConfiguration"></param>
        /// <returns></returns>
        public static CryptoSharkFactory CreateCryptoSharkFactory(ILogger logger, ICryptoSharkConfiguration cryptoSharkConfiguration)
            => new CryptoSharkFactory(logger, cryptoSharkConfiguration);
    }
}