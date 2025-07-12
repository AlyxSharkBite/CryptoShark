using CryptoShark.Interfaces;
using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

[assembly: InternalsVisibleTo("CryptoSharkTests")]
namespace CryptoShark
{    
    internal sealed class Utilities : IECCUtilities, IRSAUtilites, IHash
    {
        private static Lazy<Utilities> _utilities = new Lazy<Utilities>(() => new Utilities(), true);
        public static Utilities Instance => _utilities.Value;        

        private static readonly object _lock = new object();

        ///<inheritdoc/>
        public Exception LastException { get; private set; } = null;

        /// <summary>
        ///     Hide Constructor
        /// </summary>
        private Utilities()
        {
        }

        #region IECCUtilites

        ///<inheritdoc/>
        public ReadOnlySpan<byte> CreateEccKey(ECCurve curve)
        { 
            try
            {
                curve.Validate();

                lock (_lock)
                {
                    using var diffieHellman = ECDiffieHellmanCng.Create(curve);
                    return diffieHellman.ExportPkcs8PrivateKey();
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }            
        }

        ///<inheritdoc/>
        public ReadOnlySpan<byte> EncryptEccKey(ReadOnlySpan<byte> eccKey, string password)
        {      
            try
            {
                lock (_lock)
                {
                    using var diffieHellman = ECDiffieHellmanCng.Create();

                    diffieHellman.ImportPkcs8PrivateKey(eccKey, out var _);
                    return diffieHellman.ExportEncryptedPkcs8PrivateKey(password,
                        new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA384, 10000));
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }           
        }        

        ///<inheritdoc/>
        public ReadOnlySpan<byte> GetEccPublicKey(ReadOnlySpan<byte> unencryptedEccKey)
        {           
            try
            {
                lock (_lock)
                {
                    using var diffieHellman = ECDiffieHellmanCng.Create();

                    diffieHellman.ImportPkcs8PrivateKey(unencryptedEccKey, out var _);
                    return diffieHellman.ExportSubjectPublicKeyInfo();
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }            
        }

        ///<inheritdoc/>
        public ReadOnlySpan<byte> GetEccPublicKey(ReadOnlySpan<byte> encryptedEccKey, string password)
        {
            try
            {
                lock (_lock)
                {
                    using var diffieHellman = ECDiffieHellmanCng.Create();

                    diffieHellman.ImportEncryptedPkcs8PrivateKey(password, encryptedEccKey, out var _);
                    return diffieHellman.ExportSubjectPublicKeyInfo();
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }            
        }
        #endregion

        #region IRSAUtilites
        ///<inheritdoc/>
        public ReadOnlySpan<byte> CreateRsaKey(int keyLength)
        {
            try
            {
                if (!Enumerable.Range(1024, 16384).Contains(keyLength))
                    throw new ArgumentOutOfRangeException("Keysize must be between 1024 and 16384");
                if (keyLength % 8 != 0)
                    throw new ArgumentOutOfRangeException($"Keysize must be divisible by 8");

                lock (_lock)
                {
                    using var rsa = RSACng.Create(keyLength);
                    return rsa.ExportPkcs8PrivateKey();
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }           
        }

        ///<inheritdoc/>
        public ReadOnlySpan<byte> EncryptRsaKey(ReadOnlySpan<byte> rsaKey, string password)
        {
            try
            {
                lock (_lock)
                {
                    using var rsa = RSACng.Create();

                    rsa.ImportPkcs8PrivateKey(rsaKey, out var _);
                    
                    return rsa.ExportEncryptedPkcs8PrivateKey(password,
                        new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA384, 10000));
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }           
        }
       
        ///<inheritdoc/>
        public ReadOnlySpan<byte> GetRsaPublicKey(ReadOnlySpan<byte> unencryptedRsaKey)
        {
            try
            {
                lock (_lock)
                {
                    using var rsa = RSACng.Create();

                    rsa.ImportPkcs8PrivateKey(unencryptedRsaKey, out var _);
                    return rsa.ExportRSAPublicKey();
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }            
        }

        ///<inheritdoc/>
        public ReadOnlySpan<byte> GetRsaPublicKey(ReadOnlySpan<byte> encryptedRsaKey, string password)
        {           
            try
            {
                lock (_lock)
                {
                    using var rsa = RSACng.Create();

                    rsa.ImportEncryptedPkcs8PrivateKey(password, encryptedRsaKey, out var _);
                    return rsa.ExportRSAPublicKey();
                }
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }           
        }
        #endregion

        #region IHash
        ///<inheritdoc/>
        public string Hash(ReadOnlySpan<byte> data, Enums.StringEncoding encoding, Enums.HashAlgorithm hashAlgorithm)
        {
            var engine = new Engine.HashEngine(hashAlgorithm);
            return engine.Hash(data, encoding);
        }

        ///<inheritdoc/>
        public ReadOnlySpan<byte> Hash(ReadOnlySpan<byte> data, Enums.HashAlgorithm hashAlgorithm)
        {
            var engine = new Engine.HashEngine(hashAlgorithm);
            return engine.Hash(data);
        }

        ///<inheritdoc/>
        public ReadOnlySpan<byte> Hmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, Enums.HashAlgorithm hashAlgorithm)
        {
            var engine = new Engine.HashEngine(hashAlgorithm);
            return engine.Hmac(data, key);
        }

        ///<inheritdoc/>
        public string Hmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, Enums.StringEncoding encoding, Enums.HashAlgorithm hashAlgorithm)
        {
            var engine = new Engine.HashEngine(hashAlgorithm);
            return engine.Hmac(data, key, encoding);
        }
        #endregion


    }
}
