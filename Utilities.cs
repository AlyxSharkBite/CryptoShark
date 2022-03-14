using CryptoShark.Interfaces;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoShark
{
    internal class Utilities : IECCUtilities, IRSAUtilites, IHash
    {
        private static Lazy<Utilities> _utilities = new Lazy<Utilities>(() => new Utilities(), true);
        public static Utilities Instance => _utilities.Value;

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
        ReadOnlySpan<byte> IECCUtilities.CreateEccKey(ECCurve curve)
        {
            ECDiffieHellman diffieHellman = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    diffieHellman = new ECDiffieHellmanCng(curve);
                else
                    diffieHellman = ECDiffieHellman.Create(curve);

                return diffieHellman.ExportPkcs8PrivateKey();
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
            finally
            {
                if(diffieHellman != null)
                    diffieHellman.Dispose();    
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IECCUtilities.EncryptEccKey(ReadOnlySpan<byte> eccKey, string password)
        {
            ECDiffieHellman diffieHellman = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    diffieHellman = new ECDiffieHellmanCng();
                else
                    diffieHellman = ECDiffieHellman.Create();

                diffieHellman.ImportPkcs8PrivateKey(eccKey, out var _);
                return diffieHellman.ExportEncryptedPkcs8PrivateKey(password,
                    new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc, HashAlgorithmName.SHA384, 10000));
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
            finally
            {
                if (diffieHellman != null)
                    diffieHellman.Dispose();
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IECCUtilities.EncryptEccKey(ReadOnlySpan<byte> eccKey, string password, PbeEncryptionAlgorithm encryptionAlgorithm, HashAlgorithmName hashAlgorithm, int itterations)
        {
            ECDiffieHellman diffieHellman = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    diffieHellman = new ECDiffieHellmanCng();
                else
                    diffieHellman = ECDiffieHellman.Create();

                diffieHellman.ImportPkcs8PrivateKey(eccKey, out var _);
                return diffieHellman.ExportEncryptedPkcs8PrivateKey(password,
                    new PbeParameters(encryptionAlgorithm, hashAlgorithm, itterations));
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
            finally
            {
                if (diffieHellman != null)
                    diffieHellman.Dispose();
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IECCUtilities.GetEccPublicKey(ReadOnlySpan<byte> unencryptedEccKey)
        {
            ECDiffieHellman diffieHellman = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    diffieHellman = new ECDiffieHellmanCng();
                else
                    diffieHellman = ECDiffieHellman.Create();

                diffieHellman.ImportPkcs8PrivateKey(unencryptedEccKey, out var _);
                return diffieHellman.ExportSubjectPublicKeyInfo();
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
            finally
            {
                if (diffieHellman != null)
                    diffieHellman.Dispose();
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IECCUtilities.GetEccPublicKey(ReadOnlySpan<byte> encryptedEccKey, string password)
        {
            ECDiffieHellman diffieHellman = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    diffieHellman = new ECDiffieHellmanCng();
                else
                    diffieHellman = ECDiffieHellman.Create();

                diffieHellman.ImportEncryptedPkcs8PrivateKey(password, encryptedEccKey, out var _);
                return diffieHellman.ExportSubjectPublicKeyInfo();
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
            finally
            {
                if (diffieHellman != null)
                    diffieHellman.Dispose();
            }
        }
        #endregion

        #region IRSAUtilites
        ///<inheritdoc/>
        ReadOnlySpan<byte> IRSAUtilites.CreateRsaKey(int keyLength)
        {
            RSA rsa = null;

            try
            {
                if (!Enumerable.Range(1024, 16384).Contains(keyLength))
                    throw new ArgumentOutOfRangeException("Keysize must be between 1024 and 16384");
                if (keyLength % 8 != 0)
                    throw new ArgumentOutOfRangeException($"Keysize must be divisible by 8");

                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    rsa = new RSACng(keyLength);
                else
                    rsa = RSA.Create(keyLength);

                return rsa.ExportPkcs8PrivateKey();
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
            finally
            {
                if (rsa != null)
                    rsa.Dispose();
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IRSAUtilites.EncryptRsaKey(ReadOnlySpan<byte> rsaKey, string password)
        {
            RSA rsa = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    rsa = new RSACng();
                else
                    rsa = RSA.Create();

                rsa.ImportPkcs8PrivateKey(rsaKey, out var _);
                return rsa.ExportEncryptedPkcs8PrivateKey(password,
                    new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc, HashAlgorithmName.SHA384, 10000));
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
            finally
            {
                if (rsa != null)
                    rsa.Dispose();
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IRSAUtilites.EncryptRsaKey(ReadOnlySpan<byte> rsaKey,
            string password,
            PbeEncryptionAlgorithm encryptionAlgorithm,
            HashAlgorithmName hashAlgorithm,
            int itterations)
        {
            RSA rsa = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    rsa = new RSACng();
                else
                    rsa = RSA.Create();

                rsa.ImportPkcs8PrivateKey(rsaKey, out var _);
                return rsa.ExportEncryptedPkcs8PrivateKey(password,
                    new PbeParameters(encryptionAlgorithm, hashAlgorithm, itterations));
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
            finally
            {
                if (rsa != null)
                    rsa.Dispose();
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IRSAUtilites.GetRsaPublicKey(ReadOnlySpan<byte> unencryptedRsaKey)
        {
            RSA rsa = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    rsa = new RSACng();
                else
                    rsa = RSA.Create();

                rsa.ImportPkcs8PrivateKey(unencryptedRsaKey, out var _);
                return rsa.ExportRSAPublicKey();
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
            finally
            {
                if (rsa != null)
                    rsa.Dispose();
            }
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IRSAUtilites.GetRsaPublicKey(ReadOnlySpan<byte> encryptedRsaKey, string password)
        {
            RSA rsa = null;

            try
            {
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
                    rsa = new RSACng();
                else
                    rsa = RSA.Create();

                rsa.ImportEncryptedPkcs8PrivateKey(password, encryptedRsaKey, out var _);
                return rsa.ExportRSAPublicKey();
            }
            catch (Exception e)
            {
                LastException = e;
                return null;
            }
            finally
            {
                if (rsa != null)
                    rsa.Dispose();
            }
        }
        #endregion

        #region IHash
        ///<inheritdoc/>
        string IHash.Hash(ReadOnlySpan<byte> data, Enums.StringEncoding encoding, Enums.HashAlgorithm hashAlgorithm)
        {
            var engine = new Engine.HashEngine(hashAlgorithm);
            return engine.Hash(data, encoding);
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IHash.Hash(ReadOnlySpan<byte> data, Enums.HashAlgorithm hashAlgorithm)
        {
            var engine = new Engine.HashEngine(hashAlgorithm);
            return engine.Hash(data);
        }

        ///<inheritdoc/>
        ReadOnlySpan<byte> IHash.Hmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, Enums.HashAlgorithm hashAlgorithm)
        {
            var engine = new Engine.HashEngine(hashAlgorithm);
            return engine.Hmac(data, key);
        }

        ///<inheritdoc/>
        string IHash.Hmac(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, Enums.StringEncoding encoding, Enums.HashAlgorithm hashAlgorithm)
        {
            var engine = new Engine.HashEngine(hashAlgorithm);
            return engine.Hmac(data, key, encoding);
        }
        #endregion


    }
}
