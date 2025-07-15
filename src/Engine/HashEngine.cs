using CryptoShark.Enums;
using Org.BouncyCastle.Security;
using System;


namespace CryptoShark.Engine
{
    internal sealed class HashEngine
    {
        private readonly HashAlgorithm _hashAlgorithm;

        public HashEngine(HashAlgorithm hashAlgorithm)
        {
            _hashAlgorithm = hashAlgorithm == HashAlgorithm.NONE ?
                HashAlgorithm.SHA_256 : 
                hashAlgorithm;
        }        

        /// <summary>
        ///     Computes Hash of the data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public string Hash(byte[] data, StringEncoding encoding)
        {
            var hashed = Hash(data);
            
            switch (encoding)
            {
                case StringEncoding.Hex:
                    return Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(hashed);
                case StringEncoding.Base64:
                    return Org.BouncyCastle.Utilities.Encoders.Base64.ToBase64String(hashed);
                case StringEncoding.UrlBase64:
                    return Base64UrlEncode(hashed);

                default:
                    throw new ArgumentException("Invalid String Encoding");
            }
        }

        /// <summary>
        ///     Computes Hash of the data
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] Hash(byte[] data)
        {
            Org.BouncyCastle.Crypto.IDigest digest = GetDigest();

            var hash = new byte[digest.GetDigestSize()];

            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(hash, 0);

            return hash;

        }

        /// <summary>
        ///     Computes HMAC of the data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public byte[] Hmac(byte[] data, ReadOnlySpan<byte> key)
        {
            Org.BouncyCastle.Crypto.IDigest digest = GetDigest();

            var hmac = new Org.BouncyCastle.Crypto.Macs.HMac(digest);
            byte[] result = new byte[hmac.GetMacSize()];

            hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key.ToArray()));

            hmac.BlockUpdate(data, 0, data.Length);
            hmac.DoFinal(result, 0);

            return result;

        }

        /// <summary>
        ///     Computes HMAC of the data
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public string Hmac(byte[] data, ReadOnlySpan<byte> key, StringEncoding encoding)
        {
            var hashed = Hmac(data, key);

            switch (encoding)
            {
                case StringEncoding.Hex:
                    return Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(hashed);
                case StringEncoding.Base64:
                    return Org.BouncyCastle.Utilities.Encoders.Base64.ToBase64String(hashed);
                case StringEncoding.UrlBase64:
                    return Base64UrlEncode(hashed);

                default:
                    throw new ArgumentException("Invalid String Encoding");
            }

        }

        private Org.BouncyCastle.Crypto.IDigest GetDigest()
        {
            return DigestUtilities.GetDigest(_hashAlgorithm.ToString());
        }       

        private string Base64UrlEncode(ReadOnlySpan<byte> data)
        {
            var encoded = Org.BouncyCastle.Utilities.Encoders.UrlBase64.Encode(data.ToArray());
            return System.Text.Encoding.ASCII.GetString(encoded);
        }
    }
}
