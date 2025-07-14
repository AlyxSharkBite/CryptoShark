using CryptoShark.Enums;
using System;


namespace CryptoShark.Engine
{
    internal sealed class HashEngine
    {
        private readonly HashAlgorithm _hashAlgorithm;

        public HashEngine(HashAlgorithm hashAlgorithm)
        {
            _hashAlgorithm = hashAlgorithm;
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
            dynamic digest;

            switch (_hashAlgorithm)
            {
                case HashAlgorithm.MD5:
                    digest = new Org.BouncyCastle.Crypto.Digests.MD5Digest();
                    break;

                case HashAlgorithm.SHA1:
                    digest = new Org.BouncyCastle.Crypto.Digests.Sha1Digest();
                    break;

                case HashAlgorithm.SHA2_256:
                    digest = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
                    break;

                case HashAlgorithm.SHA2_384:
                    digest = new Org.BouncyCastle.Crypto.Digests.Sha384Digest();
                    break;

                case HashAlgorithm.SHA2_512:
                    digest = new Org.BouncyCastle.Crypto.Digests.Sha512Digest();
                    break;

                case HashAlgorithm.SHA3_256:
                    digest = new Org.BouncyCastle.Crypto.Digests.Sha3Digest(256);
                    break;

                case HashAlgorithm.SHA3_384:
                    digest = new Org.BouncyCastle.Crypto.Digests.Sha3Digest(384);
                    break;

                case HashAlgorithm.SHA3_512:
                    digest = new Org.BouncyCastle.Crypto.Digests.Sha3Digest(512);
                    break;

                case HashAlgorithm.RipeMD_128:
                    digest = new Org.BouncyCastle.Crypto.Digests.RipeMD128Digest();
                    break;

                case HashAlgorithm.RipeMD_160:
                    digest = new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest();
                    break;

                case HashAlgorithm.RipeMD_256:
                    digest = new Org.BouncyCastle.Crypto.Digests.RipeMD256Digest();
                    break;

                case HashAlgorithm.RipeMD_320:
                    digest = new Org.BouncyCastle.Crypto.Digests.RipeMD320Digest();
                    break;

                case HashAlgorithm.Whirlpool:
                    digest = new Org.BouncyCastle.Crypto.Digests.WhirlpoolDigest();
                    break;

                default:
                    throw new ArgumentException("Invalid Hash Algorithm");
            }

            return digest;
        }       

        private string Base64UrlEncode(ReadOnlySpan<byte> data)
        {
            var encoded = Org.BouncyCastle.Utilities.Encoders.UrlBase64.Encode(data.ToArray());
            return System.Text.Encoding.ASCII.GetString(encoded);
        }
    }
}
