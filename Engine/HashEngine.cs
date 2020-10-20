using System;


namespace CryptoShark.Engine
{
    class HashEngine
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
        public string Hash(ReadOnlySpan<byte> data, StringEncoding encoding)
        {
            var hashed = Hash(data);
            
            switch (encoding)
            {
                case StringEncoding.Hex:
                    return Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(hashed.ToArray());
                case StringEncoding.Base64:
                    return Org.BouncyCastle.Utilities.Encoders.Base64.ToBase64String(hashed.ToArray());
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
        public ReadOnlySpan<byte> Hash(ReadOnlySpan<byte> data)
        {
            Org.BouncyCastle.Crypto.IDigest digest = GetDigest();

            var hash = new byte[digest.GetDigestSize()];

            digest.BlockUpdate(data.ToArray(), 0, data.Length);
            digest.DoFinal(hash, 0);

            return hash;

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
