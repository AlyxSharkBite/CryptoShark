using CryptoShark.Enums;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryptoShark.Utilities
{
    /// <summary>
    /// Low level Asymmetric Cipher Utilities
    /// </summary>
    internal class AsymmetricCipherUtilities
    {
        private readonly SecureRandom _random = new SecureRandom();
        private readonly SecureStringUtilities _secureStringUtilities = new SecureStringUtilities();

        public ECDomainParameters EcGetBuiltInDomainParameters(System.Security.Cryptography.ECCurve curve)
        {
            X9ECParameters ecParams = ECNamedCurveTable.GetByOid(
                    new DerObjectIdentifier(curve.Oid.Value)
                );

            return new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N,
                ecParams.H, ecParams.GetSeed());
        }

        public AsymmetricCipherKeyPair GenerateECDHKeyPair(ECDomainParameters ecParams)
        {
            ECKeyGenerationParameters ecKeyGenParams = new ECKeyGenerationParameters(ecParams, _random);
            ECKeyPairGenerator ecKeyPairGen = new ECKeyPairGenerator();
            ecKeyPairGen.Init(ecKeyGenParams);
            AsymmetricCipherKeyPair ecKeyPair = ecKeyPairGen.GenerateKeyPair();
            return ecKeyPair;
        }

        public AsymmetricCipherKeyPair GenerateRsaKeyPair(int keySize)
        {
            var keyPairGenerator = new RsaKeyPairGenerator();
            var keyGenParams = new KeyGenerationParameters(_random, keySize);
            keyPairGenerator.Init(keyGenParams);
            AsymmetricCipherKeyPair rsaKeyPair = keyPairGenerator.GenerateKeyPair();

            return rsaKeyPair;
        }

        public ReadOnlyMemory<byte> WriteKeyPair(AsymmetricCipherKeyPair keyPair, SecureString password)
        {
            using MemoryStream pemStream = new MemoryStream();
            using StreamWriter streamWriter = new StreamWriter(pemStream);
            using PemWriter pemWriter = new PemWriter(streamWriter);
            pemWriter.WriteObject(keyPair, "BF-OFB", _secureStringUtilities.SecureStringToCharArray(password), _random);
            pemWriter.Writer.Flush();

            return pemStream.ToArray();
        }

        public ReadOnlyMemory<byte> WritePublicKey(AsymmetricKeyParameter publicKey)
        {
            using MemoryStream pemStream = new MemoryStream();
            using StreamWriter streamWriter = new StreamWriter(pemStream);
            using PemWriter pemWriter = new PemWriter(streamWriter);
            pemWriter.WriteObject(publicKey);
            pemWriter.Writer.Flush();

            return pemStream.ToArray();
        }

        public AsymmetricCipherKeyPair ReadKeyPair(ReadOnlyMemory<byte> privateKeyData, SecureString password)
        {
            using MemoryStream pemStream = new MemoryStream(privateKeyData.ToArray());
            using StreamReader reader = new StreamReader(pemStream);
            using PemReader pemReader = new PemReader(reader, new PasswordFinder(password));
            var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

            return keyPair;
        }

        public AsymmetricKeyParameter ReadPublicKey(ReadOnlyMemory<byte> publicKeyData)
        {
            using MemoryStream pemStream = new MemoryStream(publicKeyData.ToArray());
            using StreamReader reader = new StreamReader(pemStream);
            using PemReader pemReader = new PemReader(reader);
            var publicKey = (AsymmetricKeyParameter)pemReader.ReadObject();

            return publicKey;
        }

        public IAsymmetricBlockCipher ParsePadding(string paddingStr)
        {
            try
            {
                var padding = paddingStr.Trim();
                var idx = padding.LastIndexOf('/');
                if (idx > -1)
                    padding = padding.Substring(idx + 1);

                if (padding.Contains("Pkcs1", StringComparison.InvariantCultureIgnoreCase))
                    return new Pkcs1Encoding(new RsaEngine());

                if (!padding.StartsWith("OAEPWith", StringComparison.InvariantCultureIgnoreCase))
                    throw new ArgumentException($"Error Parsing Padding: Unkown Padding {paddingStr}");

                padding = padding.ToUpper().Replace("OAEPWITH", String.Empty);

                bool mfg1 = false;
                if (padding.EndsWith("ANDMGF1PADDING", StringComparison.InvariantCultureIgnoreCase))
                {
                    mfg1 = true;
                    padding = padding.Replace("ANDMGF1PADDING", String.Empty);
                }

                if (padding.Contains('-'))
                    padding = padding.Replace('-', '_');

                HashAlgorithm hashAlgorithm;
                if (!Enum.TryParse(padding, out hashAlgorithm))
                    throw new ArgumentException($"Error Parsing Padding: Unknown Hash Algorithm {padding}");

                return new OaepEncoding(
                        cipher: new RsaEngine(),
                        hash: GetDigest(hashAlgorithm),
                        mgf1Hash: mfg1 ? GetDigest(hashAlgorithm) : null,
                        encodingParams: null
                    );
            }
            catch
            {
                return new OaepEncoding(new RsaEngine(), new Sha256Digest(), new Sha256Digest(), null);
            }
        }

        private static IDigest GetDigest(HashAlgorithm algorithm)
        {
            if (algorithm == HashAlgorithm.NONE)
                algorithm = HashAlgorithm.SHA_256;

            return DigestUtilities.GetDigest(algorithm.ToString());
        }
    }
}
