using CryptoShark.Enums;
using CryptoShark.Interfaces;
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
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
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

        public AsymmetricCipherKeyPair GenerateECDHKeyPair(System.Security.Cryptography.ECCurve curve)
        {
            ECDomainParameters ecDomainParameters = EcGetBuiltInDomainParameters(curve);
            ECKeyGenerationParameters ecKeyGenParams = new ECKeyGenerationParameters(ecDomainParameters, _random);
            ECKeyPairGenerator ecKeyPairGen = new ECKeyPairGenerator();
            ecKeyPairGen.Init(ecKeyGenParams);
            AsymmetricCipherKeyPair ecKeyPair = ecKeyPairGen.GenerateKeyPair();
            return ecKeyPair;
        }        

        public AsymmetricCipherKeyPair GenerateRsaKeyPair(int keySize, bool useDotNey)
        {            
            if (useDotNey)
            {                
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    return GenerateRsaKeyPairCsp(keySize);                
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    return GenerateRsaKeyPairOpenssl(keySize);                
                else
                    return GenerateRsaKeyPairDotnet(keySize);
            }

            var keyPairGenerator = new RsaKeyPairGenerator();
            var keyGenParams = new KeyGenerationParameters(_random, keySize);
            keyPairGenerator.Init(keyGenParams);
            AsymmetricCipherKeyPair rsaKeyPair = keyPairGenerator.GenerateKeyPair();

            return rsaKeyPair;
        }

        public ReadOnlyMemory<byte> WritePrivateKey(AsymmetricKeyParameter asymmetricKeyParameter, SecureString password)
        {
            using MemoryStream pemStream = new MemoryStream();
            using StreamWriter streamWriter = new StreamWriter(pemStream);
            using PemWriter pemWriter = new PemWriter(streamWriter);
            pemWriter.WriteObject(asymmetricKeyParameter, "BF-OFB", _secureStringUtilities.SecureStringToCharArray(password), new SecureRandom());
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

        public AsymmetricKeyParameter ReadPrivateKey(ReadOnlyMemory<byte> privateKeyData, SecureString password)
        {
            using MemoryStream pemStream = new MemoryStream(privateKeyData.ToArray());
            using StreamReader reader = new StreamReader(pemStream);
            using PemReader pemReader = new PemReader(reader, new PasswordFinder(password));
            object pemObject = pemReader.ReadObject();

            var asymmetricCipherKeyPair = pemObject as AsymmetricCipherKeyPair;
            if (asymmetricCipherKeyPair is not null)
                return asymmetricCipherKeyPair.Private;

            return (AsymmetricKeyParameter)pemObject;
        }

        public AsymmetricKeyParameter ReadPublicKey(ReadOnlyMemory<byte> publicKeyData)
        {
            using MemoryStream pemStream = new MemoryStream(publicKeyData.ToArray());
            using StreamReader reader = new StreamReader(pemStream);
            using PemReader pemReader = new PemReader(reader);
            var publicKey = (AsymmetricKeyParameter)pemReader.ReadObject();

            return publicKey;
        }

        public AsymmetricKeyParameter GetPublicKey(AsymmetricKeyParameter privatkeKey)
        {
            var rsaPrivateKey = privatkeKey as RsaPrivateCrtKeyParameters;
            if (rsaPrivateKey is not null)
                return new RsaKeyParameters(false, rsaPrivateKey.Modulus, rsaPrivateKey.PublicExponent);

            var ecPrivateKey = privatkeKey as ECPrivateKeyParameters;
            if (ecPrivateKey is not null)
                return new ECPublicKeyParameters(ecPrivateKey.Parameters.G.Multiply(ecPrivateKey.D), ecPrivateKey.Parameters);

            throw new ArgumentException($"{nameof(privatkeKey)} is {privatkeKey.GetType().Name} which is not supported.");
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
                    return new OaepEncoding(new RsaEngine(), new Sha256Digest(), new Sha256Digest(), null);

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

        private ECDomainParameters EcGetBuiltInDomainParameters(System.Security.Cryptography.ECCurve curve)
        {
            X9ECParameters ecParams = ECNamedCurveTable.GetByOid(
                    new DerObjectIdentifier(curve.Oid.Value)
                );

            return new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N,
                ecParams.H, ecParams.GetSeed());
        }

        
        private AsymmetricCipherKeyPair GenerateRsaKeyPairCsp(int keySize)
        {
            // Use the Windows CSP if not running through transation (ex Windows on ARM)
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
               (RuntimeInformation.ProcessArchitecture == Architecture.X64 ||
                RuntimeInformation.ProcessArchitecture == Architecture.X86))
            {
                using var rsaCsp = new System.Security.Cryptography.RSACryptoServiceProvider(keySize);
                return DotNetUtilities.GetRsaKeyPair(rsaCsp);
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                using var rsaCng = new System.Security.Cryptography.RSACng(keySize);
                return DotNetUtilities.GetRsaKeyPair(rsaCng);
            }
            else
            {
                return GenerateRsaKeyPairDotnet(keySize);
            }
        }
              
        private AsymmetricCipherKeyPair GenerateRsaKeyPairOpenssl(int keySize)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                using var rsaOpenSsl = new System.Security.Cryptography.RSAOpenSsl(keySize);
                return DotNetUtilities.GetRsaKeyPair(rsaOpenSsl);
            }
            else
            {                
                return GenerateRsaKeyPairDotnet(keySize);
            }
        }
        
        private AsymmetricCipherKeyPair GenerateRsaKeyPairDotnet(int keySize)
        {
            using var rsa = System.Security.Cryptography.RSA.Create(keySize);
            return DotNetUtilities.GetRsaKeyPair(rsa);
        }

    }
}
