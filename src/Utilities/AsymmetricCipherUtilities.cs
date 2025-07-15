using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
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

        public byte[] WriteKeyPair(AsymmetricCipherKeyPair keyPair, SecureString password)
        {
            using MemoryStream pemStream = new MemoryStream();
            using StreamWriter streamWriter = new StreamWriter(pemStream);
            using PemWriter pemWriter = new PemWriter(streamWriter);
            pemWriter.WriteObject(keyPair, "BF-OFB", _secureStringUtilities.SecureStringToCharArray(password), _random);
            pemWriter.Writer.Flush();

            return pemStream.ToArray();
        }

        public byte[] WritePublicKey(AsymmetricKeyParameter publicKey)
        {
            using MemoryStream pemStream = new MemoryStream();
            using StreamWriter streamWriter = new StreamWriter(pemStream);
            using PemWriter pemWriter = new PemWriter(streamWriter);
            pemWriter.WriteObject(publicKey);
            pemWriter.Writer.Flush();

            return pemStream.ToArray();
        }

        public AsymmetricCipherKeyPair ReadKeyPair(byte[] privateKeyData, SecureString password)
        {
            using MemoryStream pemStream = new MemoryStream(privateKeyData);
            using StreamReader reader = new StreamReader(pemStream);
            using PemReader pemReader = new PemReader(reader, new PasswordFinder(password));
            var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();

            return keyPair;
        }

        public AsymmetricKeyParameter ReadPublicKey(byte[] privateKeyData)
        {
            using MemoryStream pemStream = new MemoryStream(privateKeyData);
            using StreamReader reader = new StreamReader(pemStream);
            using PemReader pemReader = new PemReader(reader);
            var publicKey = (AsymmetricKeyParameter)pemReader.ReadObject();

            return publicKey;
        }
    }
}
