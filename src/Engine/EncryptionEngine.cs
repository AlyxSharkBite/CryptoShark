using CryptoShark.Enums;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoShark.Engine
{
    internal sealed class EncryptionEngine
    {               
        private readonly EncryptionAlgorithm _encryptionAlgorithm;
        private readonly ZLibCompressionOptions _zlibCompressionOptions;

        public EncryptionEngine(EncryptionAlgorithm encryptionAlgorithm)
        {            
            _encryptionAlgorithm = encryptionAlgorithm;
            _zlibCompressionOptions = new ZLibCompressionOptions
            {
                CompressionStrategy = ZLibCompressionStrategy.HuffmanOnly
            };
        }

        /// <summary>
        /// Encrypts Data
        /// </summary>
        /// <param name="data">Data to Encrypt</param>
        /// <param name="key">Encryotion Key</param>
        /// <param name="nonce">Nonce Token</param>
        /// <param name="compress">Compress data before encryption Token</param>
        /// <returns></returns>
        public ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> nonce, bool compress)
        {
            // Create the Encryption Engine
            var engine = GetBlockEngine(_encryptionAlgorithm);

            // Compress
            if (compress)
                data = Compress(data);

            // Create the Cipher from the Engine
            var cipher = new GcmBlockCipher(engine);

            // Create the Paramters used to emcrypt
            var cipherParameters = new AeadParameters(
                new KeyParameter(key.ToArray()),
                8 * cipher.GetBlockSize(),
                nonce.ToArray());

           // Init the Cipher          
            cipher.Init(true, cipherParameters);

            // Allocate the Buffer for the Encrypted Data
            var encryptedData = new byte[cipher.GetOutputSize(data.Length)];

            // Encrypt
            var res = cipher.ProcessBytes(data.ToArray(),
                0,
                data.Length,
                encryptedData,
                0);

            // Process Final Block
            cipher.DoFinal(encryptedData, res);            

            return encryptedData;
        }

        /// <summary>
        /// Decrypts Data
        /// </summary>
        /// <param name="data">Data to Decrypt</param>
        /// <param name="key">Encryption Key</param>
        /// <param name="nonce">Nonce Token</param>
        /// <returns></returns>
        public ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> nonce)
        {
            // Create the Engine
            var engine = GetBlockEngine(_encryptionAlgorithm);

            // Create the Cipher from the Engine
            var cipher = new GcmBlockCipher(engine);

            // Create the Cipher Parameters 
            var cipherParameters = new AeadParameters(
                new KeyParameter(key.ToArray()),
                8 * cipher.GetBlockSize(),
                nonce.ToArray());

            // Init the Cipher               
            cipher.Init(false, cipherParameters);

            // Allocate the buffer for the decrypted data
            var decryptedData = new byte[cipher.GetOutputSize(data.Length)];

            // Decrypt
            var res = cipher.ProcessBytes(data.ToArray(),
                0,
                data.Length,
                decryptedData,
                0);

            // Process final block
            cipher.DoFinal(decryptedData, res);

            // Deompress if needed
            if (decryptedData[0] == 0x78 && decryptedData[1] == 0x01)
                decryptedData = Decompress(decryptedData);

            return decryptedData;
        }

        private byte[] Decompress(byte[] data)
        {
            using (var memoryStream = new MemoryStream(data))
            {
                using (var outputStream = new MemoryStream())
                {
                    using (var decompressStream = new ZLibStream(memoryStream, CompressionMode.Decompress))
                        decompressStream.CopyTo(outputStream);

                    return outputStream.ToArray();
                }
            }
        }

        private ReadOnlyMemory<byte> Compress(ReadOnlyMemory<byte> data)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var zlibStream = new ZLibStream(memoryStream, _zlibCompressionOptions))                
                    zlibStream.Write(data.ToArray(), 0, data.Length);
                
                return memoryStream.ToArray();
            }
        }

        private IBlockCipher GetBlockEngine(EncryptionAlgorithm algorithmName)
        {
            switch (algorithmName)
            {
                case EncryptionAlgorithm.Camellia:
                    return new CamelliaEngine();
                case EncryptionAlgorithm.CAST6:
                    return new Cast6Engine();
                case EncryptionAlgorithm.RC6:
                    return new RC6Engine();
                case EncryptionAlgorithm.Serpent:
                    return new SerpentEngine();
                case EncryptionAlgorithm.TwoFish:
                    return new TwofishEngine();
                case EncryptionAlgorithm.Aes:
                    return new AesEngine();
                default:
                    throw new ArgumentException("Unkown Encryption Algorithm");
            }
        }



    }
}
