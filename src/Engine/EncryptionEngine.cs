﻿using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using CryptoShark.Enums;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoShark.Engine
{
    internal sealed class EncryptionEngine
    {               
        private readonly EncryptionAlgorithm _encryptionAlgorithm;

        public EncryptionEngine(EncryptionAlgorithm encryptionAlgorithm)
        {            
            _encryptionAlgorithm = encryptionAlgorithm;
        }

        /// <summary>
        /// Encrypts Data
        /// </summary>
        /// <param name="data">Data to Encrypt</param>
        /// <param name="key">Encryotion Key</param>
        /// <param name="nonce">Nonce Token</param>
        /// <returns></returns>
        public byte[] Encrypt(ReadOnlyMemory<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
        {
            // Create the Encryption Engine
            var engine = GetBlockEngine(_encryptionAlgorithm);

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
        public byte[] Decrypt(ReadOnlyMemory<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
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

            return decryptedData;
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
