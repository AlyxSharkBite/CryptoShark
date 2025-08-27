using BenchmarkDotNet.Attributes;
using CryptoShark;
using CryptoShark.Configuration;
using CryptoShark.Requests;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace CryotSharkBenchmarks
{
    public class CryptoSharkCompressionBenchmark
    {
        private readonly RandomDataGenerator.Randomizers.IRandomizerBytes _randomizer = RandomDataGenerator.Randomizers.RandomizerFactory.GetRandomizer(new RandomDataGenerator.FieldOptions.FieldOptionsBytes { Min = 1000000, Max = 1000000 });
        private readonly char[] _pasword = new char[] { 'T', 'e', 's', 't', '1', '2', '3' };
        private byte[] _data;

        public CryptoSharkCompressionBenchmark()
        {
            _data = _randomizer.Generate();
        }

        [Benchmark]
        public TimeSpan EncryptNoCompresstion()
        {
            var configuration = new CryptoSharkConfiguration
            {
                CompressBeforeEncryption = false
            };

            SecureString password = new SecureString();
            foreach (char c in _pasword)
                password.AppendChar(c);
            password.MakeReadOnly();

            var encryptor = CryptoSharkFactory
                  .CreateCryptoSharkFactory(configuration)
                  .CreateSymmetricCryptography();

            var request = SemetricEncryptionRequest.CreateRequest(_data, password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA_256, false);

            Stopwatch stopwatch = Stopwatch.StartNew();
            var result = encryptor.Encrypt(request);
            stopwatch.Stop();

            return stopwatch.Elapsed;
        }

        [Benchmark]
        public TimeSpan EncryptCompresstion()
        {
            var configuration = new CryptoSharkConfiguration
            {
                CompressBeforeEncryption = true
            };

            SecureString password = new SecureString();
            foreach (char c in _pasword)
                password.AppendChar(c);
            password.MakeReadOnly();

            var encryptor = CryptoSharkFactory
                  .CreateCryptoSharkFactory(configuration)
                  .CreateSymmetricCryptography();

            var request = SemetricEncryptionRequest.CreateRequest(_data, password, CryptoShark.Enums.EncryptionAlgorithm.Aes, CryptoShark.Enums.HashAlgorithm.SHA_256, true);

            Stopwatch stopwatch = Stopwatch.StartNew();
            var result = encryptor.Encrypt(request);
            stopwatch.Stop();

            return stopwatch.Elapsed;
        }
    }
}
