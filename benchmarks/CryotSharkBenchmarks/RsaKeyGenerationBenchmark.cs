using BenchmarkDotNet.Attributes;
using CryptoShark;
using CryptoShark.Configuration;
using CryptoShark.Interfaces;
using CryptoShark.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryotSharkBenchmarks
{
    public class RsaKeyGenerationBenchmark
    {
        private ICryptoSharkCryptographyUtilities _utilities;
        private CryptoSharkConfiguration _configuration = new CryptoSharkConfiguration
        {
            PreferDotNetKeyGeneration = true
        };

        [Params(1024, 2048, 3072, 4096, 7680, 15360)]
        public int RsaKeySize { get; set; }

        public RsaKeyGenerationBenchmark()
        {
            _utilities = CryptoSharkFactory
                  .CreateCryptoSharkFactory(_configuration)
                  .CreateCryptographyUtilities();
        }
        [Benchmark]
        public byte[] CreateEccKey()
        {
            using var keyParams = new RsaKeyParameters(
                    typeof(RsaKeyGenerationBenchmark).Name,
                    (CryptoShark.Enums.RsaKeySize)RsaKeySize);

            var key = _utilities.CreateAsymetricKey(keyParams)
                .ToArray();

            return key;
        }
    }
}
