using BenchmarkDotNet.Attributes;
using CryptoShark;
using CryptoShark.Enums;
using CryptoShark.Interfaces;
using CryptoShark.Options;
using CryptoShark.Requests;
using Microsoft.VSDiagnostics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryotSharkBenchmarks
{
    [CPUUsageDiagnoser]
    public class KeyGenerationBenchmark
    {
        private ICryptoSharkCryptographyUtilities _utilities;

        [Params(1024, 2048, 3072, 4096, 7680, 15360)]
        public int RsaKeySizes { get; set; }

        [Params("brainpoolP160r1",
                "brainpoolP224r1",
                "brainpoolP256r1",
                "brainpoolP320r1",
                "brainpoolP384r1",
                "brainpoolP512r1")]
        public string CurveName { get; set; }

        public KeyGenerationBenchmark()
        {
          _utilities = CryptoSharkFactory.CreateCryptographyUtilities();
        }


        [Benchmark]
        public ReadOnlyMemory<byte> CreateRsaKey()
        {
            using var keyParams = new RsaKeyParameters(
                  typeof(KeyGenerationBenchmark).Name,
                  (RsaKeySize)this.RsaKeySizes);

            return _utilities.CreateAsymetricKey(keyParams);
        }

        [Benchmark]
        public ReadOnlyMemory<byte> CreateEccKey()
        {
            using var keyParams = new EccKeyParameters(
                 typeof(KeyGenerationBenchmark).Name,
                 ECCurve.CreateFromFriendlyName(CurveName));

            return _utilities.CreateAsymetricKey(keyParams);
        }
    }
}
