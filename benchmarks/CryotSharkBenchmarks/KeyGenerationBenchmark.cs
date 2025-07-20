using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
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
    //[CPUUsageDiagnoser]
    //[SimpleJob(RunStrategy.Throughput, launchCount: 0,
    //  warmupCount: 0, iterationCount: 1)]
    public class KeyGenerationBenchmark
    {
        private ICryptoSharkCryptographyUtilities _utilities;

        [Params(1024, 2048)]//, 3072, 4096, 7680, 15360)]
        public int RsaKeySizes { get; set; }

        [Params("brainpoolP160r1",
                "brainpoolP224r1")]/*,
                "brainpoolP256r1",
                "brainpoolP320r1",
                "brainpoolP384r1",
                "brainpoolP512r1")]*/
        public string CurveName { get; set; }

        public KeyGenerationBenchmark()
        {
            

          _utilities = CryptoSharkFactory.CreateCryptoSharkFactory().CreateCryptographyUtilities();
        }


        [Benchmark]
        public byte[] CreateRsaKey()
        {
            using var keyParams = new RsaKeyParameters(
                  typeof(KeyGenerationBenchmark).Name,
                  (RsaKeySize)this.RsaKeySizes);

            var key = _utilities.CreateAsymetricKey(keyParams)
                .ToArray();

            return key;
        }

        [Benchmark]
        public byte[] CreateEccKey()
        {
            using var keyParams = new EccKeyParameters(
                 typeof(KeyGenerationBenchmark).Name,
                 ECCurve.CreateFromFriendlyName(CurveName));

            var key = _utilities.CreateAsymetricKey(keyParams)
                .ToArray();

            return key;
        }
    }
}
