using CryptoShark;
using CryptoShark.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoSharkTests.EngineTests
{
    internal class RsaEncryptionEngineTests
    {        
        private const string RSA_PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6yg2xBuldFlzX/v4GAEXO2RyYIkOHKX8roArOwDu4+RJtFsRcHjWr45I64oHLpppuaD9XY4gSAemrU7yJrc/PG72h0IG7HhLv343DHfENRFy25vit4ac5WDqdlN+0B1DcLeTaMR1zATOPtg0rSFZhBbbCIaDVOKBNwCOq6z8YuTElqc2HZWRmB03PWMbN8NaAGWC7FPRhDkpsnoWhfjP0JmkTjezrkX5Ww6bv7bRyyzQtmgSVKkCafgTDjfb+ArVqhuz7Sy0moIGwr+mtH78RJ1aajRGCgqpOS/046wf8ztrSi7tzTtktq/htq2VUOTTL9ORhBtWMy9ihFbzlwKNJAgMBAAECggEAfj/jUSviv1BGIJfxCg1VIaINeaZvDgQ2OD5MD8JOm499rM4emkSw8iU2ySYfpI5PAyDi7yYO6lzwmyRV4pjgRJPzcFOF2/tPwWHQZ3jtXJJAOD+VBbHnXRMNS0U8jmoDdU5vyCo6RWkieJgL/p0+BQXfqQchtfw4HVUoxnWKiCI7aSNV0OR6wS0gfrlZuS/vtjBL7ejtSzMAS/+QIXXkrToF+zzgjnXaJ5yyt+O3g/OsvhX9e+tsImkizFyPTKE6dnSJF/q8K7vMa3kZpIEZMNH95ibr7zfFW7qeAT32U5R+0IaDH7/jsfcKbaS37XTATcnnfHEZzNcfyrO7tzGcoQKBgQDr6WwyOrnfdYbFWMuy6fO9G3Sv6wt0vUgpHssR95XEjPIExr4o7iXS4s5OhWDtoe0UhagSbgpJIXszcjlDpAmvxzq1QfCHuL+W1vVILOUD/TkCsqTiON/8/u61R4RjcYX33oFd5nWF+MrNGchq/pH0UgNXzn45ng4N9DwfQ9rS7wKBgQDKsdJw+Ha+p1BNB5Pq9Vz78+Ck/Kvmz6YRxmf6qYyrrL+tdW9kIG3iq+ieEKIMQwxapBeDjI7WJnO8/TAbpkGpWxXZPbN8Gr/QCetswuI0hkvp47fPu1nI+/UmrZkt8aGkjdTluHoP7LzxOuzLKbQeM7NhKvcSxFbNBcjjVkYNRwKBgAu5YQgqBPzHAXijThRJLjTSvXzUqJAXrBNnFV6COG45NvnnyqGMHFMbtHcQh92nc3nWnqCz2U0DHfVTkub6qwSSWSeS7FpCYzsi2bPJj2QgXIn2yNz5SKBxJvnZYQn0JV1JMJKzFlofIC0LP/uZRTWoMcRWXc2NPlORNL+1BpX/AoGAPILbrUgvwvkWGvjxKsq3SKxk2zxnYU+KZ3IQ5p8pVLMMwg72AzE/PNVPa6jRh9GYZZLpRid3GO1/zeLUMtzua0269xDZfWpK6yOa+ewwNbgF/7wwyr5Grp6xcCuROEsTk5mX/kCViB2Hxoht2rUHhaCvo4l9G0gsFabtcxj1bs8CgYEAjadBnv4cTNaRDmPMLXsKIuJ7RPAlobu/UxOgHCDTXcH4W1mWIFNQ29vEsahY5oEoYEiQpRLYeHrQUu8bcHipFKDYobZ/sro12jJsDfNA4boIPlRbZH5EzJalG3kUaQHUjhTOMxim/B1ULxDMF2Tcpj3deO6dXOgYkpeZBZ4Mi3w=";
        private const string PRIVATE_KEY_PW = "PrivatePassword";        
        private byte[] _sampleData;        
        private byte[] _rsaPrivateKey;
        private byte[] _rsaPublicKey;


        [SetUp]
        public void Setup()
        {
            _sampleData = Encoding.UTF8.GetBytes("EncryptionEngineTests Data");            
            _rsaPrivateKey = Convert.FromBase64String(RSA_PRIVATE_KEY);
            _rsaPublicKey = RsaEncryption.RSAUtilities.GetRsaPublicKey(_rsaPrivateKey).ToArray();
        }

        [TestCaseSource("GetSerializationMethods")]
        public void RsaEncryptionTest(EncryptionAlgorithm encryptionAlgorithm)
        {
            RsaEncryption rsaEncryption = new RsaEncryption();

            var encrypted = rsaEncryption.Encrypt(_sampleData, _rsaPublicKey, _rsaPrivateKey, encryptionAlgorithm);
            Assert.That(encrypted.EncryptedData, Is.Not.EqualTo(null));
            Assert.That(encrypted.RSASignature, Is.Not.EqualTo(null));
            Assert.That(encrypted.GcmNonce, Is.Not.EqualTo(null));
            Assert.That(encrypted.EncryptionKey, Is.Not.EqualTo(null));

            var decrypted = rsaEncryption.Decrypt(encrypted.EncryptedData, _rsaPublicKey, _rsaPrivateKey,
                encryptionAlgorithm, encrypted.GcmNonce, encrypted.RSASignature, encrypted.EncryptionKey);

            Assert.That(decrypted.SequenceEqual(_sampleData), Is.True);
        }

        private static Array GetSerializationMethods()
        {
            return Enum.GetValues(typeof(CryptoShark.Enums.EncryptionAlgorithm));
        }
    }
}
