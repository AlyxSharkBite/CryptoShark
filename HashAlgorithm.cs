using System;

namespace CryptoShark
{
    /// <summary>
    ///     Hashing Algorithms
    /// </summary>
    public enum HashAlgorithm
    {
        /// <summary>
        ///     MD5 128 Bit
        ///     https://en.wikipedia.org/wiki/MD5
        /// </summary>
        MD5,

        /// <summary>
        ///     SHA-1 160 Bit
        ///     https://en.wikipedia.org/wiki/SHA-1
        /// </summary>
        SHA1,

        /// <summary>
        ///     SHA-2 256 Bit
        ///     https://en.wikipedia.org/wiki/SHA-2
        /// </summary>
        SHA2_256,

        /// <summary>
        ///     SHA-2 384 Bit
        ///     https://en.wikipedia.org/wiki/SHA-2
        /// </summary>
        SHA2_384,

        /// <summary>
        ///     SHA-2 512 Bit
        ///     https://en.wikipedia.org/wiki/SHA-2
        /// </summary>
        SHA2_512,

        /// <summary>
        ///     SHA-3 256 Bit
        ///     https://en.wikipedia.org/wiki/SHA-3
        /// </summary>
        SHA3_256,

        /// <summary>
        ///     SHA-3 384 Bit
        ///     https://en.wikipedia.org/wiki/SHA-3
        /// </summary>
        SHA3_384,

        /// <summary>
        ///     SHA-3 512 Bit
        ///     https://en.wikipedia.org/wiki/SHA-3
        /// </summary>
        SHA3_512,

        /// <summary>
        ///     RIPEMD 128 Bit
        ///     https://en.wikipedia.org/wiki/RIPEMD
        /// </summary>
        RipeMD_128,

        /// <summary>
        ///     RIPEMD 160 Bit
        ///     https://en.wikipedia.org/wiki/RIPEMD
        /// </summary>
        RipeMD_160,

        /// <summary>
        ///     RIPEMD 256 Bit
        ///     https://en.wikipedia.org/wiki/RIPEMD
        /// </summary>
        RipeMD_256,

        /// <summary>
        ///     RIPEMD 320 Bit
        ///     https://en.wikipedia.org/wiki/RIPEMD
        /// </summary>
        RipeMD_320,

        /// <summary>
        ///     Whirlpool 512 Bit
        ///     https://en.wikipedia.org/wiki/Whirlpool_(hash_function)
        /// </summary>
        Whirlpool

    }
}
