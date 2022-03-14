using System;

namespace CryptoShark.Enums
{
    /// <summary>
    ///     Encryption Algorithm
    /// </summary>
    public enum EncryptionAlgorithm : byte
    {
        /// <summary>
        ///     AES
        ///     https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
        /// </summary>
        Aes,

        /// <summary>
        ///     Camellia
        ///     https://en.wikipedia.org/wiki/Camellia_(cipher)
        /// </summary>
        Camellia,

        /// <summary>
        ///     CAST6 / CAST-256
        ///     https://en.wikipedia.org/wiki/CAST-256
        /// </summary>
        CAST6,

        /// <summary>
        ///     RC6
        ///     https://en.wikipedia.org/wiki/RC6
        /// </summary>
        RC6,

        /// <summary>
        ///     Serpent
        ///     https://en.wikipedia.org/wiki/Serpent_(cipher)
        /// </summary>
        Serpent,

        /// <summary>
        ///     TwoFish
        ///     https://en.wikipedia.org/wiki/Twofish
        /// </summary>
        TwoFish
    }
}
