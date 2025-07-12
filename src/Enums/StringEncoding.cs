using System;

namespace CryptoShark.Enums
{
    /// <summary>
    ///     String Encoding Options
    /// </summary>
    public enum StringEncoding
    {
        /// <summary>
        ///     Hexadecimal format
        /// </summary>
        Hex,

        /// <summary>
        ///     Base64 Encoded
        /// </summary>
        Base64,

        /// <summary>
        ///     Url Base64 Encoded
        ///     (safe for use as part of a url query string)
        /// </summary>
        UrlBase64
    }
}
