namespace CryptoShark.Enums;

/// <summary>
/// Serialization Method
/// </summary>
public enum SerializationMethod : short
{
    /// <summary>
    /// BLOB (Binary Large Object) Format
    /// Note Max Encrypted Data Length = 2Gb
    /// </summary>
    BinarySerialization = 0x00,
    
    /// <summary>
    /// Binary Json Format
    /// </summary>
    BsonSerialization = 0x01,
    
    /// <summary>
    /// Json Format
    /// </summary>
    JsonSerialization = 0x02,
    
    /// <summary>
    /// XML Format
    /// </summary>
    XmlSerialization = 0x03
}