using System.Runtime.CompilerServices;

namespace Qeen.Core.Frame;

/// <summary>
/// Handles encoding and decoding of ACK delay values according to RFC 9000.
/// The ACK delay is encoded as an integer representing microseconds scaled by 2^ack_delay_exponent.
/// </summary>
public static class AckDelayEncoder
{
    /// <summary>
    /// Default ACK delay exponent value as specified in RFC 9000.
    /// </summary>
    public const byte DefaultAckDelayExponent = 3;
    
    /// <summary>
    /// Maximum allowed ACK delay exponent value (20) as specified in RFC 9000.
    /// Values above 20 are invalid.
    /// </summary>
    public const byte MaxAckDelayExponent = 20;
    
    /// <summary>
    /// Encodes an ACK delay from microseconds to the wire format.
    /// RFC 9000 Section 18.2: delay = delay_in_microseconds / (2^ack_delay_exponent)
    /// </summary>
    /// <param name="delayMicroseconds">The delay in microseconds.</param>
    /// <param name="ackDelayExponent">The ACK delay exponent (0-20).</param>
    /// <returns>The encoded delay value for the wire format.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong EncodeAckDelay(ulong delayMicroseconds, byte ackDelayExponent)
    {
        if (ackDelayExponent > MaxAckDelayExponent)
        {
            throw new ArgumentOutOfRangeException(nameof(ackDelayExponent), 
                $"ACK delay exponent must be between 0 and {MaxAckDelayExponent}");
        }
        
        // Divide by 2^ack_delay_exponent using right shift
        return delayMicroseconds >> ackDelayExponent;
    }
    
    /// <summary>
    /// Decodes an ACK delay from the wire format to microseconds.
    /// RFC 9000 Section 18.2: delay_in_microseconds = delay * (2^ack_delay_exponent)
    /// </summary>
    /// <param name="encodedDelay">The encoded delay value from the wire.</param>
    /// <param name="ackDelayExponent">The ACK delay exponent (0-20).</param>
    /// <returns>The decoded delay in microseconds.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong DecodeAckDelay(ulong encodedDelay, byte ackDelayExponent)
    {
        if (ackDelayExponent > MaxAckDelayExponent)
        {
            throw new ArgumentOutOfRangeException(nameof(ackDelayExponent), 
                $"ACK delay exponent must be between 0 and {MaxAckDelayExponent}");
        }
        
        // Multiply by 2^ack_delay_exponent using left shift
        // Check for overflow
        if (ackDelayExponent > 0 && encodedDelay > (ulong.MaxValue >> ackDelayExponent))
        {
            // Saturate to maximum value on overflow
            return ulong.MaxValue;
        }
        
        return encodedDelay << ackDelayExponent;
    }
    
    /// <summary>
    /// Converts microseconds to a TimeSpan.
    /// </summary>
    /// <param name="microseconds">The microseconds value.</param>
    /// <returns>The corresponding TimeSpan.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static TimeSpan MicrosecondsToTimeSpan(ulong microseconds)
    {
        // TimeSpan ticks are 100 nanoseconds, microseconds are 1000 nanoseconds
        // So 1 microsecond = 10 ticks
        const long ticksPerMicrosecond = 10;
        
        // Check for overflow
        if (microseconds > (ulong)(long.MaxValue / ticksPerMicrosecond))
        {
            return TimeSpan.MaxValue;
        }
        
        return TimeSpan.FromTicks((long)microseconds * ticksPerMicrosecond);
    }
    
    /// <summary>
    /// Converts a TimeSpan to microseconds.
    /// </summary>
    /// <param name="timeSpan">The TimeSpan value.</param>
    /// <returns>The corresponding microseconds value.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong TimeSpanToMicroseconds(TimeSpan timeSpan)
    {
        // TimeSpan ticks are 100 nanoseconds, microseconds are 1000 nanoseconds
        // So 1 microsecond = 10 ticks
        const long ticksPerMicrosecond = 10;
        
        if (timeSpan.Ticks < 0)
        {
            return 0;
        }
        
        return (ulong)(timeSpan.Ticks / ticksPerMicrosecond);
    }
    
    /// <summary>
    /// Validates an ACK delay exponent value.
    /// </summary>
    /// <param name="ackDelayExponent">The ACK delay exponent to validate.</param>
    /// <returns>True if the value is valid (0-20), false otherwise.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsValidAckDelayExponent(byte ackDelayExponent)
    {
        return ackDelayExponent <= MaxAckDelayExponent;
    }
}