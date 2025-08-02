using System.Runtime.CompilerServices;
using System.Threading;

namespace Qeen.Core.Packet;

/// <summary>
/// Manages packet number spaces for QUIC connections as defined in RFC 9000
/// </summary>
public struct PacketNumberSpace
{
    // RFC 9000 Section 17.1: Maximum packet number is 2^62 - 1
    private const long MaxPacketNumber = (1L << 62) - 1;
    
    private long _largestAcked;
    private long _largestReceived;
    private long _nextPacketNumber;

    /// <summary>
    /// Gets the largest acknowledged packet number
    /// </summary>
    public readonly long LargestAcked => Volatile.Read(ref Unsafe.AsRef(in _largestAcked));

    /// <summary>
    /// Gets the largest received packet number
    /// </summary>
    public readonly long LargestReceived => Volatile.Read(ref Unsafe.AsRef(in _largestReceived));

    /// <summary>
    /// Gets the next packet number to send
    /// </summary>
    public readonly long NextPacketNumber => Volatile.Read(ref Unsafe.AsRef(in _nextPacketNumber));

    /// <summary>
    /// Initializes a new PacketNumberSpace
    /// </summary>
    public PacketNumberSpace()
    {
        _largestAcked = -1;
        _largestReceived = -1;
        _nextPacketNumber = 0;
    }

    /// <summary>
    /// Gets the next packet number and increments the counter
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public long GetNextPacketNumber()
    {
        var nextNumber = Interlocked.Increment(ref _nextPacketNumber) - 1;
        
        // RFC 9000 Section 17.1: Packet number must not exceed 2^62 - 1
        if (nextNumber > MaxPacketNumber)
        {
            throw new InvalidOperationException(
                $"Packet number would exceed maximum value of {MaxPacketNumber}. " +
                "Connection must be closed with AEAD_LIMIT_REACHED error.");
        }
        
        return nextNumber;
    }

    /// <summary>
    /// Updates the largest acknowledged packet number
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void UpdateLargestAcked(long packetNumber)
    {
        long current;
        do
        {
            current = _largestAcked;
            if (packetNumber <= current) return;
        } while (Interlocked.CompareExchange(ref _largestAcked, packetNumber, current) != current);
    }

    /// <summary>
    /// Updates the largest received packet number
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void UpdateLargestReceived(long packetNumber)
    {
        long current;
        do
        {
            current = _largestReceived;
            if (packetNumber <= current) return;
        } while (Interlocked.CompareExchange(ref _largestReceived, packetNumber, current) != current);
    }

    /// <summary>
    /// Checks if a packet number is valid (not duplicate)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public readonly bool IsValidPacketNumber(long packetNumber)
    {
        // A packet number is valid if it's greater than the largest received
        // or within a reasonable window for reordering
        long largest = LargestReceived;
        if (packetNumber > largest)
            return true;

        // Allow for some reordering (e.g., within 1000 packets)
        const long ReorderingThreshold = 1000;
        return packetNumber >= largest - ReorderingThreshold;
    }

    /// <summary>
    /// Determines the optimal packet number encoding length
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public readonly int GetPacketNumberLength(long packetNumber)
    {
        long largestAcked = LargestAcked;
        
        // Calculate the number of unacknowledged packets
        // This matches the algorithm in PacketProcessor.EncodePacketNumber
        long numUnacked = largestAcked == -1 ? packetNumber + 1 : packetNumber - largestAcked;
        
        // The number of bits must be at least one more than the base-2 logarithm
        // of the number of contiguous unacknowledged packet numbers
        int minBits = numUnacked > 0 ? (int)Math.Ceiling(Math.Log2(numUnacked)) + 1 : 1;
        
        // Round up to the nearest byte
        int length = (minBits + 7) / 8;
        
        // Ensure we use at least 1 byte and at most 4 bytes
        return Math.Max(1, Math.Min(4, length));
    }

    /// <summary>
    /// Resets the packet number space
    /// </summary>
    public void Reset()
    {
        Volatile.Write(ref _largestAcked, -1);
        Volatile.Write(ref _largestReceived, -1);
        Volatile.Write(ref _nextPacketNumber, 0);
    }
}

/// <summary>
/// Manages all three packet number spaces for a QUIC connection
/// </summary>
public sealed class PacketNumberSpaceManager
{
    /// <summary>
    /// Initial packet number space
    /// </summary>
    public PacketNumberSpace Initial;

    /// <summary>
    /// Handshake packet number space
    /// </summary>
    public PacketNumberSpace Handshake;

    /// <summary>
    /// Application data (1-RTT) packet number space
    /// </summary>
    public PacketNumberSpace ApplicationData;

    /// <summary>
    /// Initializes a new PacketNumberSpaceManager
    /// </summary>
    public PacketNumberSpaceManager()
    {
        Initial = new PacketNumberSpace();
        Handshake = new PacketNumberSpace();
        ApplicationData = new PacketNumberSpace();
    }

    /// <summary>
    /// Gets the packet number space for a given packet type
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ref PacketNumberSpace GetSpace(PacketType packetType)
    {
        switch (packetType)
        {
            case PacketType.Initial:
            case PacketType.Retry:
                return ref Initial;

            case PacketType.Handshake:
                return ref Handshake;

            case PacketType.ZeroRtt:
            case PacketType.OneRtt:
                return ref ApplicationData;

            default:
                throw new ArgumentException($"Invalid packet type for packet number space: {packetType}");
        }
    }

    /// <summary>
    /// Resets all packet number spaces
    /// </summary>
    public void Reset()
    {
        Initial.Reset();
        Handshake.Reset();
        ApplicationData.Reset();
    }
}