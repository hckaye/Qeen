using System;
using System.Buffers.Binary;
using Qeen.Core.Connection;

namespace Qeen.Security.Tls;

/// <summary>
/// Encodes and decodes QUIC Transport Parameters for TLS extension (0xffa5)
/// as defined in RFC 9000 Section 18
/// </summary>
public static class TransportParametersCodec
{
    public const ushort TlsExtensionType = 0xffa5;

    private enum ParameterId : ulong
    {
        OriginalDestinationConnectionId = 0x00,
        MaxIdleTimeout = 0x01,
        StatelessResetToken = 0x02,
        MaxUdpPayloadSize = 0x03,
        InitialMaxData = 0x04,
        InitialMaxStreamDataBidiLocal = 0x05,
        InitialMaxStreamDataBidiRemote = 0x06,
        InitialMaxStreamDataUni = 0x07,
        InitialMaxStreamsBidi = 0x08,
        InitialMaxStreamsUni = 0x09,
        AckDelayExponent = 0x0a,
        MaxAckDelay = 0x0b,
        DisableActiveMigration = 0x0c,
        PreferredAddress = 0x0d,
        ActiveConnectionIdLimit = 0x0e,
        InitialSourceConnectionId = 0x0f,
        RetrySourceConnectionId = 0x10,
        MaxDatagramFrameSize = 0x11,
        GreaseParameter = 0x1a2a  // Reserved for greasing
    }

    /// <summary>
    /// Encodes transport parameters for inclusion in TLS handshake
    /// </summary>
    public static byte[] Encode(TransportParameters parameters, bool isServer)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);

        // For client, must include initial_source_connection_id
        if (!isServer && parameters.InitialSourceConnectionId.HasValue)
        {
            WriteParameter(writer, ParameterId.InitialSourceConnectionId, 
                parameters.InitialSourceConnectionId.Value.ToArray());
        }

        // Max idle timeout (in milliseconds)
        if (parameters.MaxIdleTimeout > 0)
        {
            WriteVarIntParameter(writer, ParameterId.MaxIdleTimeout, parameters.MaxIdleTimeout);
        }

        // Stateless reset token (server only, exactly 16 bytes)
        if (isServer && parameters.StatelessResetToken != null && parameters.StatelessResetToken.Length == 16)
        {
            WriteParameter(writer, ParameterId.StatelessResetToken, parameters.StatelessResetToken);
        }

        // Max UDP payload size
        if (parameters.MaxUdpPayloadSize != 1200) // Only write if not default
        {
            WriteVarIntParameter(writer, ParameterId.MaxUdpPayloadSize, parameters.MaxUdpPayloadSize);
        }

        // Flow control parameters
        if (parameters.InitialMaxData > 0)
        {
            WriteVarIntParameter(writer, ParameterId.InitialMaxData, parameters.InitialMaxData);
        }

        if (parameters.InitialMaxStreamDataBidiLocal > 0)
        {
            WriteVarIntParameter(writer, ParameterId.InitialMaxStreamDataBidiLocal, 
                parameters.InitialMaxStreamDataBidiLocal);
        }

        if (parameters.InitialMaxStreamDataBidiRemote > 0)
        {
            WriteVarIntParameter(writer, ParameterId.InitialMaxStreamDataBidiRemote, 
                parameters.InitialMaxStreamDataBidiRemote);
        }

        if (parameters.InitialMaxStreamDataUni > 0)
        {
            WriteVarIntParameter(writer, ParameterId.InitialMaxStreamDataUni, 
                parameters.InitialMaxStreamDataUni);
        }

        // Stream limits
        if (parameters.InitialMaxStreamsBidi > 0)
        {
            WriteVarIntParameter(writer, ParameterId.InitialMaxStreamsBidi, 
                parameters.InitialMaxStreamsBidi);
        }

        if (parameters.InitialMaxStreamsUni > 0)
        {
            WriteVarIntParameter(writer, ParameterId.InitialMaxStreamsUni, 
                parameters.InitialMaxStreamsUni);
        }

        // ACK delay parameters
        if (parameters.AckDelayExponent != 3) // Only write if not default
        {
            WriteVarIntParameter(writer, ParameterId.AckDelayExponent, parameters.AckDelayExponent);
        }

        if (parameters.MaxAckDelay != 25) // Only write if not default (25ms)
        {
            WriteVarIntParameter(writer, ParameterId.MaxAckDelay, parameters.MaxAckDelay);
        }

        // Disable active migration
        if (parameters.DisableActiveMigration)
        {
            WriteVarInt(writer, (ulong)ParameterId.DisableActiveMigration);
            WriteVarInt(writer, 0); // Zero-length value
        }

        // Active connection ID limit
        if (parameters.ActiveConnectionIdLimit != 2) // Only write if not default
        {
            WriteVarIntParameter(writer, ParameterId.ActiveConnectionIdLimit, 
                parameters.ActiveConnectionIdLimit);
        }

        // Server-only parameters
        if (isServer)
        {
            if (parameters.InitialSourceConnectionId.HasValue)
            {
                WriteParameter(writer, ParameterId.InitialSourceConnectionId, 
                    parameters.InitialSourceConnectionId.Value.ToArray());
            }

            if (parameters.RetrySourceConnectionId.HasValue)
            {
                WriteParameter(writer, ParameterId.RetrySourceConnectionId, 
                    parameters.RetrySourceConnectionId.Value.ToArray());
            }

            // Preferred address (complex structure, skip for now)
            // TODO: Implement preferred address encoding when needed
        }

        // Max datagram frame size (0 means not supported)
        if (parameters.MaxDatagramFrameSize > 0)
        {
            WriteVarIntParameter(writer, ParameterId.MaxDatagramFrameSize, 
                parameters.MaxDatagramFrameSize);
        }

        return stream.ToArray();
    }

    /// <summary>
    /// Decodes transport parameters from TLS extension data
    /// </summary>
    public static TransportParameters Decode(ReadOnlySpan<byte> data, bool isServer)
    {
        var parameters = TransportParameters.GetDefault();
        var position = 0;

        while (position < data.Length)
        {
            // Read parameter ID
            var (paramId, idLen) = ReadVarInt(data[position..]);
            position += idLen;

            if (position >= data.Length)
                break;

            // Read parameter length
            var (paramLength, lengthLen) = ReadVarInt(data[position..]);
            position += lengthLen;

            if (position + (int)paramLength > data.Length)
                throw new InvalidOperationException("Invalid transport parameters: length exceeds data");

            var paramData = data.Slice(position, (int)paramLength);
            position += (int)paramLength;

            // Process parameter based on ID
            switch ((ParameterId)paramId)
            {
                case ParameterId.OriginalDestinationConnectionId:
                    // Server receives this from client's perspective
                    if (!isServer && paramData.Length <= ConnectionId.MaxLength)
                    {
                        // This would be stored separately as it's not in our TransportParameters struct
                    }
                    break;

                case ParameterId.MaxIdleTimeout:
                    parameters.MaxIdleTimeout = ReadVarIntValue(paramData);
                    parameters.IdleTimeout = parameters.MaxIdleTimeout; // Keep both in sync
                    break;

                case ParameterId.StatelessResetToken:
                    if (paramData.Length == 16)
                    {
                        parameters.StatelessResetToken = paramData.ToArray();
                    }
                    break;

                case ParameterId.MaxUdpPayloadSize:
                    parameters.MaxUdpPayloadSize = ReadVarIntValue(paramData);
                    break;

                case ParameterId.InitialMaxData:
                    parameters.InitialMaxData = ReadVarIntValue(paramData);
                    break;

                case ParameterId.InitialMaxStreamDataBidiLocal:
                    parameters.InitialMaxStreamDataBidiLocal = ReadVarIntValue(paramData);
                    break;

                case ParameterId.InitialMaxStreamDataBidiRemote:
                    parameters.InitialMaxStreamDataBidiRemote = ReadVarIntValue(paramData);
                    break;

                case ParameterId.InitialMaxStreamDataUni:
                    parameters.InitialMaxStreamDataUni = ReadVarIntValue(paramData);
                    break;

                case ParameterId.InitialMaxStreamsBidi:
                    parameters.InitialMaxStreamsBidi = ReadVarIntValue(paramData);
                    break;

                case ParameterId.InitialMaxStreamsUni:
                    parameters.InitialMaxStreamsUni = ReadVarIntValue(paramData);
                    break;

                case ParameterId.AckDelayExponent:
                    parameters.AckDelayExponent = ReadVarIntValue(paramData);
                    break;

                case ParameterId.MaxAckDelay:
                    parameters.MaxAckDelay = ReadVarIntValue(paramData);
                    break;

                case ParameterId.DisableActiveMigration:
                    parameters.DisableActiveMigration = true;
                    break;

                case ParameterId.ActiveConnectionIdLimit:
                    parameters.ActiveConnectionIdLimit = ReadVarIntValue(paramData);
                    break;

                case ParameterId.InitialSourceConnectionId:
                    if (paramData.Length <= ConnectionId.MaxLength)
                    {
                        parameters.InitialSourceConnectionId = new ConnectionId(paramData);
                    }
                    break;

                case ParameterId.RetrySourceConnectionId:
                    if (paramData.Length <= ConnectionId.MaxLength)
                    {
                        parameters.RetrySourceConnectionId = new ConnectionId(paramData);
                    }
                    break;

                case ParameterId.PreferredAddress:
                    // TODO: Implement preferred address decoding when needed
                    break;

                case ParameterId.MaxDatagramFrameSize:
                    parameters.MaxDatagramFrameSize = ReadVarIntValue(paramData);
                    break;

                default:
                    // Unknown parameter - ignore per RFC 9000
                    break;
            }
        }

        return parameters;
    }

    private static void WriteParameter(BinaryWriter writer, ParameterId id, byte[] value)
    {
        WriteVarInt(writer, (ulong)id);
        WriteVarInt(writer, (ulong)value.Length);
        writer.Write(value);
    }

    private static void WriteVarIntParameter(BinaryWriter writer, ParameterId id, ulong value)
    {
        WriteVarInt(writer, (ulong)id);
        var length = GetVarIntLength(value);
        WriteVarInt(writer, (ulong)length);
        WriteVarIntDirect(writer, value, length);
    }

    private static void WriteVarInt(BinaryWriter writer, ulong value)
    {
        if (value < 0x40)
        {
            writer.Write((byte)value);
        }
        else if (value < 0x4000)
        {
            writer.Write((byte)(0x40 | (value >> 8)));
            writer.Write((byte)value);
        }
        else if (value < 0x40000000)
        {
            writer.Write((byte)(0x80 | (value >> 24)));
            writer.Write((byte)(value >> 16));
            writer.Write((byte)(value >> 8));
            writer.Write((byte)value);
        }
        else
        {
            writer.Write((byte)(0xc0 | (value >> 56)));
            writer.Write((byte)(value >> 48));
            writer.Write((byte)(value >> 40));
            writer.Write((byte)(value >> 32));
            writer.Write((byte)(value >> 24));
            writer.Write((byte)(value >> 16));
            writer.Write((byte)(value >> 8));
            writer.Write((byte)value);
        }
    }

    private static void WriteVarIntDirect(BinaryWriter writer, ulong value, int length)
    {
        switch (length)
        {
            case 1:
                writer.Write((byte)value);
                break;
            case 2:
                writer.Write((byte)(0x40 | (value >> 8)));
                writer.Write((byte)value);
                break;
            case 4:
                writer.Write((byte)(0x80 | (value >> 24)));
                writer.Write((byte)(value >> 16));
                writer.Write((byte)(value >> 8));
                writer.Write((byte)value);
                break;
            case 8:
                writer.Write((byte)(0xc0 | (value >> 56)));
                writer.Write((byte)(value >> 48));
                writer.Write((byte)(value >> 40));
                writer.Write((byte)(value >> 32));
                writer.Write((byte)(value >> 24));
                writer.Write((byte)(value >> 16));
                writer.Write((byte)(value >> 8));
                writer.Write((byte)value);
                break;
        }
    }

    private static int GetVarIntLength(ulong value)
    {
        if (value < 0x40) return 1;
        if (value < 0x4000) return 2;
        if (value < 0x40000000) return 4;
        return 8;
    }

    private static (ulong value, int length) ReadVarInt(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
            throw new InvalidOperationException("Insufficient data for varint");

        var firstByte = data[0];
        var lengthBits = (firstByte & 0xc0) >> 6;

        return lengthBits switch
        {
            0 => ((ulong)(firstByte & 0x3f), 1),
            1 => data.Length >= 2 
                ? (((ulong)(firstByte & 0x3f) << 8) | data[1], 2)
                : throw new InvalidOperationException("Insufficient data for 2-byte varint"),
            2 => data.Length >= 4
                ? (((ulong)(firstByte & 0x3f) << 24) | ((ulong)data[1] << 16) | 
                   ((ulong)data[2] << 8) | data[3], 4)
                : throw new InvalidOperationException("Insufficient data for 4-byte varint"),
            _ => data.Length >= 8
                ? (((ulong)(firstByte & 0x3f) << 56) | ((ulong)data[1] << 48) | 
                   ((ulong)data[2] << 40) | ((ulong)data[3] << 32) |
                   ((ulong)data[4] << 24) | ((ulong)data[5] << 16) | 
                   ((ulong)data[6] << 8) | data[7], 8)
                : throw new InvalidOperationException("Insufficient data for 8-byte varint")
        };
    }

    private static ulong ReadVarIntValue(ReadOnlySpan<byte> data)
    {
        var (value, _) = ReadVarInt(data);
        return value;
    }
}