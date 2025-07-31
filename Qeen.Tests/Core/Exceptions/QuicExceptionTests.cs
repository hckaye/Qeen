using System;
using Xunit;
using Qeen.Core.Exceptions;
using Qeen.Core.Frame;

namespace Qeen.Tests.Core.Exceptions;

public class QuicExceptionTests
{
    [Fact]
    public void QuicException_CanBeCreatedWithDefaultConstructor()
    {
        var ex = new QuicException();
        
        Assert.NotNull(ex);
        Assert.NotNull(ex.Message); // Base Exception class provides a default message
    }

    [Fact]
    public void QuicException_CanBeCreatedWithMessage()
    {
        const string message = "Test exception message";
        var ex = new QuicException(message);
        
        Assert.Equal(message, ex.Message);
    }

    [Fact]
    public void QuicException_CanBeCreatedWithMessageAndInnerException()
    {
        const string message = "Test exception message";
        var inner = new InvalidOperationException("Inner exception");
        var ex = new QuicException(message, inner);
        
        Assert.Equal(message, ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void QuicConnectionException_StoresErrorCode()
    {
        var ex = new QuicConnectionException(TransportErrorCode.ProtocolViolation);
        
        Assert.Equal(TransportErrorCode.ProtocolViolation, ex.ErrorCode);
        Assert.Contains("QUIC connection error: ProtocolViolation", ex.Message);
        Assert.Null(ex.ReasonPhrase);
        Assert.Null(ex.FrameType);
    }

    [Fact]
    public void QuicConnectionException_StoresAllProperties()
    {
        const string reason = "Invalid frame sequence";
        var ex = new QuicConnectionException(
            TransportErrorCode.FrameEncodingError, 
            reason, 
            FrameType.Crypto);
        
        Assert.Equal(TransportErrorCode.FrameEncodingError, ex.ErrorCode);
        Assert.Equal(reason, ex.ReasonPhrase);
        Assert.Equal(FrameType.Crypto, ex.FrameType);
        Assert.Contains("QUIC connection error: FrameEncodingError - Invalid frame sequence", ex.Message);
    }

    [Fact]
    public void QuicConnectionException_WithInnerException()
    {
        var inner = new ArgumentException("Inner error");
        var ex = new QuicConnectionException(
            TransportErrorCode.InternalError,
            "Processing failed",
            inner);
        
        Assert.Equal(TransportErrorCode.InternalError, ex.ErrorCode);
        Assert.Equal("Processing failed", ex.ReasonPhrase);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void QuicStreamException_StoresStreamIdAndErrorCode()
    {
        const long streamId = 42;
        const long errorCode = 0x52;
        const string message = "Stream was reset";
        
        var ex = new QuicStreamException(streamId, errorCode, message);
        
        Assert.Equal(streamId, ex.StreamId);
        Assert.Equal(errorCode, ex.ErrorCode);
        Assert.Contains($"Stream {streamId} error ({errorCode}): {message}", ex.Message);
    }

    [Fact]
    public void QuicProtocolViolationException_StoresErrorCode()
    {
        const string message = "Received frame in wrong state";
        var ex = new QuicProtocolViolationException(TransportErrorCode.ProtocolViolation, message);
        
        Assert.Equal(TransportErrorCode.ProtocolViolation, ex.ErrorCode);
        Assert.Contains($"QUIC protocol violation (ProtocolViolation): {message}", ex.Message);
    }

    [Theory]
    [InlineData(TransportErrorCode.NoError, 0x00)]
    [InlineData(TransportErrorCode.InternalError, 0x01)]
    [InlineData(TransportErrorCode.ConnectionRefused, 0x02)]
    [InlineData(TransportErrorCode.FlowControlError, 0x03)]
    [InlineData(TransportErrorCode.StreamLimitError, 0x04)]
    [InlineData(TransportErrorCode.StreamStateError, 0x05)]
    [InlineData(TransportErrorCode.FinalSizeError, 0x06)]
    [InlineData(TransportErrorCode.FrameEncodingError, 0x07)]
    [InlineData(TransportErrorCode.TransportParameterError, 0x08)]
    [InlineData(TransportErrorCode.ConnectionIdLimitError, 0x09)]
    [InlineData(TransportErrorCode.ProtocolViolation, 0x0a)]
    [InlineData(TransportErrorCode.InvalidToken, 0x0b)]
    [InlineData(TransportErrorCode.ApplicationError, 0x0c)]
    [InlineData(TransportErrorCode.CryptoBufferExceeded, 0x0d)]
    [InlineData(TransportErrorCode.KeyUpdateError, 0x0e)]
    [InlineData(TransportErrorCode.AeadLimitReached, 0x0f)]
    [InlineData(TransportErrorCode.NoViablePath, 0x10)]
    [InlineData(TransportErrorCode.CryptoError, 0x100)]
    public void TransportErrorCode_HasCorrectValues(TransportErrorCode code, ulong expectedValue)
    {
        Assert.Equal(expectedValue, (ulong)code);
    }
}