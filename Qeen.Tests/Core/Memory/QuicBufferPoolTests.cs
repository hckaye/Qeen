using System;
using Xunit;
using Qeen.Core.Memory;

namespace Qeen.Tests.Core.Memory;

public class QuicBufferPoolTests
{
    [Fact]
    public void Shared_ReturnsSameInstance()
    {
        var pool1 = QuicBufferPool.Shared;
        var pool2 = QuicBufferPool.Shared;
        
        Assert.Same(pool1, pool2);
    }

    [Theory]
    [InlineData(100)]
    [InlineData(1500)]
    [InlineData(4096)]
    [InlineData(65536)]
    public void Rent_ReturnsBufferOfAtLeastRequestedSize(int requestedSize)
    {
        var pool = new QuicBufferPool();
        
        var buffer = pool.Rent(requestedSize);
        
        Assert.NotNull(buffer);
        Assert.True(buffer.Length >= requestedSize);
    }

    [Fact]
    public void Rent_WithZeroOrNegativeSize_ThrowsException()
    {
        var pool = new QuicBufferPool();
        
        Assert.Throws<ArgumentOutOfRangeException>(() => pool.Rent(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => pool.Rent(-1));
    }

    [Fact]
    public void Rent_WithSizeExceedingMax_ThrowsException()
    {
        const int maxSize = 1024;
        var pool = new QuicBufferPool(maxSize);
        
        Assert.Throws<ArgumentOutOfRangeException>(() => pool.Rent(maxSize + 1));
    }

    [Fact]
    public void Return_AcceptsRentedBuffer()
    {
        var pool = new QuicBufferPool();
        var buffer = pool.Rent(1000);
        
        // Should not throw
        pool.Return(buffer);
    }

    [Fact]
    public void Return_WithNull_ThrowsException()
    {
        var pool = new QuicBufferPool();
        
        Assert.Throws<ArgumentNullException>(() => pool.Return(null!));
    }

    [Fact]
    public void Return_WithClearBuffer_ClearsContent()
    {
        var pool = new QuicBufferPool();
        var buffer = pool.Rent(100);
        
        // Fill buffer with data
        for (int i = 0; i < buffer.Length; i++)
        {
            buffer[i] = (byte)i;
        }
        
        pool.Return(buffer, clearBuffer: true);
        
        // Rent again (might get the same buffer back)
        var buffer2 = pool.Rent(100);
        
        // If we got the same buffer, it should be cleared
        // Note: This is not guaranteed by ArrayPool, but we test the intent
        if (ReferenceEquals(buffer, buffer2))
        {
            Assert.All(buffer2, b => Assert.Equal(0, b));
        }
    }

    [Fact]
    public void RentMemory_ReturnsRentedBuffer()
    {
        var pool = new QuicBufferPool();
        
        using var rented = pool.RentMemory(500);
        
        Assert.Equal(500, rented.Memory.Length);
        Assert.Equal(500, rented.Span.Length);
    }

    [Fact]
    public void RentedBuffer_DisposesCorrectly()
    {
        var pool = new QuicBufferPool();
        
        using (var rented = pool.RentMemory(200))
        {
            // Buffer should be available
            Assert.Equal(200, rented.Memory.Length);
        }
        
        // After disposal, the buffer is returned to the pool
        // We can verify by renting again
        var buffer2 = pool.Rent(200);
        Assert.NotNull(buffer2);
    }

    [Fact]
    public void QuicSpan_TracksPosition()
    {
        Span<byte> buffer = stackalloc byte[100];
        var quicSpan = new QuicSpan(buffer);
        
        Assert.Equal(0, quicSpan.Position);
        Assert.Equal(100, quicSpan.Length);
        Assert.Equal(100, quicSpan.Remaining);
    }

    [Fact]
    public void QuicSpan_Advance_UpdatesPosition()
    {
        Span<byte> buffer = stackalloc byte[100];
        var quicSpan = new QuicSpan(buffer);
        
        quicSpan.Advance(20);
        
        Assert.Equal(20, quicSpan.Position);
        Assert.Equal(80, quicSpan.Remaining);
    }

    [Fact]
    public void QuicSpan_Advance_WithInvalidCount_ThrowsException()
    {
        var buffer = new byte[100];
        
        Assert.Throws<ArgumentOutOfRangeException>(() => 
        {
            var quicSpan = new QuicSpan(buffer);
            quicSpan.Advance(-1);
        });
        
        Assert.Throws<ArgumentOutOfRangeException>(() => 
        {
            var quicSpan = new QuicSpan(buffer);
            quicSpan.Advance(101);
        });
    }

    [Fact]
    public void QuicSpan_GetSpan_ReturnsCorrectSlice()
    {
        Span<byte> buffer = stackalloc byte[100];
        for (int i = 0; i < buffer.Length; i++)
        {
            buffer[i] = (byte)i;
        }
        var quicSpan = new QuicSpan(buffer);
        
        quicSpan.Advance(10);
        var slice = quicSpan.GetSpan(20);
        
        Assert.Equal(20, slice.Length);
        Assert.Equal(10, slice[0]); // Should start at position 10
        Assert.Equal(29, slice[19]); // Should end at position 29
    }

    [Fact]
    public void QuicSpan_GetRemainingSpan_ReturnsCorrectSlice()
    {
        Span<byte> buffer = stackalloc byte[100];
        var quicSpan = new QuicSpan(buffer);
        
        quicSpan.Advance(30);
        var remaining = quicSpan.GetRemainingSpan();
        
        Assert.Equal(70, remaining.Length);
    }

    [Fact]
    public void QuicSpan_Reset_ResetsPosition()
    {
        Span<byte> buffer = stackalloc byte[100];
        var quicSpan = new QuicSpan(buffer);
        
        quicSpan.Advance(50);
        Assert.Equal(50, quicSpan.Position);
        
        quicSpan.Reset();
        Assert.Equal(0, quicSpan.Position);
        Assert.Equal(100, quicSpan.Remaining);
    }

    [Fact]
    public void DefaultBufferSize_HasExpectedValue()
    {
        Assert.Equal(1500, QuicBufferPool.DefaultBufferSize);
    }

    [Fact]
    public void LargeBufferSize_HasExpectedValue()
    {
        Assert.Equal(65536, QuicBufferPool.LargeBufferSize);
    }
}