using System.Net;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Path;
using Xunit;

namespace Qeen.Tests.Core.Path;

public class PathValidatorTests
{
    private static IPEndPoint CreateEndPoint(int port) => new(IPAddress.Loopback, port);
    
    [Fact]
    public void PathValidator_StartPathValidation_GeneratesChallenge()
    {
        // Arrange
        var validator = new PathValidator();
        var local = CreateEndPoint(1234);
        var remote = CreateEndPoint(5678);
        
        // Act
        var challenge = validator.StartPathValidation(local, remote);
        
        // Assert
        Assert.NotNull(challenge);
        Assert.Equal(8, challenge.Value.Data.Length);
        
        var paths = validator.GetAllPaths();
        Assert.Single(paths);
        Assert.Equal(PathState.Validating, paths.First().State);
    }
    
    [Fact]
    public void PathValidator_ProcessPathChallenge_GeneratesResponse()
    {
        // Arrange
        var validator = new PathValidator();
        var local = CreateEndPoint(1234);
        var remote = CreateEndPoint(5678);
        var challengeData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var challenge = new PathChallengeFrame(challengeData);
        
        // Act
        var response = validator.ProcessPathChallenge(challenge, local, remote);
        
        // Assert
        Assert.True(response.Data.Span.SequenceEqual(challengeData));
    }
    
    [Fact]
    public void PathValidator_ProcessPathResponse_ValidatesPath()
    {
        // Arrange
        var validator = new PathValidator();
        var local = CreateEndPoint(1234);
        var remote = CreateEndPoint(5678);
        
        // Start validation
        var challenge = validator.StartPathValidation(local, remote);
        Assert.NotNull(challenge);
        
        // Create matching response
        var response = new PathResponseFrame(challenge.Value.Data);
        
        // Act
        var result = validator.ProcessPathResponse(response, local, remote);
        
        // Assert
        Assert.True(result);
        
        var paths = validator.GetAllPaths();
        Assert.Single(paths);
        var path = paths.First();
        Assert.Equal(PathState.Validated, path.State);
        Assert.True(path.IsPrimary);
    }
    
    [Fact]
    public void PathValidator_ProcessPathResponse_FailsWithWrongChallenge()
    {
        // Arrange
        var validator = new PathValidator();
        var local = CreateEndPoint(1234);
        var remote = CreateEndPoint(5678);
        
        // Start validation
        var challenge = validator.StartPathValidation(local, remote);
        Assert.NotNull(challenge);
        
        // Create wrong response
        var wrongData = new byte[] { 9, 9, 9, 9, 9, 9, 9, 9 };
        var response = new PathResponseFrame(wrongData);
        
        // Act
        var result = validator.ProcessPathResponse(response, local, remote);
        
        // Assert
        Assert.False(result);
        
        var paths = validator.GetAllPaths();
        Assert.Single(paths);
        Assert.Equal(PathState.Failed, paths.First().State);
    }
    
    [Fact]
    public void PathValidator_AbandonPath_MarksAsAbandoned()
    {
        // Arrange
        var validator = new PathValidator();
        var local = CreateEndPoint(1234);
        var remote = CreateEndPoint(5678);
        
        // Validate path first
        var challenge = validator.StartPathValidation(local, remote);
        Assert.NotNull(challenge);
        var response = new PathResponseFrame(challenge.Value.Data);
        validator.ProcessPathResponse(response, local, remote);
        
        // Act
        validator.AbandonPath(local, remote);
        
        // Assert
        var paths = validator.GetAllPaths();
        Assert.Single(paths);
        Assert.Equal(PathState.Abandoned, paths.First().State);
        Assert.Null(validator.PrimaryPath);
    }
    
    [Fact]
    public void PathValidator_MigratePath_ChangesPrimaryPath()
    {
        // Arrange
        var validator = new PathValidator();
        var local1 = CreateEndPoint(1234);
        var remote1 = CreateEndPoint(5678);
        var local2 = CreateEndPoint(2345);
        var remote2 = CreateEndPoint(6789);
        
        // Validate first path
        var challenge1 = validator.StartPathValidation(local1, remote1);
        Assert.NotNull(challenge1);
        validator.ProcessPathResponse(new PathResponseFrame(challenge1.Value.Data), local1, remote1);
        
        // Validate second path
        var challenge2 = validator.StartPathValidation(local2, remote2);
        Assert.NotNull(challenge2);
        validator.ProcessPathResponse(new PathResponseFrame(challenge2.Value.Data), local2, remote2);
        
        // Act
        var result = validator.MigratePath(local2, remote2);
        
        // Assert
        Assert.True(result);
        Assert.NotNull(validator.PrimaryPath);
        Assert.Equal($"{local2}:{remote2}", validator.PrimaryPath.GetPathId());
        Assert.True(validator.PrimaryPath.IsPrimary);
        
        // Check old path is not primary
        var paths = validator.GetAllPaths();
        var oldPath = paths.First(p => p.GetPathId() == $"{local1}:{remote1}");
        Assert.False(oldPath.IsPrimary);
    }
    
    [Fact]
    public void PathValidator_UpdatePathMetrics_UpdatesRttAndMtu()
    {
        // Arrange
        var validator = new PathValidator();
        var local = CreateEndPoint(1234);
        var remote = CreateEndPoint(5678);
        var rtt = TimeSpan.FromMilliseconds(25);
        var mtu = 1500;
        
        // Act
        validator.UpdatePathMetrics(local, remote, rtt, mtu);
        
        // Assert
        var paths = validator.GetAllPaths();
        Assert.Single(paths);
        var path = paths.First();
        Assert.Equal(rtt, path.Rtt);
        Assert.Equal(mtu, path.Mtu);
    }
    
    [Fact]
    public void PathValidator_RecordBytes_UpdatesCounters()
    {
        // Arrange
        var validator = new PathValidator();
        var local = CreateEndPoint(1234);
        var remote = CreateEndPoint(5678);
        
        // Act
        validator.RecordBytesSent(local, remote, 1000);
        validator.RecordBytesReceived(local, remote, 2000);
        
        // Assert
        var paths = validator.GetAllPaths();
        Assert.Single(paths);
        var path = paths.First();
        Assert.Equal(1000ul, path.BytesSent);
        Assert.Equal(2000ul, path.BytesReceived);
    }
    
    [Fact]
    public void PathInfo_NeedsRevalidation_ChecksTimeout()
    {
        // Arrange
        var local = CreateEndPoint(1234);
        var remote = CreateEndPoint(5678);
        var path = new PathInfo(local, remote)
        {
            State = PathState.Validated,
            LastValidated = DateTime.UtcNow.AddSeconds(-40)
        };
        
        // Act & Assert
        Assert.True(path.NeedsRevalidation(TimeSpan.FromSeconds(30)));
        Assert.False(path.NeedsRevalidation(TimeSpan.FromSeconds(60)));
    }
    
    [Fact]
    public void PathInfo_GetPathId_GeneratesUniqueId()
    {
        // Arrange
        var local = CreateEndPoint(1234);
        var remote = CreateEndPoint(5678);
        var path = new PathInfo(local, remote);
        
        // Act
        var id = path.GetPathId();
        
        // Assert
        Assert.Equal($"{local}:{remote}", id);
    }
}