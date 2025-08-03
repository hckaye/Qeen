using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using Qeen.Core.Frame.Frames;

namespace Qeen.Core.Path;

/// <summary>
/// Implements path validation according to RFC 9000 Section 8.2
/// </summary>
public class PathValidator
{
    private readonly ConcurrentDictionary<string, PathInfo> _paths;
    private readonly ConcurrentDictionary<string, byte[]> _pendingChallenges;
    private readonly object _lock = new();
    private PathInfo? _primaryPath;
    
    // RFC 9000 constants
    private const int MaxValidationAttempts = 3;
    private const int ChallengeSize = 8;
    private static readonly TimeSpan ValidationTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan PathIdleTimeout = TimeSpan.FromSeconds(30);
    
    public PathValidator()
    {
        _paths = new ConcurrentDictionary<string, PathInfo>();
        _pendingChallenges = new ConcurrentDictionary<string, byte[]>();
    }
    
    /// <summary>
    /// Gets the primary path
    /// </summary>
    public PathInfo? PrimaryPath
    {
        get { lock (_lock) return _primaryPath; }
    }
    
    /// <summary>
    /// Gets all known paths
    /// </summary>
    public IEnumerable<PathInfo> GetAllPaths()
    {
        return _paths.Values.ToList();
    }
    
    /// <summary>
    /// Initiates path validation for a new or existing path
    /// </summary>
    public PathChallengeFrame? StartPathValidation(IPEndPoint local, IPEndPoint remote)
    {
        var pathInfo = GetOrCreatePath(local, remote);
        
        lock (_lock)
        {
            if (pathInfo.State == PathState.Validated && !pathInfo.NeedsRevalidation(PathIdleTimeout))
            {
                // Path is already validated and doesn't need revalidation
                return null;
            }
            
            if (pathInfo.ValidationAttempts >= MaxValidationAttempts)
            {
                // Too many validation attempts
                pathInfo.State = PathState.Failed;
                return null;
            }
            
            // Generate challenge data
            var challenge = new byte[ChallengeSize];
            RandomNumberGenerator.Fill(challenge);
            
            pathInfo.ValidationChallenge = challenge;
            pathInfo.State = PathState.Validating;
            pathInfo.ValidationAttempts++;
            
            var pathId = pathInfo.GetPathId();
            _pendingChallenges[pathId] = challenge;
            
            return new PathChallengeFrame(challenge);
        }
    }
    
    /// <summary>
    /// Processes a PATH_CHALLENGE frame and generates a PATH_RESPONSE
    /// </summary>
    public PathResponseFrame ProcessPathChallenge(PathChallengeFrame challenge, IPEndPoint local, IPEndPoint remote)
    {
        var pathInfo = GetOrCreatePath(local, remote);
        
        lock (_lock)
        {
            pathInfo.LastUsed = DateTime.UtcNow;
            pathInfo.BytesReceived += 16; // Approximate frame size
        }
        
        // Echo the challenge data in the response
        return new PathResponseFrame(challenge.Data);
    }
    
    /// <summary>
    /// Processes a PATH_RESPONSE frame to complete path validation
    /// </summary>
    public bool ProcessPathResponse(PathResponseFrame response, IPEndPoint local, IPEndPoint remote)
    {
        var pathInfo = GetOrCreatePath(local, remote);
        var pathId = pathInfo.GetPathId();
        
        lock (_lock)
        {
            // Check if we have a pending challenge for this path
            if (!_pendingChallenges.TryRemove(pathId, out var expectedChallenge))
            {
                // No pending challenge for this path
                return false;
            }
            
            // Verify the response matches our challenge
            if (!response.Data.Span.SequenceEqual(expectedChallenge))
            {
                // Response doesn't match challenge
                pathInfo.State = PathState.Failed;
                return false;
            }
            
            // Path validation successful
            pathInfo.State = PathState.Validated;
            pathInfo.LastValidated = DateTime.UtcNow;
            pathInfo.LastUsed = DateTime.UtcNow;
            pathInfo.ValidationAttempts = 0;
            
            // Set as primary path if we don't have one
            if (_primaryPath == null || _primaryPath.State != PathState.Validated)
            {
                _primaryPath = pathInfo;
                pathInfo.IsPrimary = true;
            }
            
            return true;
        }
    }
    
    /// <summary>
    /// Marks a path as abandoned
    /// </summary>
    public void AbandonPath(IPEndPoint local, IPEndPoint remote)
    {
        var pathId = $"{local}:{remote}";
        
        if (_paths.TryGetValue(pathId, out var pathInfo))
        {
            lock (_lock)
            {
                pathInfo.State = PathState.Abandoned;
                
                if (_primaryPath == pathInfo)
                {
                    // Need to select a new primary path
                    _primaryPath = _paths.Values
                        .Where(p => p.State == PathState.Validated && p != pathInfo)
                        .OrderByDescending(p => p.LastUsed)
                        .FirstOrDefault();
                    
                    if (_primaryPath != null)
                    {
                        _primaryPath.IsPrimary = true;
                    }
                }
            }
        }
    }
    
    /// <summary>
    /// Updates path metrics
    /// </summary>
    public void UpdatePathMetrics(IPEndPoint local, IPEndPoint remote, TimeSpan rtt, int mtu)
    {
        var pathInfo = GetOrCreatePath(local, remote);
        
        lock (_lock)
        {
            pathInfo.Rtt = rtt;
            pathInfo.Mtu = Math.Max(pathInfo.Mtu, mtu);
            pathInfo.LastUsed = DateTime.UtcNow;
        }
    }
    
    /// <summary>
    /// Records bytes sent on a path
    /// </summary>
    public void RecordBytesSent(IPEndPoint local, IPEndPoint remote, ulong bytes)
    {
        var pathInfo = GetOrCreatePath(local, remote);
        
        lock (_lock)
        {
            pathInfo.BytesSent += bytes;
            pathInfo.LastUsed = DateTime.UtcNow;
        }
    }
    
    /// <summary>
    /// Records bytes received on a path
    /// </summary>
    public void RecordBytesReceived(IPEndPoint local, IPEndPoint remote, ulong bytes)
    {
        var pathInfo = GetOrCreatePath(local, remote);
        
        lock (_lock)
        {
            pathInfo.BytesReceived += bytes;
            pathInfo.LastUsed = DateTime.UtcNow;
        }
    }
    
    /// <summary>
    /// Migrates to a new path
    /// </summary>
    public bool MigratePath(IPEndPoint newLocal, IPEndPoint newRemote)
    {
        var newPath = GetOrCreatePath(newLocal, newRemote);
        
        lock (_lock)
        {
            if (newPath.State != PathState.Validated)
            {
                // Can't migrate to non-validated path
                return false;
            }
            
            // Mark old primary path as non-primary
            if (_primaryPath != null)
            {
                _primaryPath.IsPrimary = false;
            }
            
            // Set new primary path
            _primaryPath = newPath;
            newPath.IsPrimary = true;
            
            return true;
        }
    }
    
    /// <summary>
    /// Checks for paths that need revalidation or cleanup
    /// </summary>
    public void MaintainPaths()
    {
        var now = DateTime.UtcNow;
        var pathsToRemove = new List<string>();
        
        lock (_lock)
        {
            foreach (var kvp in _paths)
            {
                var path = kvp.Value;
                
                // Remove abandoned paths after idle timeout
                if (path.State == PathState.Abandoned && 
                    now - path.LastUsed > PathIdleTimeout)
                {
                    pathsToRemove.Add(kvp.Key);
                    continue;
                }
                
                // Mark paths as needing revalidation if idle
                if (path.State == PathState.Validated &&
                    now - path.LastUsed > PathIdleTimeout)
                {
                    path.State = PathState.Unknown;
                }
                
                // Fail paths that have been validating for too long
                if (path.State == PathState.Validating &&
                    now - path.LastUsed > ValidationTimeout)
                {
                    path.State = PathState.Failed;
                    _pendingChallenges.TryRemove(kvp.Key, out _);
                }
            }
        }
        
        // Remove abandoned paths
        foreach (var pathId in pathsToRemove)
        {
            _paths.TryRemove(pathId, out _);
        }
    }
    
    private PathInfo GetOrCreatePath(IPEndPoint local, IPEndPoint remote)
    {
        var pathId = $"{local}:{remote}";
        return _paths.GetOrAdd(pathId, _ => new PathInfo(local, remote));
    }
}