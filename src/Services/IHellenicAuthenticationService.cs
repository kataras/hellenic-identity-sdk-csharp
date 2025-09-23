using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace Hellenic.Identity.SDK.Services;

/// <summary>
/// Authentication service interface for Hellenic Identity with EdDSA support
/// Non-generic interface for easier DI registration and usage
/// </summary>
public interface IHellenicAuthenticationService
{
    /// <summary>
    /// Authenticate a Bearer token and return authentication result
    /// </summary>
    /// <param name="authorizationHeader">The Authorization header value</param>
    /// <returns>Authentication result with claims if successful</returns>
    Task<AuthenticateResult> AuthenticateAsync(string? authorizationHeader);

    /// <summary>
    /// Validate a JWT token
    /// </summary>
    /// <param name="token">JWT token to validate</param>
    /// <returns>True if token is valid</returns>
    Task<bool> ValidateTokenAsync(string token);

    /// <summary>
    /// Extract claims from a validated JWT token
    /// </summary>
    /// <param name="token">JWT token to extract claims from</param>
    /// <returns>List of claims</returns>
    Task<List<Claim>> ExtractClaimsAsync(string token);
}