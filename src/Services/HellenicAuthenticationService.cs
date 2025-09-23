using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;

namespace Hellenic.Identity.SDK.Services;

/// <summary>
/// Service for handling Hellenic Identity authentication with EdDSA support
/// </summary>
public class HellenicAuthenticationService<TUser> : IHellenicAuthenticationService where TUser : class
{
    private readonly IIdentityClient<TUser> _identityClient;
    private readonly ILogger<HellenicAuthenticationService<TUser>> _logger;

    public HellenicAuthenticationService(
        IIdentityClient<TUser> identityClient,
        ILogger<HellenicAuthenticationService<TUser>> logger)
    {
        _identityClient = identityClient;
        _logger = logger;
    }

    public async Task<AuthenticateResult> AuthenticateAsync(string? authorizationHeader)
    {
        try
        {
            // Check if Authorization header exists
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }
    
            // Extract Bearer token
            if (!authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.Fail("Invalid authorization header format"); // No logging for performance
            }
    
            var token = authorizationHeader.Substring("Bearer ".Length);
    
            // Validate token
            var isValid = await ValidateTokenAsync(token);
            if (!isValid)
            {
                return AuthenticateResult.Fail("Token validation failed"); // No logging for performance
            }
    
            // Extract claims
            var claims = await ExtractClaimsAsync(token);
            if (claims == null || !claims.Any())
            {
                return AuthenticateResult.Fail("Failed to extract token claims"); // No logging for performance
            }
    
            // Create identity and principal
            var identity = new ClaimsIdentity(claims, "Hellenic");
            var principal = new ClaimsPrincipal(identity);
    
            // No logging for successful authentication to improve performance
    
            return AuthenticateResult.Success(new AuthenticationTicket(principal, "Hellenic"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authentication failed with exception");
            return AuthenticateResult.Fail($"Authentication failed: {ex.Message}");
        }
    }

    public async Task<bool> ValidateTokenAsync(string token)
    {
        try
        {
            return await _identityClient.VerifyTokenAsync(token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token validation failed");
            return false;
        }
    }

    public Task<List<Claim>> ExtractClaimsAsync(string token)
    {
        try
        {
            // Direct JWT claims extraction - much faster than Dictionary approach
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            
            var claims = new List<Claim>();
            
            // Map JWT claims directly to ASP.NET Core claims - no JsonElement complexity!
            foreach (var jwtClaim in jwtToken.Claims)
            {
                var claimType = MapClaimType(jwtClaim.Type);
                
                // Handle scopes as multiple claims (JWT standard approach)
                if (jwtClaim.Type == "scopes" && !string.IsNullOrEmpty(jwtClaim.Value))
                {
                    // Split space-separated scopes into individual claims
                    var scopes = jwtClaim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var scope in scopes)
                    {
                        claims.Add(new Claim("scopes", scope));
                    }
                }
                else
                {
                    claims.Add(new Claim(claimType, jwtClaim.Value));
                }
            }

            // No logging for successful claim extraction to improve performance
            return Task.FromResult(claims);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to extract claims from token");
            return Task.FromResult(new List<Claim>());
        }
    }

    // Alternative: Extract claims directly from TUser object (even faster for typed scenarios)
    public Task<List<Claim>> ExtractClaimsFromUserAsync(string token)
    {
        try
        {
            // Get strongly typed user data - no Dictionary overhead!
            var userData = _identityClient.IntrospectToken<TUser>(token);
            if (userData == null)
            {
                return Task.FromResult(new List<Claim>()); // No logging for performance
            }

            var claims = new List<Claim>();
            
            // Use reflection to convert user properties to claims
            var properties = typeof(TUser).GetProperties();
            foreach (var property in properties)
            {
                var value = property.GetValue(userData);
                if (value != null)
                {
                    var claimType = MapClaimType(property.Name.ToLowerInvariant());
                    claims.Add(new Claim(claimType, value.ToString() ?? ""));
                }
            }

            // No logging for successful claim extraction to improve performance
            return Task.FromResult(claims);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to extract claims from user object");
            return Task.FromResult(new List<Claim>());
        }
    }

    private static string MapClaimType(string tokenClaimType)
    {
        return tokenClaimType switch
        {
            "id" => ClaimTypes.NameIdentifier,
            "username" => ClaimTypes.Name,
            "firstname" => ClaimTypes.GivenName,
            "lastname" => ClaimTypes.Surname,
            "phone" => ClaimTypes.MobilePhone,
            "role" => ClaimTypes.Role,
            "email" => ClaimTypes.Email,
            "client_id" => "client_id",
            "client_name" => "client_name",
            "scopes" => "scopes",
            "iat" => "iat",
            "exp" => "exp",
            "jti" => "jti",
            "aud" => "aud",
            _ => tokenClaimType
        };
    }

}