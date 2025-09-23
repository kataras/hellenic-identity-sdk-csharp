using System.Text.Json.Serialization;

namespace Hellenic.Identity.SDK.Models;

/// <summary>
/// Identity client configuration options (mirrors Go SDK Options)
/// </summary>
public class IdentityClientOptions
{
    public string BaseURL { get; set; } = string.Empty;
    public string ClientToken { get; set; } = string.Empty;
    public string ClientID { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string EncryptionKey { get; set; } = string.Empty;
    public string PasswordStrengthLevel { get; set; } = "medium";
    public string DefaultScope { get; set; } = "user:read";
}

/// <summary>
/// Rate limiting configuration
/// </summary>
public class RateLimit
{
    public int RequestsPerMinute { get; set; } = 60;
}

/// <summary>
/// Application configuration
/// </summary>
public class AppConfiguration
{
    public IdentityClientOptions IdentityClient { get; set; } = new();
    public RateLimit RateLimit { get; set; } = new();
}

/// <summary>
/// OAuth2 token response (mirrors Go oauth2.Token)
/// </summary>
public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;
    
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";
    
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }
    
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
    
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
}