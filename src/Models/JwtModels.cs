using System.Text.Json.Serialization;

namespace Hellenic.Identity.SDK.Models;

/// <summary>
/// JSON Web Key Set (JWKS) model
/// </summary>
public class JwkSet
{
    [JsonPropertyName("keys")]
    public List<JwkKey> Keys { get; set; } = new();
}

/// <summary>
/// JSON Web Key model (renamed to avoid conflicts with Microsoft.IdentityModel.Tokens.JsonWebKey)
/// </summary>
public class JwkKey
{
    [JsonPropertyName("kty")]
    public string KeyType { get; set; } = string.Empty;

    [JsonPropertyName("kid")]
    public string KeyId { get; set; } = string.Empty;

    [JsonPropertyName("use")]
    public string Use { get; set; } = string.Empty;

    [JsonPropertyName("alg")]
    public string Algorithm { get; set; } = string.Empty;

    [JsonPropertyName("crv")]
    public string? Curve { get; set; }

    [JsonPropertyName("x")]
    public string? X { get; set; }

    [JsonPropertyName("y")]
    public string? Y { get; set; }

    [JsonPropertyName("n")]
    public string? N { get; set; }

    [JsonPropertyName("e")]
    public string? E { get; set; }

    [JsonPropertyName("d")]
    public string? D { get; set; }
}

/// <summary>
/// JWT Claims for client tokens (similar to Go SDK's ClientTokenClaims)
/// </summary>
public class ClientTokenClaims
{
    public string ClientID { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public List<string> Scopes { get; set; } = new();
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public DateTime IssuedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}