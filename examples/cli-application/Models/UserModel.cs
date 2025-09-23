using System.Text.Json.Serialization;

namespace Hellenic.Identity.CLI.Example.Models;

/// <summary>
/// Custom user model for demonstration purposes.
/// This shows how the generic IdentitySDK<TUser> can work with any user model.
/// </summary>
public class UserModel
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;
    
    [JsonPropertyName("firstname")]
    public string? FirstName { get; set; }
    
    [JsonPropertyName("lastname")]
    public string? LastName { get; set; }
    
    [JsonPropertyName("phone")]
    public string? Phone { get; set; }
    
    [JsonPropertyName("role")]
    public int? Role { get; set; }

    public override string ToString()
    {
        return $"UserModel(Username: {Username}, FirstName: {FirstName}, LastName: {LastName}, Phone: {Phone}, Role: {Role})";
    }
}