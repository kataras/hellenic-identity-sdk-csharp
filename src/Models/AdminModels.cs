using System.Text.Json.Serialization;

namespace Hellenic.Identity.SDK.Models;

/// <summary>
/// Admin delete user request (mirrors Go AdminDeleteUserRequest)
/// </summary>
public class AdminDeleteUserRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty; // ID or Username

    [JsonPropertyName("soft")]
    public bool? Soft { get; set; } // Soft delete flag
}

/// <summary>
/// Admin restore user request (mirrors Go AdminRestoreUserRequest)
/// </summary>
public class AdminRestoreUserRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty; // ID or Username
}

/// <summary>
/// Admin reset user password request (mirrors Go AdminResetUserPasswordRequest)
/// </summary>
public class AdminResetUserPasswordRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty; // ID or Username

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty; // New plain password
}

/// <summary>
/// User attribute/schema definition (mirrors Go identity.UserAttribute)
/// </summary>
public class UserAttribute
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty;

    [JsonPropertyName("required")]
    public bool Required { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("default_value")]
    public object? DefaultValue { get; set; }
}

/// <summary>
/// User filter options for listing users (mirrors Go entity.UserFilterOptions)
/// </summary>
public class UserFilterOptions
{
    [JsonPropertyName("username")]
    public string? Username { get; set; }

    [JsonPropertyName("role")]
    public int? Role { get; set; }

    [JsonPropertyName("deleted")]
    public bool? Deleted { get; set; }

    [JsonPropertyName("created_at_from")]
    public DateTime? CreatedAtFrom { get; set; }

    [JsonPropertyName("created_at_to")]
    public DateTime? CreatedAtTo { get; set; }
}

/// <summary>
/// Pagination options (mirrors Go rest.PageOptions)
/// </summary>
public class PageOptions
{
    [JsonPropertyName("page")]
    public int Page { get; set; } = 1;

    [JsonPropertyName("limit")]
    public int Limit { get; set; } = 20;

    [JsonPropertyName("sort")]
    public string? Sort { get; set; }

    [JsonPropertyName("order")]
    public string Order { get; set; } = "desc";
}

/// <summary>
/// Paginated response (mirrors Go rest.Page[T])
/// </summary>
public class PagedResponse<T>
{
    [JsonPropertyName("data")]
    public List<T> Data { get; set; } = new();

    [JsonPropertyName("total")]
    public long Total { get; set; }

    [JsonPropertyName("page")]
    public int Page { get; set; }

    [JsonPropertyName("limit")]
    public int Limit { get; set; }

    [JsonPropertyName("pages")]
    public int Pages { get; set; }
}

/// <summary>
/// Count response (mirrors Go rest.CountResponse[int64])
/// </summary>
public class CountResponse<T>
{
    [JsonPropertyName("count")]
    public T Count { get; set; } = default(T)!;
}

/// <summary>
/// Internal password reset token response
/// </summary>
public class PasswordResetTokenResponse
{
    [JsonPropertyName("token")]
    public string Token { get; set; } = string.Empty;
}

/// <summary>
/// Internal password reset confirmation request
/// </summary>
public class PasswordResetConfirmRequest
{
    [JsonPropertyName("token")]
    public string Token { get; set; } = string.Empty;

    [JsonPropertyName("new_password")]
    public string NewPassword { get; set; } = string.Empty;
}

/// <summary>
/// Internal request password reset request
/// </summary>
public class RequestPasswordResetRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty;
}