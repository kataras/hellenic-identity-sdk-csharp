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
/// Filter term for querying users (mirrors Go entity.FilterTerm)
/// </summary>
public class FilterTerm
{
    [JsonPropertyName("field")]
    public string Field { get; set; } = string.Empty; // e.g. "username", "email", "attrs->>'phone'"

    [JsonPropertyName("operator")]
    public string Operator { get; set; } = "="; // e.g. "=", "ILIKE", "@>", etc.

    [JsonPropertyName("value")]
    public object? Value { get; set; } // e.g. "makis", "%gmail%", JSON...

    [JsonPropertyName("logic")]
    public string Logic { get; set; } = "AND"; // e.g. "AND", "OR"
}

/// <summary>
/// User filter options for listing users (mirrors Go entity.UserFilterOptions)
/// </summary>
public class UserFilterOptions
{
    [JsonPropertyName("sort")]
    public string? Sort { get; set; } // Optional. Sort expression.

    [JsonPropertyName("sort_descending")]
    public bool SortDescending { get; set; } // Optional. Sort in descending order.

    [JsonPropertyName("terms")]
    public List<FilterTerm>? Terms { get; set; } // Filter terms

    [JsonPropertyName("include_deleted")]
    public bool IncludeDeleted { get; set; } // Optional. Include soft-deleted users.

    [JsonPropertyName("include_ids")]
    public List<string>? IncludeIds { get; set; } // Optional. List of user IDs to include.
}

/// <summary>
/// Pagination options (mirrors Go rest.PageOptions)
/// </summary>
public class PageOptions
{
    [JsonPropertyName("page")]
    public int Page { get; set; } = 1; // Current page number

    [JsonPropertyName("size")]
    public int Size { get; set; } = 100; // Elements to get (called Size in Go, not Limit)

    [JsonPropertyName("details")]
    public bool Details { get; set; } // Return nested objects or not
}

/// <summary>
/// Paginated response (mirrors Go rest.Page[T])
/// </summary>
public class PagedResponse<T>
{
    [JsonPropertyName("current_page")]
    public int CurrentPage { get; set; } // The current page

    [JsonPropertyName("page_size")]
    public int PageSize { get; set; } // The total amount of entities returned

    [JsonPropertyName("total_pages")]
    public int TotalPages { get; set; } // Total number of pages based on page, size and total count

    [JsonPropertyName("total_items")]
    public long TotalItems { get; set; } // Total number of rows

    [JsonPropertyName("has_next_page")]
    public bool HasNextPage { get; set; } // True if more data can be fetched

    [JsonPropertyName("filter")]
    public object? Filter { get; set; } // Any filter data

    [JsonPropertyName("items")]
    public List<T> Items { get; set; } = new(); // Items array
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

/// <summary>
/// Partial update specification for updating users (mirrors Go entity.PartialUpdateSpec)
/// </summary>
public class PartialUpdateSpec
{
    [JsonPropertyName("id")]
    public string? Id { get; set; } // User ID for identification

    [JsonPropertyName("username")]
    public string? Username { get; set; } // Username for identification if ID is not provided

    [JsonPropertyName("set")]
    public Dictionary<string, object>? Set { get; set; } // Paths to set (e.g., {"profile.name": "John", "profile": {"age": 30}})

    [JsonPropertyName("remove")]
    public List<string>? Remove { get; set; } // JSON paths to remove (e.g., ["profile.avatar", "settings.notifications"])
}

/// <summary>
/// Bulk delete users request (mirrors Go BulkUserDeleteRequest)
/// </summary>
public class BulkUserDeleteRequest
{
    [JsonPropertyName("ids")]
    public List<string> Ids { get; set; } = new(); // IDs of the users to delete

    [JsonPropertyName("soft")]
    public bool? Soft { get; set; } // When true, users are marked as deleted but not actually removed
}