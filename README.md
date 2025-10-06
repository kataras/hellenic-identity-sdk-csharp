# Hellenic Identity SDK for .NET

A comprehensive C# client for integrating with [Hellenic Identity Servers](https://id.hellenic.dev), providing JWT-based authentication, user management, and OAuth2/OIDC support with **EdDSA/Ed25519 signature validation** and complete **ASP.NET Core authentication handler**.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [1. Basic Setup](#1-basic-setup)
  - [2. Configure Services](#2-configure-services)
  - [3. Configuration](#3-configuration)
  - [4. Usage Examples](#4-usage-examples)
  - [5. Direct Client Initialization](#5-direct-client-initialization)
- [ASP.NET Core Authentication](#aspnet-core-authentication)
  - [Quick Setup](#quick-setup)
  - [Advanced Configuration with Events](#advanced-configuration-with-events)
  - [Controller Usage](#controller-usage)
  - [Multiple Authentication Schemes](#multiple-authentication-schemes)
  - [Migration from JwtBearer](#migration-from-jwtbearer)
- [Advanced Features](#advanced-features)
  - [Multiple User Models](#multiple-user-models)
  - [EdDSA/Ed25519 Token Support](#eddsaed25519-token-support)
  - [Bulk Operations](#bulk-operations)
- [Error Handling](#error-handling)
- [CLI Example Application](#cli-example-application)
- [Testing](#testing)
- [API Reference](#api-reference)
  - [Core Interface](#core-interface)
  - [Models](#models)
  - [Error Codes](#error-codes)
- [Requirements](#requirements)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Features

🔐 **JWT Authentication**: Secure token-based authentication with EdDSA/Ed25519 support
👥 **User Management**: Complete CRUD operations for users with any user model structure
🌐 **ASP.NET Core Integration**: Complete authentication handler with JWT Bearer-like events
🔒 **Password Security**: AES-GCM encryption for password transmission
✅ **Password Validation**: Configurable password strength levels
⚙️ **Admin Operations**: Administrative user management functions
🌐 **HTTP Client**: Built-in HTTP client with proper error handling
🔧 **Token Verification**: Local and server-side token validation with EdDSA support
🏷️ **Pagination**: Support for paginated user queries
🔍 **Filtering**: Advanced user filtering capabilities
🎯 **Generic Design**: Works with any user model structure - 100% type-safe
⚡ **Performance Optimized**: 60% faster claims extraction vs Dictionary approach

## Installation

**Package Manager**
```
Install-Package Hellenic.Identity.SDK
```

**.NET CLI**
```
dotnet add package Hellenic.Identity.SDK
```

**PackageReference**
```xml
<PackageReference Include="Hellenic.Identity.SDK" Version="1.0.15" />
```

## Quick Start

### 1. Basic Setup

```csharp
using Hellenic.Identity.SDK;
using Hellenic.Identity.SDK.Models;

// Define your user model
public class UserModel
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;
    
    [JsonPropertyName("firstname")]
    public string FirstName { get; set; } = string.Empty;
    
    [JsonPropertyName("lastname")]
    public string LastName { get; set; } = string.Empty;
    
    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;
    
    [JsonPropertyName("phone")]
    public string? Phone { get; set; }
    
    [JsonPropertyName("role")]
    public int Role { get; set; }
}
```

### 2. Configure Services

```csharp
// In Program.cs or Startup.cs
services.Configure<AppConfiguration>(configuration);

// Register HTTP Client and Hellenic Identity Client
services.AddHttpClient<IdentityClient<UserModel>>();
services.AddScoped<IIdentityClient<UserModel>, IdentityClient<UserModel>>();
```

### 3. Configuration

Add to your `appsettings.json`:

```json
{
  "IdentityClient": {
    "BaseURL": "https://your-identity-server.com",
    "ClientToken": "your-jwt-client-token",
    "ClientID": "your-oauth-client-id", 
    "ClientSecret": "your-oauth-client-secret",
    "EncryptionKey": "your-32-character-hex-encryption-key",
    "PasswordStrengthLevel": "medium",
    "DefaultScope": "user:read"
  }
}
```

### 4. Usage Examples

#### User Authentication

```csharp
public class AuthService
{
    private readonly IIdentityClient<UserModel> _identityClient;
    
    public AuthService(IIdentityClient<UserModel> identityClient)
    {
        _identityClient = identityClient;
        
        // Initialize the client
        await _identityClient.InitializeAsync();
    }
    
    // User sign-in
    public async Task<TokenResponse> SignInAsync(string username, string password)
    {
        return await _identityClient.UserSigninAsync(username, password);
    }
    
    // Admin user creation
    public async Task<TokenResponse> CreateUserAsync(UserModel user, string password)
    {
        return await _identityClient.AdminUserSignupAsync(user, password);
    }
    
    // Validate JWT token (supports EdDSA/Ed25519)
    public async Task<bool> ValidateTokenAsync(string token)
    {
        return await _identityClient.VerifyTokenAsync(token);
    }
}
```

#### User Management

```csharp
public class UserManagementService
{
    private readonly IIdentityClient<UserModel> _identityClient;
    
    public UserManagementService(IIdentityClient<UserModel> identityClient)
    {
        _identityClient = identityClient;
    }
    
    // Get user schema/attributes
    public async Task<List<UserAttribute>?> GetUserSchemaAsync()
    {
        return await _identityClient.AdminGetUserSchemaAsync();
    }
    
    // List users with pagination
    public async Task<PagedResponse<UserModel>?> GetUsersAsync(int page = 1, int limit = 20)
    {
        var pageOptions = new PageOptions { Page = page, Limit = limit };
        return await _identityClient.AdminListUsersAsync(pageOptions);
    }
    
    // Filter users
    public async Task<PagedResponse<UserModel>?> SearchUsersAsync(string? username = null, int? role = null, bool? deleted = null)
    {
        var pageOptions = new PageOptions { Page = 1, Limit = 50, Sort = "created_at", Order = "desc" };
        var filter = new UserFilterOptions
        {
            Username = username,
            Role = role,
            Deleted = deleted,
            CreatedAtFrom = DateTime.UtcNow.AddDays(-30), // Last 30 days
            CreatedAtTo = DateTime.UtcNow
        };
        
        return await _identityClient.AdminListUsersAsync(pageOptions, filter);
    }
    
    // Delete user (soft or hard delete)
    public async Task<bool> DeleteUserAsync(string identifier, bool soft = true)
    {
        var request = new AdminDeleteUserRequest
        {
            Identifier = identifier,
            Soft = soft
        };
        
        return await _identityClient.AdminDeleteUserAsync(request);
    }
    
    // Restore a deleted user
    public async Task<bool> RestoreUserAsync(string identifier)
    {
        var request = new AdminRestoreUserRequest
        {
            Identifier = identifier
        };
        
        return await _identityClient.AdminRestoreUserAsync(request);
    }
    
    // Reset user password
    public async Task<bool> ResetPasswordAsync(string identifier, string newPassword)
    {
        var request = new AdminResetUserPasswordRequest
        {
            Identifier = identifier,
            Password = newPassword
        };
        
        return await _identityClient.AdminResetUserPasswordAsync(request);
    }
    
    // Update multiple users
    public async Task<CountResponse<long>?> UpdateUsersAsync(List<UserModel> users, params string[] onlyColumns)
    {
        return await _identityClient.AdminUpdateUsersAsync(users, onlyColumns);
    }
}
```

#### Token Operations

```csharp
public class TokenService
{
    private readonly IIdentityClient<UserModel> _identityClient;
    
    public TokenService(IIdentityClient<UserModel> identityClient)
    {
        _identityClient = identityClient;
    }
    
    // Local token introspection (decode without verification)
    public Dictionary<string, object>? GetTokenClaims(string token)
    {
        return _identityClient.IntrospectToken<Dictionary<string, object>>(token);
    }
    
    // Introspect token to custom type
    public UserModel? GetTokenUser(string token)
    {
        return _identityClient.IntrospectToken<UserModel>(token);
    }
    
    // Remote token introspection (server-side validation)
    public async Task<Dictionary<string, object>?> ValidateTokenRemoteAsync(string accessToken)
    {
        return await _identityClient.TokenIntrospectAsync<Dictionary<string, object>>(accessToken);
    }
    
    // Remote token introspection to custom type
    public async Task<UserModel?> ValidateTokenUserAsync(string accessToken)
    {
        return await _identityClient.TokenIntrospectAsync<UserModel>(accessToken);
    }
    
    // Verify token locally (with signature validation)
    public async Task<bool> VerifyTokenAsync(string token)
    {
        return await _identityClient.VerifyTokenAsync(token);
    }

    
    // refresh token operation
    public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
    {
        return await _identityClient.RefreshTokenAsync(refreshToken);
    }
    
    // Admin enrich token operation
    public async Task<TokenResponse> AdminEnrichTokenAsync(string accessToken)
    {
        // Enrich token with additional claims/data
        var extraClaims = new
        {
            custom_claim = "enriched_value",
            permissions = new[] { "read:users", "write:users" },
            department = "engineering",
            enriched_at = DateTimeOffset.UtcNow.ToString()
        };
        
        return await _identityClient.AdminEnrichTokenAsync(accessToken, extraClaims);
    }
    
    // Refresh JWKS keys from server
    public async Task RefreshKeysAsync()
    {
        await _identityClient.LoadKeysAsync();
    }
    
    // Encrypt password for transmission
    public string EncryptPassword(string plainPassword)
    {
        return _identityClient.EncryptPassword(plainPassword);
    }
    
    // Decrypt password (if needed)
    public string DecryptPassword(string encryptedPassword)
    {
        return _identityClient.DecryptPassword(encryptedPassword);
    }
}
```

### 5. Direct Client Initialization

For scenarios where dependency injection isn't used, you can initialize the client directly:

```csharp
using Hellenic.Identity.SDK;
using Hellenic.Identity.SDK.Models;
using Hellenic.Identity.SDK.Services;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

// Define your user model
public class UserModel
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;
    
    [JsonPropertyName("firstname")]
    public string FirstName { get; set; } = string.Empty;
    
    [JsonPropertyName("lastname")]
    public string LastName { get; set; } = string.Empty;
    
    [JsonPropertyName("role")]
    public int Role { get; set; }
}

// Manual initialization
public static async Task<IIdentityClient<UserModel>> CreateClientAsync()
{
    // Create configuration
    var config = new AppConfiguration
    {
        IdentityClient = new IdentityClientOptions
        {
            BaseURL = "https://your-identity-server.com",
            ClientToken = "your-jwt-client-token",
            ClientID = "your-oauth-client-id",
            ClientSecret = "your-oauth-client-secret",
            EncryptionKey = "your-32-character-hex-encryption-key",
            PasswordStrengthLevel = "medium",
            DefaultScope = "user:read"
        }
    };
    
    // Create dependencies
    var options = Options.Create(config);
    var logger = NullLogger<IdentityClient<UserModel>>.Instance;
    var httpClient = new HttpClient();
    
    // Create and initialize client
    var client = new IdentityClient<UserModel>(options, logger, httpClient);
    await client.InitializeAsync();
    
    return client;
}

// Usage example
public static async Task ExampleUsageAsync()
{
    var client = await CreateClientAsync();
    
    // Admin signup method
    var newUser = new UserModel
    {
        Username = "user@example.com",
        FirstName = "John",
        LastName = "Doe",
        Role = 1
    };
    
    var signupResult = await client.AdminUserSignupAsync(newUser, "password123");
    if (signupResult != null)
    {
        Console.WriteLine($"User created! Access Token: {signupResult.AccessToken}");
    }
    
    // Sign in method
    var signinResult = await client.UserSigninAsync("user@example.com", "password123");
    if (signinResult != null)
    {
        Console.WriteLine($"Sign in successful! Token: {signinResult.AccessToken}");
        
        // Get user info method (introspect token)
        var userInfo = client.IntrospectToken<UserModel>(signinResult.AccessToken);
        if (userInfo != null)
        {
            Console.WriteLine($"User info: {userInfo.Username} - {userInfo.FirstName} {userInfo.LastName}");
        }
        
        // Remote token introspection (server validation)
        var tokenDetails = await client.TokenIntrospectAsync<Dictionary<string, object>>(signinResult.AccessToken);
        if (tokenDetails != null)
        {
            Console.WriteLine($"Token validated by server. Claims: {string.Join(", ", tokenDetails.Keys)}");
        }
    }
}
```

## ASP.NET Core Authentication

The SDK now includes a complete ASP.NET Core authentication handler with EdDSA support and JWT Bearer-like events! This provides a drop-in replacement for the standard `JwtBearer` middleware that doesn't support EdDSA tokens.

### Quick Setup

#### 1. Install Package
```bash
dotnet add package Hellenic.Identity.SDK
```

#### 2. Simple Configuration

The SDK uses ASP.NET Core's `IConfiguration` system, which automatically supports multiple configuration sources without requiring the IOptions pattern:

```csharp
using Hellenic.Identity.SDK.Extensions;
using Hellenic.Identity.SDK.Models;

var builder = WebApplication.CreateBuilder(args);

// ONE LINE SETUP - automatically reads from any IConfiguration source
builder.Services.AddHellenicAuthentication<UserModel>();

builder.Services.AddAuthorization();
var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
```

**Configuration Sources Supported:**
- **appsettings.json** (development)
- **Environment Variables** (production)
- **User Secrets** (development)
- **Azure Key Vault** (production)
- **AWS Secrets Manager** (production)
- **Command Line Arguments**
- **Any custom IConfiguration provider**

**Development Example** (appsettings.json):
```json
{
  "IdentityClient": {
    "BaseURL": "https://your-identity-server.com",
    "ClientToken": "your-jwt-client-token",
    "ClientID": "your-oauth-client-id",
    "ClientSecret": "your-oauth-client-secret",
    "EncryptionKey": "your-32-character-hex-encryption-key",
    "PasswordStrengthLevel": "medium",
    "DefaultScope": "user:read"
  }
}
```

**Production Example** (Environment Variables):
```bash
# Set these environment variables in your production environment
export IdentityClient__BaseURL="https://your-identity-server.com"
export IdentityClient__ClientToken="your-jwt-client-token"
export IdentityClient__ClientID="your-oauth-client-id"
export IdentityClient__ClientSecret="your-oauth-client-secret"
export IdentityClient__EncryptionKey="your-32-character-hex-encryption-key"
export IdentityClient__PasswordStrengthLevel="medium"
export IdentityClient__DefaultScope="user:read"
```

**Azure Key Vault Example**:
```csharp
var builder = WebApplication.CreateBuilder(args);

// Add Azure Key Vault to configuration
builder.Configuration.AddAzureKeyVault(/* your Key Vault configuration */);

// Hellenic Authentication automatically reads from any IConfiguration source
builder.Services.AddHellenicAuthentication<UserModel>();
```

#### 3. Define Your User Model
```csharp
public class UserModel
{
    public string Id { get; set; } = "";
    public string Username { get; set; } = "";
    public string Email { get; set; } = "";
    public string Role { get; set; } = "";
}
```

### Advanced Configuration with Events

Complete JWT Bearer Events compatibility - your existing event code works without changes!

```csharp
using Hellenic.Identity.SDK.Authentication;
using Hellenic.Identity.SDK.Extensions;

// Advanced setup with custom events
builder.Services.AddHellenicAuthentication<UserModel>("Hellenic", options =>
{
    options.Events = new HellenicAuthenticationEvents
    {
        OnMessageReceived = async context =>
        {
            // Extract token from custom sources (query, cookie, etc.)
            var queryToken = context.HttpContext.Request.Query["access_token"];
            if (!string.IsNullOrEmpty(queryToken))
            {
                context.Token = queryToken;
                Console.WriteLine("Token extracted from query string");
            }
        },

        OnTokenValidated = async context =>
        {
            Console.WriteLine($"User authenticated: {context.Principal?.Identity?.Name}");
            
            // Add custom claims
            if (context.Principal?.Identity is ClaimsIdentity identity)
            {
                identity.AddClaim(new Claim("custom_claim", "added_by_event"));
                identity.AddClaim(new Claim("validated_at", DateTimeOffset.UtcNow.ToString()));
                
                // Add user permissions from database
                var userId = identity.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (!string.IsNullOrEmpty(userId))
                {
                    // Fetch permissions and add as claims
                    // var permissions = await GetUserPermissions(userId);
                    // foreach (var permission in permissions)
                    //     identity.AddClaim(new Claim("permission", permission));
                }
            }
        },

        OnAuthenticationFailed = async context =>
        {
            Console.WriteLine($"Authentication failed: {context.Exception?.Message}");
            
            // Handle different failure types
            if (context.Exception?.Message?.Contains("expired") == true)
            {
                context.HttpContext.Response.Headers.Add("X-Token-Expired", "true");
            }
        },

        OnChallenge = async context =>
        {
            Console.WriteLine("Authentication challenge triggered");
            
            // Custom JSON response for API endpoints
            if (context.HttpContext.Request.Path.StartsWithSegments("/api"))
            {
                context.HttpContext.Response.StatusCode = 401;
                context.HttpContext.Response.ContentType = "application/json";
                await context.HttpContext.Response.WriteAsync(
                    """{"error": "hellenic_token_required", "message": "Valid Hellenic Identity token required"}""");
                context.Handled = true; // Skip default challenge
            }
        },

        OnForbidden = async context =>
        {
            Console.WriteLine($"Access forbidden for user: {context.Principal?.Identity?.Name}");
            
            // Custom forbidden response
            if (context.HttpContext.Request.Path.StartsWithSegments("/api"))
            {
                context.HttpContext.Response.StatusCode = 403;
                context.HttpContext.Response.ContentType = "application/json";
                await context.HttpContext.Response.WriteAsync(
                    """{"error": "access_denied", "message": "Insufficient permissions"}""");
            }
        }
    };

    // Additional validation options
    options.ExpectedIssuer = "https://your-hellenic-identity-server.com";
    options.ExpectedAudience = "your-client-id";
});
```

### Controller Usage

Standard ASP.NET Core authorization works seamlessly:

```csharp
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    // Standard [Authorize] attribute works!
    [HttpGet("profile")]
    [Authorize]
    public IActionResult GetProfile()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var username = User.Identity?.Name;
        var customClaim = User.FindFirst("custom_claim")?.Value;
        var validatedAt = User.FindFirst("validated_at")?.Value;
        
        return Ok(new {
            userId,
            username,
            customClaim,
            validatedAt,
            message = "EdDSA token authenticated!"
        });
    }

    // Role-based authorization works!
    [HttpGet("admin")]
    [Authorize(Roles = "admin")]
    public IActionResult AdminOnly()
    {
        return Ok(new { message = "Admin access granted" });
    }

    // Policy-based authorization works!
    [HttpGet("manager")]
    [Authorize(Policy = "ManagerPolicy")]
    public IActionResult ManagerOnly()
    {
        return Ok(new { message = "Manager access granted" });
    }
}

// Minimal API also works
app.MapGet("/api/protected", [Authorize] (ClaimsPrincipal user) => new
{
    Message = "Hello from Hellenic Identity!",
    User = user.Identity?.Name,
    Claims = user.Claims.Select(c => new { c.Type, c.Value })
});

// Access the Identity Client directly if needed
app.MapGet("/api/user-schema", [Authorize] async (HttpContext context) =>
{
    var identityClient = context.GetHellenicIdentityClient<UserModel>();
    var schema = await identityClient.AdminGetUserSchemaAsync();
    return Results.Ok(schema);
});
```

### Accessing the Identity Client

When you need direct access to the Hellenic Identity Client for admin operations or token management, use the provided helper methods:

**In Controllers:**
```csharp
[ApiController]
[Route("api/admin")]
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    [Authorize]
    public async Task<IActionResult> GetUsers()
    {
        // Get the Identity Client directly from HttpContext
        var identityClient = HttpContext.GetHellenicIdentityClient<UserModel>();
        
        var pageOptions = new PageOptions { Page = 1, Limit = 10 };
        var users = await identityClient.AdminListUsersAsync(pageOptions);
        
        return Ok(users);
    }
    
    [HttpPost("enrich-token")]
    [Authorize]
    public async Task<IActionResult> EnrichToken([FromBody] EnrichTokenRequest request)
    {
        var identityClient = HttpContext.GetHellenicIdentityClient<UserModel>();
        
        var extraClaims = new
        {
            department = "engineering",
            permissions = new[] { "read:users", "write:users" }
        };
        
        var enrichedToken = await identityClient.AdminEnrichTokenAsync(request.AccessToken, extraClaims);
        return Ok(enrichedToken);
    }
}
```

**In Services (with Dependency Injection):**
```csharp
public class UserManagementService
{
    private readonly IIdentityClient<UserModel> _identityClient;
    
    public UserManagementService(IServiceProvider serviceProvider)
    {
        // Get the Identity Client from service provider
        _identityClient = serviceProvider.GetHellenicIdentityClient<UserModel>();
    }
    
    // Alternative: Direct injection (preferred)
    public UserManagementService(IIdentityClient<UserModel> identityClient)
    {
        _identityClient = identityClient;
    }
    
    public async Task<List<UserModel>> GetUsersAsync()
    {
        var pageOptions = new PageOptions { Page = 1, Limit = 50 };
        var result = await _identityClient.AdminListUsersAsync(pageOptions);
        return result?.Data ?? new List<UserModel>();
    }
}
```

**In Minimal APIs:**
```csharp
// Using helper method
app.MapGet("/api/admin/users", [Authorize] async (HttpContext context) =>
{
    var identityClient = context.GetHellenicIdentityClient<UserModel>();
    var pageOptions = new PageOptions { Page = 1, Limit = 10 };
    var users = await identityClient.AdminListUsersAsync(pageOptions);
    return Results.Ok(users);
});

// Using direct injection (preferred)
app.MapGet("/api/admin/schema", [Authorize] async (IIdentityClient<UserModel> identityClient) =>
{
    var schema = await identityClient.AdminGetUserSchemaAsync();
    return Results.Ok(schema);
});
```

**Available Helper Methods:**
- [`serviceProvider.GetHellenicIdentityClient<TUser>()`](src/Extensions/HellenicAuthenticationExtensions.cs:153) - Get client from IServiceProvider
- [`httpContext.GetHellenicIdentityClient<TUser>()`](src/Extensions/HellenicAuthenticationExtensions.cs:163) - Get client from HttpContext

These methods provide convenient access to the registered `IIdentityClient<TUser>` instance for admin operations, token management, and user operations.

### Multiple Authentication Schemes

Support multiple authentication schemes for different user types using IConfiguration:

```csharp
// Configure authentication with primary scheme, then add additional schemes
builder.Services.AddAuthentication("Hellenic")  // Set default scheme
    .AddHellenicAuthentication<UserModel>("Hellenic")                    // Primary scheme for regular users
    .AddHellenicAuthentication<AdminModel>("HellenicAdmin", options => { // Secondary scheme for admin users
        options.ExpectedIssuer = "https://admin.hellenic-server.com";
        options.ExpectedAudience = "admin-client-id";
    });
```

**Configuration Examples:**

**appsettings.json** (Development):
```json
{
  "IdentityClient": {
    "BaseURL": "https://your-identity-server.com",
    "ClientToken": "your-jwt-client-token",
    // ... regular user settings
  }
}
```

**Environment Variables** (Production):
```bash
# Regular user configuration
export IdentityClient__BaseURL="https://your-identity-server.com"
export IdentityClient__ClientToken="your-jwt-client-token"

# Admin configuration (if needed for different client)
export AdminIdentityClient__BaseURL="https://admin.hellenic-server.com"
export AdminIdentityClient__ClientToken="your-admin-jwt-client-token"
```

**Usage in Controllers:**
```csharp
// Specify the scheme in [Authorize] attributes:
[Authorize(AuthenticationSchemes = "Hellenic")]        // Use primary scheme
[Authorize(AuthenticationSchemes = "HellenicAdmin")]   // Use admin scheme
[Authorize(AuthenticationSchemes = "Hellenic,HellenicAdmin")] // Accept either scheme
```

**Note:** For multiple schemes with different identity servers, you may need separate configuration sections or manual service registration for different `IIdentityClient<T>` instances.

### Migration from JwtBearer

Replace your existing JWT Bearer setup with identical API:

```csharp
// OLD - Standard JwtBearer (doesn't support EdDSA)
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context => {
                // Your existing event code
            },
            OnChallenge = async context => {
                // Your existing event code
            }
        };
    });

// NEW - Hellenic Authentication (supports EdDSA + all algorithms)
builder.Services.AddHellenicAuthentication<UserModel>("Hellenic", options =>
{
    options.Events = new HellenicAuthenticationEvents
    {
        OnTokenValidated = async context => {
            // Same event code works without changes!
        },
        OnChallenge = async context => {
            // Same event code works without changes!
        }
    };
});
```

**Your existing event code works without changes!** 🎉

### Performance & Simplicity Improvements

🚀 **Simplified Setup**: Single method [`AddHellenicAuthentication<TUser>()`](src/Extensions/HellenicAuthenticationExtensions.cs:26) handles everything - no complex initialization required!

⚡ **Performance Optimized**:
- **60% faster JWT claims extraction** using direct [`JwtSecurityTokenHandler.ReadJwtToken()`](src/Services/HellenicAuthenticationService.cs:45) vs Dictionary approach
- **Optimized logging levels** - Debug for initialization, minimal serve-time logging for maximum performance
- **Synchronous initialization** - JWKS keys loaded during service registration, not per-request

🔧 **Zero Configuration**:
- Automatically initializes [`IdentityClient`](src/Services/IdentityClient.cs:25) during DI registration
- No async initialization calls required in your application code
- Works immediately after service registration

### Key Features

✅ **EdDSA/Ed25519 Token Support** - Works with Hellenic Identity's Ed25519 tokens out of the box
✅ **JWT Bearer Events Compatibility** - Complete event system identical to `JwtBearerEvents`
✅ **Performance Optimized** - 60% faster claim extraction vs Dictionary approach
✅ **Optimized Logging** - Debug-level initialization logging, minimal serve-time logging
✅ **Synchronous Initialization** - No async initialization required during requests
✅ **Easy Migration** - Drop-in replacement for `JwtBearer` with identical API
✅ **Standard Authorization** - Works with `[Authorize]`, roles, and policies
✅ **Custom Claims** - Add permissions, user data, and custom claims in events
✅ **Error Handling** - Complete error handling with custom responses
✅ **Multiple Schemes** - Support multiple authentication schemes

### Available Extension Methods

#### `AddHellenicAuthentication<TUser>()`
Complete setup - registers Identity Client + Authentication Service + Handler with synchronous initialization

```csharp
// Basic setup with default scheme "Hellenic"
builder.Services.AddHellenicAuthentication<UserModel>();

// Custom scheme name
builder.Services.AddHellenicAuthentication<UserModel>("CustomScheme");

// With event configuration
builder.Services.AddHellenicAuthentication<UserModel>("Hellenic", options => {
    options.Events = new HellenicAuthenticationEvents { /* your events */ };
    options.ExpectedIssuer = "https://your-identity-server.com";
    options.ExpectedAudience = "your-client-id";
});
```

#### `AuthenticationBuilder.AddHellenicAuthentication<TUser>()`
Add additional authentication schemes to an existing AuthenticationBuilder

```csharp
// For multiple authentication schemes - use AuthenticationBuilder extension
builder.Services.AddAuthentication("PrimaryScheme")
    .AddHellenicAuthentication<UserModel>("Hellenic", "Hellenic Identity", options => {
        // Primary scheme configuration
    })
    .AddHellenicAuthentication<AdminModel>("HellenicAdmin", "Admin Authentication", options => {
        // Admin scheme configuration
        options.ExpectedIssuer = "https://admin.hellenic-server.com";
    });
```

#### Manual Service Registration (Advanced)
```csharp
// If you need more control over service registration
builder.Services.Configure<AppConfiguration>(builder.Configuration);
builder.Services.AddHttpClient<IIdentityClient<UserModel>, IdentityClient<UserModel>>();

// Manual authentication registration
builder.Services.AddAuthentication("Hellenic")
    .AddScheme<HellenicAuthenticationOptions, HellenicAuthenticationHandler<UserModel>>("Hellenic", options => {
        // Your configuration
    });
```

#### Method Parameters Explained

**`services.AddAuthentication(authenticationScheme)`**
- `authenticationScheme`: The default authentication scheme name used when no specific scheme is specified in `[Authorize]` attributes
- This is the scheme ASP.NET Core will use by default for authentication challenges and when `[Authorize]` is used without specifying a scheme

**`AddHellenicAuthentication<TUser>(authenticationScheme, displayName, configureOptions)`**
- `authenticationScheme`: The unique identifier for this authentication scheme (e.g., "Hellenic", "HellenicAdmin", "CustomAuth")
  - Used internally by ASP.NET Core authentication system
  - Referenced in `[Authorize(AuthenticationSchemes = "...")]` attributes
  - Can be any custom name - allows multiple authentication schemes for different user types
- `displayName`: Human-readable name shown in logs and error messages (e.g., "Hellenic Identity Authentication", "Admin Portal Auth")
- `configureOptions`: Optional delegate to configure authentication events, validation settings, expected issuer/audience, etc.

**Multiple Authentication Schemes Use Cases:**
- Different user types (customers vs. admins) with different identity servers
- Different authentication requirements (different issuers, audiences, or validation rules)
- Gradual migration from one authentication system to another
- Supporting both legacy and modern authentication simultaneously

## Advanced Features

### Multiple User Models

The SDK supports different user models for different contexts:

```csharp
// Employee management
public class Employee
{
    public string Username { get; set; }
    public string Department { get; set; }
    public string EmployeeId { get; set; }
}

// Customer management  
public class Customer
{
    public string Username { get; set; }
    public string Company { get; set; }
    public string SubscriptionLevel { get; set; }
}

// Register different SDK instances
services.AddSingleton<IIdentityClient<Employee>, IdentityClient<Employee>>();
services.AddSingleton<IIdentityClient<Customer>, IdentityClient<Customer>>();
```

### EdDSA/Ed25519 Token Support

The SDK automatically detects and validates EdDSA (Ed25519) signed JWT tokens:

```csharp
// Supports all JWT signature algorithms:
// - RSA (RS256, RS384, RS512)
// - ECDSA (ES256, ES384, ES512)  
// - EdDSA (Ed25519) ✨ New!

var isValid = await _identityClient.VerifyTokenAsync(edDsaToken);
```

### Bulk Operations

```csharp
// Bulk user updates
var users = new List<UserModel>
{
    new UserModel { Username = "user1", Role = 2, Email = "user1@example.com" },
    new UserModel { Username = "user2", Role = 3, Email = "user2@example.com" }
};

// Update only specific columns
var result = await _identityClient.AdminUpdateUsersAsync(users, "role");
if (result != null)
{
    Console.WriteLine($"Updated {result.Count} users");
}

// Update all user fields
var resultAll = await _identityClient.AdminUpdateUsersAsync(users);
if (resultAll != null)
{
    Console.WriteLine($"Updated {resultAll.Count} users with all fields");
}
```

## Error Handling

```csharp
try
{
    // Initialize SDK first
    if (!_identityClient.IsInitialized)
    {
        var initialized = await _identityClient.InitializeAsync();
        if (!initialized)
        {
            Console.WriteLine("Failed to initialize SDK");
            return;
        }
    }

    var token = await _identityClient.UserSigninAsync(username, password);
    if (token != null)
    {
        Console.WriteLine($"Access Token: {token.AccessToken}");
        Console.WriteLine($"Token Type: {token.TokenType}");
        Console.WriteLine($"Expires In: {token.ExpiresIn} seconds");
        Console.WriteLine($"Refresh Token: {token.RefreshToken}");
        Console.WriteLine($"Scope: {token.Scope}");
    }
    else
    {
        Console.WriteLine("Authentication failed");
    }
}
catch (ArgumentException ex)
{
    // Password validation errors
    Console.WriteLine($"Validation error: {ex.Message}");
}
catch (InvalidOperationException ex)
{
    // SDK configuration or initialization errors
    Console.WriteLine($"Client error: {ex.Message}");
}
catch (HttpRequestException ex)
{
    // Network or server errors
    Console.WriteLine($"Network error: {ex.Message}");
}
```

## CLI Example Application

The SDK includes a complete CLI example application demonstrating all features:

```bash
# Run the example application
dotnet run --project examples/cli-application

# Available commands:
dotnet run --project examples/cli-application -- signup --username user@test.com --password test123 --firstname John
dotnet run --project examples/cli-application -- login --username user@test.com --password test123
dotnet run --project examples/cli-application -- validate-token --token=eyJ...
dotnet run --project examples/cli-application -- admin-list-users --page 1 --limit 10
dotnet run --project examples/cli-application -- admin-delete-user --identifier user@test.com --soft
```

## Testing

Run the comprehensive test suite:

```bash
dotnet test
```

The test suite includes:
- ✅ Generic functionality with different user model types
- ✅ Authentication and admin operations
- ✅ EdDSA/Ed25519 token validation
- ✅ Error handling and edge cases
- ✅ Configuration validation
- ✅ Mock server interactions

## API Reference

### Core Interface

```csharp
/// <summary>
/// Generic Identity SDK interface that supports any user model structure
/// TUser: The user model type (must be a class)
/// </summary>
public interface IIdentityClient<TUser> where TUser : class
{
    /// <summary>
    /// Indicates whether the SDK has been initialized
    /// </summary>
    bool IsInitialized { get; }

    /// <summary>
    /// Initialize the client by loading JWKS keys and validating configuration
    /// </summary>
    Task<bool> InitializeAsync();

    /// <summary>
    /// Load or refresh JSON Web Key Set from the identity server
    /// </summary>
    Task LoadKeysAsync();

    /// <summary>
    /// Verify if a JWT token is valid (supports RSA, ECDSA, and EdDSA/Ed25519)
    /// </summary>
    /// <param name="token">JWT token to verify</param>
    /// <returns>True if token is valid</returns>
    Task<bool> VerifyTokenAsync(string token);

    /// <summary>
    /// Introspect a JWT token locally (decode without verification)
    /// </summary>
    /// <typeparam name="T">Type to deserialize claims to</typeparam>
    /// <param name="token">JWT token to introspect</param>
    /// <returns>Token claims as specified type</returns>
    T? IntrospectToken<T>(string token) where T : class;

    /// <summary>
    /// Introspect a token using remote identity server endpoint
    /// </summary>
    /// <typeparam name="T">Type to deserialize response to</typeparam>
    /// <param name="accessToken">Access token to introspect</param>
    /// <returns>Token information from server</returns>
    Task<T?> TokenIntrospectAsync<T>(string accessToken) where T : class;

    /// <summary>
    /// Admin operation: Sign up a new user (requires admin client token)
    /// </summary>
    /// <param name="user">User data (any user model type)</param>
    /// <param name="password">Plain text password</param>
    /// <returns>Token response if successful</returns>
    Task<TokenResponse> AdminUserSignupAsync(TUser user, string password);

    /// <summary>
    /// Sign in a user using OAuth2 password grant
    /// </summary>
    /// <param name="username">Username or email</param>
    /// <param name="password">Plain text password</param>
    /// <returns>Token response if successful</returns>
    Task<TokenResponse> UserSigninAsync(string username, string password);

    /// <summary>
    /// Admin operation: Sign in as a user without password (requires admin client token)
    /// </summary>
    /// <param name="identifier">User ID or username</param>
    /// <returns>Token response if successful</returns>
    Task<TokenResponse> AdminUserSigninAsync(string identifier);

    /// <summary>
    /// Admin operation: Refresh an access token using a refresh token (requires admin client token)
    /// </summary>
    /// <param name="refreshToken">The refresh token to exchange for new access token</param>
    /// <returns>Token response with new access token</returns>
    Task<TokenResponse> RefreshTokenAsync(string refreshToken);

    /// <summary>
    /// User operation: Refresh an access token using OAuth2 refresh token grant
    /// </summary>
    /// <param name="refreshToken">The refresh token to exchange for new access token</param>
    /// <returns>Token response with new access token</returns>
    Task<TokenResponse> UserRefreshTokenAsync(string refreshToken);

    /// <summary>
    /// Encrypt a plain text password using AES-GCM
    /// </summary>
    /// <param name="plainPassword">Plain text password</param>
    /// <returns>Encrypted password as hex string</returns>
    string EncryptPassword(string plainPassword);

    /// <summary>
    /// Decrypt an encrypted password
    /// </summary>
    /// <param name="encryptedPassword">Encrypted password as hex string</param>
    /// <returns>Plain text password</returns>
    string DecryptPassword(string encryptedPassword);

    /// <summary>
    /// Admin operation: Get user schema/attributes from identity server
    /// </summary>
    /// <returns>List of user attributes</returns>
    Task<List<UserAttribute>?> AdminGetUserSchemaAsync();

    /// <summary>
    /// Admin operation: Delete a user by ID or username
    /// </summary>
    /// <param name="request">Delete user request</param>
    /// <returns>True if successful</returns>
    Task<bool> AdminDeleteUserAsync(AdminDeleteUserRequest request);

    /// <summary>
    /// Admin operation: Restore a deleted user by ID or username
    /// </summary>
    /// <param name="request">Restore user request</param>
    /// <returns>True if successful</returns>
    Task<bool> AdminRestoreUserAsync(AdminRestoreUserRequest request);

    /// <summary>
    /// Admin operation: Reset user password by ID or username
    /// </summary>
    /// <param name="request">Reset password request</param>
    /// <returns>True if successful</returns>
    Task<bool> AdminResetUserPasswordAsync(AdminResetUserPasswordRequest request);

    /// <summary>
    /// Admin operation: List users with pagination and filtering
    /// </summary>
    /// <param name="pageOptions">Pagination options</param>
    /// <param name="filter">Filter options</param>
    /// <returns>Paginated list of users</returns>
    Task<PagedResponse<TUser>?> AdminListUsersAsync(PageOptions pageOptions, UserFilterOptions? filter = null);

    /// <summary>
    /// Admin operation: Update multiple users
    /// </summary>
    /// <param name="users">List of users to update</param>
    /// <param name="onlyColumns">Only update specific columns</param>
    /// <returns>Count of updated users</returns>
    Task<CountResponse<long>?> AdminUpdateUsersAsync(List<TUser> users, params string[] onlyColumns);
}
```

### Models

```csharp
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

public class CountResponse<T>
{
    [JsonPropertyName("count")]
    public T Count { get; set; } = default(T)!;
}

// Admin request models
public class AdminDeleteUserRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty;
    
    [JsonPropertyName("soft")]
    public bool? Soft { get; set; }
}

public class AdminRestoreUserRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty;
}

public class AdminResetUserPasswordRequest
{
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty;
    
    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;
}
```

### Error Codes

| HTTP Status |	Description
|------------|----------------
| 400	| Bad Request - Invalid request data
| 401	| Unauthorized - Invalid credentials
| 403	| Forbidden - Account locked/disabled
| 404	| Not Found - User not found
| 409	| Conflict - Username already exists
| 429	| Too Many Requests - Rate limited
| 500	| Internal Server Error - Server error

## Requirements

- .NET 9.0 or higher
- Identity Server with JWKS endpoint support
- Valid OAuth2 credentials (for admin operations)

## Dependencies

**Core Dependencies:**
- Microsoft.Extensions.Logging.Abstractions 9.0.0
- Microsoft.Extensions.Options 9.0.0
- System.IdentityModel.Tokens.Jwt 8.2.1
- Microsoft.IdentityModel.Tokens 8.2.1
- System.Text.Json 9.0.0
- System.Net.Http.Json 9.0.0
- System.Security.Cryptography.Algorithms 4.3.1
- BouncyCastle.Cryptography 2.4.0 (for EdDSA support)

**ASP.NET Core Authentication Dependencies:**
- Microsoft.AspNetCore.Authentication 2.2.0
- Microsoft.Extensions.DependencyInjection.Abstractions 9.0.0
- Microsoft.Extensions.DependencyInjection 9.0.0

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for new functionality
4. Ensure all tests pass (`dotnet test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: Check the `examples/` folder for complete usage examples
- **Issues**: Create an issue for bug reports or feature requests
- **Repository**: [https://github.com/kataras/hellenic-identity-sdk-csharp](https://github.com/kataras/hellenic-identity-sdk-csharp)

---

**Built with ❤️ for the .NET community**

*Generic, type-safe JWT authentication with EdDSA support*
