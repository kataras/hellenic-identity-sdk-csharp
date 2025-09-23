using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Hellenic.Identity.SDK.Models;
using Hellenic.Identity.SDK.Services;

namespace Hellenic.Identity.SDK.Tests;

/// <summary>
/// Test the IdentityClient implementation with different user models to verify generic functionality
/// </summary>
public class TestUserModel
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;
    
    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;
    
    [JsonPropertyName("role")]
    public int Role { get; set; }
}

public class CustomUserModel
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;
    
    [JsonPropertyName("company")]
    public string Company { get; set; } = string.Empty;
    
    [JsonPropertyName("department")]
    public string Department { get; set; } = string.Empty;
}

public class IdentityClientTests : IDisposable
{
    private readonly WireMockServer _mockServer;
    private readonly Mock<ILogger<IdentityClient<TestUserModel>>> _mockLogger;
    private readonly IOptions<AppConfiguration> _config;
    private readonly HttpClient _httpClient;

    public IdentityClientTests()
    {
        _mockServer = WireMockServer.Start();
        _mockLogger = new Mock<ILogger<IdentityClient<TestUserModel>>>();

        var config = new AppConfiguration
        {
            IdentityClient = new IdentityClientOptions
            {
                BaseURL = _mockServer.Urls[0],
                ClientToken = "test-client-token",
                EncryptionKey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                PasswordStrengthLevel = "medium",
                ClientID = "test-client-id",
                ClientSecret = "test-client-secret",
                DefaultScope = "user:read"
            }
        };
        _config = Options.Create(config);
        
        _httpClient = new HttpClient();
        _httpClient.BaseAddress = new Uri(_mockServer.Urls[0]);

        SetupJwksMock();
    }

    public void Dispose()
    {
        _mockServer.Dispose();
        _httpClient.Dispose();
    }

    private void SetupJwksMock()
    {
        // Mock JWKS endpoint with EdDSA key
        var jwkSet = new
        {
            keys = new[]
            {
                new
                {
                    kty = "OKP",
                    crv = "Ed25519",
                    x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
                    kid = "ed25519-key-1",
                    alg = "EdDSA",
                    use = "sig"
                }
            }
        };

        _mockServer
            .Given(Request.Create().WithPath("/.well-known/jwks.json").UsingGet())
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(jwkSet));
    }

    [Fact]
    public async Task InitializeAsync_ShouldReturnTrue_WhenConfigurationIsValid()
    {
        // Arrange
        var client = new IdentityClient<TestUserModel>(_config, _mockLogger.Object, _httpClient);

        // Act
        var result = await client.InitializeAsync();

        // Assert
        Assert.True(result);
        Assert.True(client.IsInitialized);
    }

    [Fact]
    public void EncryptPassword_ShouldReturnEncryptedString()
    {
        // Arrange
        var client = new IdentityClient<TestUserModel>(_config, _mockLogger.Object, _httpClient);
        var plainPassword = "testpassword123";

        // Act
        var encryptedPassword = client.EncryptPassword(plainPassword);

        // Assert
        Assert.NotNull(encryptedPassword);
        Assert.NotEqual(plainPassword, encryptedPassword);
        Assert.True(encryptedPassword.Length > 0);
        Assert.Matches(@"^[0-9a-f]+$", encryptedPassword); // Hex string check
    }

    [Fact]
    public void EncryptDecryptPassword_ShouldReturnOriginalPassword()
    {
        // Arrange
        var client = new IdentityClient<TestUserModel>(_config, _mockLogger.Object, _httpClient);
        var originalPassword = "testpassword123";

        // Act
        var encrypted = client.EncryptPassword(originalPassword);
        var decrypted = client.DecryptPassword(encrypted);

        // Assert
        Assert.Equal(originalPassword, decrypted);
    }

    [Fact]
    public async Task AdminUserSignupAsync_ShouldInitializeAndCallAPI()
    {
        // Arrange
        var configWithClientToken = Options.Create(new AppConfiguration
        {
            IdentityClient = new IdentityClientOptions
            {
                BaseURL = _mockServer.Urls[0],
                ClientToken = "valid-client-token",
                EncryptionKey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                PasswordStrengthLevel = "medium"
            }
        });

        _mockServer
            .Given(Request.Create().WithPath("/u/signup").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(new
            {
                access_token = "test-access-token",
                token_type = "Bearer",
                expires_in = 3600
            }));

        var mockLogger = new Mock<ILogger<IdentityClient<TestUserModel>>>();
        var client = new IdentityClient<TestUserModel>(configWithClientToken, mockLogger.Object, _httpClient);
        await client.InitializeAsync();

        var user = new TestUserModel
        {
            Username = "testuser",
            Email = "test@example.com",
            Role = 1
        };

        // Act
        var result = await client.AdminUserSignupAsync(user, "password123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("test-access-token", result.AccessToken);
        Assert.Equal("Bearer", result.TokenType);
    }

    [Fact]
    public async Task GenericFunctionality_ShouldWorkWithDifferentUserModels()
    {
        // Arrange & Act - Test with CustomUserModel
        var configWithClientToken = Options.Create(new AppConfiguration
        {
            IdentityClient = new IdentityClientOptions
            {
                BaseURL = _mockServer.Urls[0],
                ClientToken = "valid-client-token",
                EncryptionKey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                PasswordStrengthLevel = "medium"
            }
        });

        _mockServer
            .Given(Request.Create().WithPath("/u/signup").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(new
            {
                access_token = "custom-access-token",
                token_type = "Bearer",
                expires_in = 3600
            }));

        var mockLogger = new Mock<ILogger<IdentityClient<CustomUserModel>>>();
        var client = new IdentityClient<CustomUserModel>(configWithClientToken, mockLogger.Object, new HttpClient());
        await client.InitializeAsync();

        var user = new CustomUserModel
        {
            Username = "customuser",
            Company = "Test Company",
            Department = "Engineering"
        };

        var result = await client.AdminUserSignupAsync(user, "password123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("custom-access-token", result.AccessToken);
    }

    [Fact]
    public async Task UserSigninAsync_ShouldReturnTokenResponse_WhenCredentialsAreValid()
    {
        // Arrange
        var configWithClientToken = Options.Create(new AppConfiguration
        {
            IdentityClient = new IdentityClientOptions
            {
                BaseURL = _mockServer.Urls[0],
                ClientToken = "valid-client-token",
                EncryptionKey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                PasswordStrengthLevel = "medium",
                ClientID = "test-client-id",
                ClientSecret = "test-client-secret",
                DefaultScope = "user:read"
            }
        });

        _mockServer
            .Given(Request.Create().WithPath("/oauth2/token").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(new
            {
                access_token = "signin-access-token",
                token_type = "Bearer",
                expires_in = 3600,
                refresh_token = "refresh-token",
                scope = "user:read"
            }));

        var mockLogger = new Mock<ILogger<IdentityClient<TestUserModel>>>();
        var client = new IdentityClient<TestUserModel>(configWithClientToken, mockLogger.Object, new HttpClient());
        await client.InitializeAsync();

        // Act
        var result = await client.UserSigninAsync("testuser@example.com", "password123");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("signin-access-token", result.AccessToken);
        Assert.Equal("Bearer", result.TokenType);
        Assert.Equal(3600, result.ExpiresIn);
        Assert.Equal("refresh-token", result.RefreshToken);
        Assert.Equal("user:read", result.Scope);
    }

    [Fact]
    public async Task IntrospectToken_ShouldDecodeJwtClaims()
    {
        // Create a simple JWT token for testing (this is a mock token, not signed)
        var header = Convert.ToBase64String(Encoding.UTF8.GetBytes(@"{""alg"":""HS256"",""typ"":""JWT""}"));
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(@"{""sub"":""testuser"",""username"":""testuser"",""role"":""1""}"));
        var signature = "mock-signature";
        var token = $"{header}.{payload}.{signature}";

        SetupJwksMock();
        var client = new IdentityClient<TestUserModel>(_config, _mockLogger.Object, _httpClient);
        await client.InitializeAsync();

        // Act
        var claims = client.IntrospectToken<Dictionary<string, object>>(token);

        // Assert - Note: This should work for local introspection even with invalid signature
        // as IntrospectToken method doesn't verify signatures, it just decodes claims
        Assert.NotNull(claims);
    }

    [Fact]
    public async Task ValidatePassword_ShouldThrowException_ForShortPasswords()
    {
        // Arrange
        var config = Options.Create(new AppConfiguration
        {
            IdentityClient = new IdentityClientOptions
            {
                BaseURL = _mockServer.Urls[0],
                ClientToken = "valid-client-token",
                EncryptionKey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                PasswordStrengthLevel = "strong" // Requires 10+ characters
            }
        });
        SetupJwksMock();
        var mockLogger = new Mock<ILogger<IdentityClient<TestUserModel>>>();
        var client = new IdentityClient<TestUserModel>(config, mockLogger.Object, _httpClient);
        await client.InitializeAsync();

        var shortPassword = "123"; // Less than 10 characters

        // Act & Assert
        var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
            client.AdminUserSignupAsync(new TestUserModel { Username = "test" }, shortPassword));
        
        Assert.Contains("Password must be at least", exception.Message);
    }

    [Fact]
    public void TypeSafety_ShouldCompileWithDifferentUserTypes()
    {
        // Arrange & Act - This tests compile-time type safety
        var testUserClient = new IdentityClient<TestUserModel>(_config, _mockLogger.Object, _httpClient);
        var customUserLogger = new Mock<ILogger<IdentityClient<CustomUserModel>>>();
        var customUserClient = new IdentityClient<CustomUserModel>(_config, customUserLogger.Object, new HttpClient());

        // Assert - These should compile and create different typed instances
        Assert.NotNull(testUserClient);
        Assert.NotNull(customUserClient);
        Assert.IsAssignableFrom<IIdentityClient<TestUserModel>>(testUserClient);
        Assert.IsAssignableFrom<IIdentityClient<CustomUserModel>>(customUserClient);
    }

    [Fact]
    public async Task LoadKeysAsync_ShouldLoadJwksSuccessfully()
    {
        // Arrange
        var client = new IdentityClient<TestUserModel>(_config, _mockLogger.Object, _httpClient);

        // Act
        await client.LoadKeysAsync();

        // Assert - Should not throw exception
        Assert.True(true);
    }

    [Fact] 
    public async Task VerifyTokenAsync_ShouldReturnFalse_ForInvalidToken()
    {
        // Arrange
        SetupJwksMock();
        var client = new IdentityClient<TestUserModel>(_config, _mockLogger.Object, _httpClient);
        await client.InitializeAsync();

        var invalidToken = "invalid.jwt.token";

        // Act
        var result = await client.VerifyTokenAsync(invalidToken);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task TokenIntrospectAsync_ShouldCallRemoteEndpoint()
    {
        // Arrange
        _mockServer
            .Given(Request.Create().WithPath("/oauth2/token/introspect").UsingPost())
            .RespondWith(Response.Create().WithStatusCode(200).WithBodyAsJson(new
            {
                active = true,
                sub = "testuser",
                username = "testuser"
            }));

        SetupJwksMock();
        var client = new IdentityClient<TestUserModel>(_config, _mockLogger.Object, _httpClient);
        await client.InitializeAsync();

        // Act
        var result = await client.TokenIntrospectAsync<Dictionary<string, object>>("test-access-token");

        // Assert
        Assert.NotNull(result);
        Assert.True(result.ContainsKey("active"));
    }
}