using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Hellenic.Identity.SDK.Models;

namespace Hellenic.Identity.SDK.Services;

/// <summary>
/// Generic Identity Client interface that supports any user model structure
/// TUser: The user model type (must be a class)
/// </summary>
public interface IIdentityClient<TUser> where TUser : class
{
    /// <summary>
    /// Indicates whether the client has been initialized
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
    /// Get signing keys from the JWKS endpoint
    /// </summary>
    /// <returns>List of security keys for JWT validation</returns>
    Task<IList<SecurityKey>> GetSigningKeysAsync();

    /// <summary>
    /// Get signing keys from the JWKS endpoint synchronously
    /// WARNING: This blocks the calling thread and should be used sparingly.
    /// Prefer GetSigningKeysAsync() for better performance.
    /// </summary>
    /// <returns>List of security keys for JWT validation</returns>
    IList<SecurityKey> GetSigningKeys();

    /// <summary>
    /// Initialize the client synchronously (blocks current thread)
    /// WARNING: This blocks the calling thread and should be used sparingly.
    /// Prefer InitializeAsync() or hosted service patterns for better performance.
    /// </summary>
    /// <returns>True if initialization succeeded</returns>
    bool Initialize();

    /// <summary>
    /// Load or refresh JSON Web Key Set from the identity server synchronously
    /// WARNING: This blocks the calling thread and should be used sparingly.
    /// Prefer LoadKeysAsync() for better performance.
    /// </summary>
    void LoadKeys();

    /// <summary>
    /// Verify if a JWT token is valid
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
    /// <returns>Token response</returns>
    /// <exception cref="InvalidOperationException">Thrown when client is not initialized or operation fails</exception>
    Task<TokenResponse> AdminUserSignupAsync(TUser user, string password);

    /// <summary>
    /// Sign in a user using OAuth2 password grant
    /// </summary>
    /// <param name="username">Username or email</param>
    /// <param name="password">Plain text password</param>
    /// <returns>Token response</returns>
    /// <exception cref="InvalidOperationException">Thrown when signin fails</exception>
    Task<TokenResponse> UserSigninAsync(string username, string password);

    /// <summary>
    /// Admin operation: Sign in as a user without password (requires admin client token)
    /// </summary>
    /// <param name="identifier">User ID or username</param>
    /// <returns>Token response</returns>
    /// <exception cref="InvalidOperationException">Thrown when client is not initialized or operation fails</exception>
    Task<TokenResponse> AdminUserSigninAsync(string identifier);

    /// <summary>
    /// Admin operation: Refresh an access token using a refresh token (requires admin client token)
    /// </summary>
    /// <param name="refreshToken">The refresh token to exchange for new access token</param>
    /// <returns>Token response with new access token</returns>
    /// <exception cref="InvalidOperationException">Thrown when client is not initialized or operation fails</exception>
    Task<TokenResponse> RefreshTokenAsync(string refreshToken);

/*
    /// <summary>
    /// User operation: Refresh an access token using OAuth2 refresh token grant
    /// </summary>
    /// <param name="refreshToken">The refresh token to exchange for new access token</param>
    /// <returns>Token response with new access token</returns>
    /// <exception cref="InvalidOperationException">Thrown when refresh operation fails</exception>
    Task<TokenResponse> UserRefreshTokenAsync(string refreshToken);
*/
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
    /// <exception cref="InvalidOperationException">Thrown when client is not initialized or operation fails</exception>
    Task<List<UserAttribute>> AdminGetUserSchemaAsync();

    /// <summary>
    /// Admin operation: Delete a user by ID or username
    /// </summary>
    /// <param name="request">Delete user request</param>
    /// <returns>True if successful</returns>
    /// <exception cref="InvalidOperationException">Thrown when client is not initialized or operation fails</exception>
    Task<bool> AdminDeleteUserAsync(AdminDeleteUserRequest request);

    /// <summary>
    /// Admin operation: Restore a deleted user by ID or username
    /// </summary>
    /// <param name="request">Restore user request</param>
    /// <returns>True if successful</returns>
    /// <exception cref="InvalidOperationException">Thrown when client is not initialized or operation fails</exception>
    Task<bool> AdminRestoreUserAsync(AdminRestoreUserRequest request);

    /// <summary>
    /// Admin operation: Reset user password by ID or username
    /// </summary>
    /// <param name="request">Reset password request</param>
    /// <returns>True if successful</returns>
    /// <exception cref="InvalidOperationException">Thrown when client is not initialized or operation fails</exception>
    Task<bool> AdminResetUserPasswordAsync(AdminResetUserPasswordRequest request);

    /// <summary>
    /// Admin operation: List users with pagination and filtering
    /// </summary>
    /// <param name="pageOptions">Pagination options</param>
    /// <param name="filter">Filter options</param>
    /// <returns>Paginated list of users</returns>
    /// <exception cref="InvalidOperationException">Thrown when client is not initialized or operation fails</exception>
    Task<PagedResponse<TUser>> AdminListUsersAsync(PageOptions pageOptions, UserFilterOptions? filter = null);

    /// <summary>
    /// Admin operation: Update multiple users
    /// </summary>
    /// <param name="users">List of users to update</param>
    /// <param name="onlyColumns">Only update specific columns</param>
    /// <returns>Count of updated users</returns>
    /// <exception cref="InvalidOperationException">Thrown when client is not initialized or operation fails</exception>
    Task<CountResponse<long>> AdminUpdateUsersAsync(List<TUser> users, params string[] onlyColumns);
}