using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Hellenic.Identity.SDK.Models;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Hellenic.Identity.SDK.Services;

/// <summary>
/// Generic Identity Client implementation that mirrors the Go SDK functionality
/// TUser allows any user model structure
/// </summary>
public class IdentityClient<TUser> : IIdentityClient<TUser> where TUser : class
{
    private readonly IdentityClientOptions _settings;
    private readonly ILogger<IdentityClient<TUser>> _logger;
    private readonly HttpClient _httpClient;
    private readonly JwtSecurityTokenHandler _tokenHandler;
    
    private IList<SecurityKey> _signingKeys = new List<SecurityKey>();
    private byte[]? _encryptionKeyBytes;

    public bool IsInitialized { get; private set; }

    public IdentityClient(
        IOptions<AppConfiguration> config,
        ILogger<IdentityClient<TUser>> logger,
        HttpClient httpClient)
    {
        _settings = config.Value.IdentityClient;
        _logger = logger;
        _httpClient = httpClient;
        _tokenHandler = new JwtSecurityTokenHandler();
        
        // Log client configuration (excluding sensitive data) - DEBUG level for initialization
        _logger.LogDebug("IdentityClient Configuration: BaseURL={BaseURL}, ClientID={ClientID}, DefaultScope={DefaultScope}, PasswordStrengthLevel={PasswordStrengthLevel}",
            _settings.BaseURL, _settings.ClientID, _settings.DefaultScope, _settings.PasswordStrengthLevel);
        
        // Set base URL for HTTP client
        _httpClient.BaseAddress = new Uri(_settings.BaseURL);
        
        // Parse encryption key
        if (!string.IsNullOrEmpty(_settings.EncryptionKey))
        {
            _encryptionKeyBytes = Convert.FromHexString(_settings.EncryptionKey);
            _logger.LogDebug("Encryption key configured (length: {Length} bytes)", _encryptionKeyBytes.Length);
        }
        else
        {
            _logger.LogWarning("No encryption key configured");
        }
    }

    public async Task<bool> InitializeAsync()
    {
        try
        {
            _logger.LogDebug("Initializing Identity Client...");
            
            // Load public keys from JWKS endpoint
            await LoadKeysAsync();
            
            // Verify client token is provided (required for initialization)
            if (string.IsNullOrEmpty(_settings.ClientToken))
            {
                _logger.LogDebug("ERR: Client token is required for client initialization");
                throw new InvalidOperationException("Client token is required for client initialization");
            }
            
            // Store client token for API calls
            _logger.LogDebug("Client token provided, client ready for admin operations");
            
            IsInitialized = true;
            _logger.LogDebug("Identity Client initialized successfully");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Failed to initialize Identity Client");
            return false;
        }
    }

    public async Task LoadKeysAsync()
    {
        try
        {
            _signingKeys = await GetSigningKeysAsync();
            _logger.LogDebug("Loaded {KeyCount} signing keys", _signingKeys.Count);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Failed to load keys from JWKS endpoint");
            throw;
        }
    }

    public async Task<IList<SecurityKey>> GetSigningKeysAsync()
    {
        try
        {
            var jwksUrl = $"{_settings.BaseURL}/.well-known/jwks.json";
            _logger.LogDebug("Loading keys from {JwksUrl}", jwksUrl);
            
            var response = await _httpClient.GetAsync(jwksUrl);
            response.EnsureSuccessStatusCode();
            
            var json = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("Raw JWKs response: {JwksJson}", json);
            
            var jwkSet = JsonSerializer.Deserialize<JwkSet>(json);
            
            if (jwkSet?.Keys != null)
            {
                _logger.LogDebug("Found {KeyCount} keys in JWKs", jwkSet.Keys.Count);
                foreach (var key in jwkSet.Keys)
                {
                    _logger.LogDebug("JWK Key: ID={KeyId}, Type={KeyType}, Use={Use}, Algorithm={Algorithm}, Curve={Curve}",
                        key.KeyId, key.KeyType, key.Use, key.Algorithm, key.Curve);
                }
            }
            else
            {
                _logger.LogWarning("No keys found in JWKs response");
            }
            
            return ConvertJwkSetToSecurityKeys(jwkSet);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Failed to get signing keys from JWKS endpoint");
            throw;
        }
    }

    public bool Initialize()
    {
        _logger.LogWarning("Using synchronous Initialize() - this blocks the current thread. Consider using InitializeAsync() or a hosted service pattern for better performance.");
        
        try
        {
            return InitializeAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Synchronous initialization failed");
            return false;
        }
    }

    public void LoadKeys()
    {
        _logger.LogWarning("Using synchronous LoadKeys() - this blocks the current thread. Consider using LoadKeysAsync() for better performance.");
        
        try
        {
            LoadKeysAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Synchronous key loading failed");
            throw;
        }
    }

    public IList<SecurityKey> GetSigningKeys()
    {
        _logger.LogWarning("Using synchronous GetSigningKeys() - this blocks the current thread. Consider using GetSigningKeysAsync() for better performance.");
        
        try
        {
            return GetSigningKeysAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Synchronous get signing keys failed");
            throw;
        }
    }

    public async Task<bool> VerifyTokenAsync(string token)
    {
        try
        {
            // First decode the token to check the algorithm
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(token);
            
            // Check if this is an EdDSA token
            if (jsonToken.Header.Alg?.Equals("EdDSA", StringComparison.OrdinalIgnoreCase) == true)
            {
                return VerifyEdDsaToken(token, jsonToken);
            }
            
            // Use standard validation for other algorithms (RSA, ECDSA)
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false, // Will be validated by the identity server's keys
                ValidateAudience = false, // Will be validated by the identity server's keys
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                // IssuerSigningKeys = _signingKeys.Where(k => !(k is EdDsaSecurityKey)),
                IssuerSigningKeys = _signingKeys,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var result = await _tokenHandler.ValidateTokenAsync(token, validationParameters);
            return result.IsValid;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Token validation failed");
            return false;
        }
    }

    private bool VerifyEdDsaToken(string token, JwtSecurityToken jsonToken)
    {
        try
        {
            // Find the EdDSA key by kid
            var kid = jsonToken.Header.Kid;
            
            // Find EdDSA key efficiently - no logging on hot path for performance
            var edDsaKeys = _signingKeys.OfType<EdDsaSecurityKey>().ToList();
            var edDsaKey = edDsaKeys.FirstOrDefault(k => k.KeyId == kid);
                
            if (edDsaKey == null)
            {
                // Only log key mismatch warnings when necessary for debugging
                _logger.LogWarning("No EdDSA key found for kid: {Kid}. Available EdDSA key IDs: [{AvailableKeyIds}]",
                    kid, string.Join(", ", edDsaKeys.Select(k => k.KeyId)));
                return false;
            }

            // Validate token lifetime - no logging on valid tokens for performance
            var now = DateTimeOffset.UtcNow;
            if (jsonToken.ValidTo < now.DateTime)
            {
                return false; // Token expired - no logging for performance
            }
            
            if (jsonToken.ValidFrom > now.DateTime)
            {
                return false; // Token not yet valid - no logging for performance
            }

            // Verify EdDSA signature
            return VerifyEdDsaSignature(token, edDsaKey);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "EdDSA token validation failed");
            return false;
        }
    }

    private bool VerifyEdDsaSignature(string token, EdDsaSecurityKey edDsaKey)
    {
        try
        {
            // Split JWT token into parts
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                return false; // Invalid JWT format - no logging for performance
            }

            // The message to verify is: header.payload
            var message = $"{parts[0]}.{parts[1]}";
            var messageBytes = Encoding.UTF8.GetBytes(message);
            
            // Decode the signature
            var signature = Base64UrlEncoder.DecodeBytes(parts[2]);
            
            if (signature.Length != 64)
            {
                return false; // Invalid signature length - no logging for performance
            }

            // Use pre-created BouncyCastle Ed25519 public key parameter for performance
            var verifier = new Ed25519Signer();
            verifier.Init(false, edDsaKey.PublicKeyParam);
            verifier.BlockUpdate(messageBytes, 0, messageBytes.Length);
            
            return verifier.VerifySignature(signature);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "EdDSA signature verification failed");
            return false;
        }
    }

    public T? IntrospectToken<T>(string token) where T : class
    {
        try
        {
            // Decode without verification (like jwt.Decode in Go SDK)
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            
            // Convert claims to JSON and deserialize to T
            var claimsDict = jwtToken.Claims.ToDictionary(c => c.Type, c => c.Value);
            var json = JsonSerializer.Serialize(claimsDict);
            return JsonSerializer.Deserialize<T>(json);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to introspect token");
            return null;
        }
    }

    public async Task<T?> TokenIntrospectAsync<T>(string accessToken) where T : class
    {
        try
        {
            var request = new { access_token = accessToken };
            _logger.LogDebug("Token introspection request body: {RequestBody}",
                JsonSerializer.Serialize(request));
            
            var response = await _httpClient.PostAsJsonAsync("/oauth2/token/introspect", request);
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<T>(json);
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogWarning("Token introspection failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Token introspection failed");
            return null;
        }
    }

    public async Task<TokenResponse> AdminUserSignupAsync(TUser user, string password)
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException("Client not initialized");
        }
        
        // Validate password first - let validation exceptions bubble up
        ValidatePassword(password);
        
        try
        {
            var encryptedPassword = EncryptPassword(password);
            
            // Merge user data with encrypted password (similar to Go SDK)
            var userJson = JsonSerializer.Serialize(user);
            var passwordJson = JsonSerializer.Serialize(new { password = encryptedPassword });
            
            var userDict = JsonSerializer.Deserialize<Dictionary<string, object>>(userJson) ?? new();
            var passwordDict = JsonSerializer.Deserialize<Dictionary<string, object>>(passwordJson) ?? new();
            
            foreach (var kvp in passwordDict)
            {
                userDict[kvp.Key] = kvp.Value;
            }
            
            var request = JsonSerializer.Serialize(userDict);
            
            _logger.LogDebug("Admin signup request body: {RequestBody}", request);
            
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-Token", _settings.ClientToken);
            
            var response = await _httpClient.PostAsync("/u/signup",
                new StringContent(request, Encoding.UTF8, "application/json"));
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);
                return tokenResponse ?? throw new InvalidOperationException("Failed to deserialize token response");
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("ERR: Admin signup failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            throw new InvalidOperationException($"Admin signup failed with status {response.StatusCode}: {errorContent}");
        }
        catch (Exception ex) when (!(ex is InvalidOperationException || ex is ArgumentException))
        {
            _logger.LogDebug(ex, "ERR: Admin user signup failed");
            throw new InvalidOperationException("Admin user signup failed", ex);
        }
    }

    public async Task<TokenResponse> UserSigninAsync(string username, string password)
    {
        try
        {
            var encryptedPassword = EncryptPassword(password);
            
            // Use OAuth2 password credentials flow (like Go SDK)
            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = username,
                ["password"] = encryptedPassword
            };
            
            // Add required OAuth2 client credentials
            if (!string.IsNullOrEmpty(_settings.ClientID))
            {
                parameters["client_id"] = _settings.ClientID;
            }
            
            if (!string.IsNullOrEmpty(_settings.ClientSecret))
            {
                parameters["client_secret"] = _settings.ClientSecret;
            }
            
            if (!string.IsNullOrEmpty(_settings.DefaultScope))
            {
                parameters["scope"] = _settings.DefaultScope;
            }
            
            _logger.LogDebug("User signin request parameters: {Parameters}",
                string.Join(", ", parameters.Select(kvp => $"{kvp.Key}={kvp.Value}")));
            
            var content = new FormUrlEncodedContent(parameters);
            var response = await _httpClient.PostAsync("/oauth2/token", content);
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);
                return tokenResponse ?? throw new InvalidOperationException("Failed to deserialize token response");
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("ERR: User signin failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            throw new InvalidOperationException($"User signin failed with status {response.StatusCode}: {errorContent}");
        }
        catch (Exception ex) when (!(ex is InvalidOperationException))
        {
            _logger.LogDebug(ex, "ERR: User signin failed");
            throw new InvalidOperationException("User signin failed", ex);
        }
    }

    public async Task<TokenResponse> AdminUserSigninAsync(string identifier)
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException("Client not initialized");
        }
        
        try
        {
            var request = new { identifier };
            _logger.LogDebug("Admin signin request body: {RequestBody}",
                JsonSerializer.Serialize(request));
            
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-Token", _settings.ClientToken);
            
            var response = await _httpClient.PostAsJsonAsync("/u/signin", request);
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);
                return tokenResponse ?? throw new InvalidOperationException("Failed to deserialize token response");
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("ERR: Admin user signin failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            throw new InvalidOperationException($"Admin user signin failed with status {response.StatusCode}: {errorContent}");
        }
        catch (Exception ex) when (!(ex is InvalidOperationException))
        {
            _logger.LogDebug(ex, "ERR: Admin user signin failed");
            throw new InvalidOperationException("Admin user signin failed", ex);
        }
    }

    public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException("Client not initialized");
        }
        
        try
        {
            var request = new { refresh_token = refreshToken };
            _logger.LogDebug("Admin refresh token request body: {RequestBody}",
                JsonSerializer.Serialize(request));
            
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-Token", _settings.ClientToken);
            
            var response = await _httpClient.PostAsJsonAsync("/u/refresh", request);
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);
                return tokenResponse ?? throw new InvalidOperationException("Failed to deserialize token response");
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("ERR: Admin refresh token failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            throw new InvalidOperationException($"Admin refresh token failed with status {response.StatusCode}: {errorContent}");
        }
        catch (Exception ex) when (!(ex is InvalidOperationException))
        {
            _logger.LogDebug(ex, "ERR: Admin refresh token failed");
            throw new InvalidOperationException("Admin refresh token failed", ex);
        }
    }

    public async Task<TokenResponse> AdminEnrichTokenAsync(string accessToken, object extraClaims)
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException("Client not initialized");
        }
        
        try
        {
            _logger.LogDebug("Starting admin enrich token operation");

            // Create request body with the expected structure
            var requestBody = new
            {
                access_token = accessToken,
                extra_claims = extraClaims
            };

            var requestJson = JsonSerializer.Serialize(requestBody);
            _logger.LogDebug("Admin enrich token request body: {RequestBody}", requestJson);
            
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-Token", _settings.ClientToken);
            
            var response = await _httpClient.PostAsync("/u/enrich",
                new StringContent(requestJson, Encoding.UTF8, "application/json"));
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);
                _logger.LogDebug("Admin enrich token operation completed successfully");
                return tokenResponse ?? throw new InvalidOperationException("Failed to deserialize token response");
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("ERR: Admin enrich token failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            throw new InvalidOperationException($"Admin enrich token failed with status {response.StatusCode}: {errorContent}");
        }
        catch (Exception ex) when (!(ex is InvalidOperationException))
        {
            _logger.LogDebug(ex, "ERR: Admin enrich token failed");
            throw new InvalidOperationException("Admin enrich token failed", ex);
        }
    }

/*
    public async Task<TokenResponse> UserRefreshTokenAsync(string refreshToken)
    {
        try
        {
            // Use OAuth2 refresh_token grant flow (like Go SDK)
            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken
            };
            
            // Add required OAuth2 client credentials
            if (!string.IsNullOrEmpty(_settings.ClientID))
            {
                parameters["client_id"] = _settings.ClientID;
            }
            
            if (!string.IsNullOrEmpty(_settings.ClientSecret))
            {
                parameters["client_secret"] = _settings.ClientSecret;
            }
            
            if (!string.IsNullOrEmpty(_settings.DefaultScope))
            {
                parameters["scope"] = _settings.DefaultScope;
            }
            
            _logger.LogDebug("User refresh token request parameters: {Parameters}",
                string.Join(", ", parameters.Select(kvp => $"{kvp.Key}={kvp.Value}")));
            
            var content = new FormUrlEncodedContent(parameters);
            var response = await _httpClient.PostAsync("/oauth2/token", content);
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);
                return tokenResponse ?? throw new InvalidOperationException("Failed to deserialize token response");
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("ERR: User refresh token failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            throw new InvalidOperationException($"User refresh token failed with status {response.StatusCode}: {errorContent}");
        }
        catch (Exception ex) when (!(ex is InvalidOperationException))
        {
            _logger.LogDebug(ex, "ERR: User refresh token failed");
            throw new InvalidOperationException("User refresh token failed", ex);
        }
    }
*/
    public string EncryptPassword(string plainPassword)
    {
        if (_encryptionKeyBytes == null)
        {
            throw new InvalidOperationException("Encryption key not configured");
        }
        
        try
        {
            using var aes = new AesGcm(_encryptionKeyBytes, 16); // 128-bit tag size
            
            var plainBytes = Encoding.UTF8.GetBytes(plainPassword);
            var nonce = new byte[12]; // 96-bit nonce for AES-GCM
            var ciphertext = new byte[plainBytes.Length];
            var tag = new byte[16]; // 128-bit authentication tag
            
            RandomNumberGenerator.Fill(nonce);
            
            aes.Encrypt(nonce, plainBytes, ciphertext, tag);
            
            // Combine nonce + ciphertext + tag and encode as hex (like Go SDK)
            var combined = new byte[nonce.Length + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(nonce, 0, combined, 0, nonce.Length);
            Buffer.BlockCopy(ciphertext, 0, combined, nonce.Length, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, combined, nonce.Length + ciphertext.Length, tag.Length);
            
            return Convert.ToHexString(combined).ToLowerInvariant();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Password encryption failed");
            throw new InvalidOperationException("Failed to encrypt password", ex);
        }
    }

    public string DecryptPassword(string encryptedPassword)
    {
        if (_encryptionKeyBytes == null)
        {
            throw new InvalidOperationException("Encryption key not configured");
        }
        
        try
        {
            var combined = Convert.FromHexString(encryptedPassword);
            
            var nonce = new byte[12];
            var tag = new byte[16];
            var ciphertext = new byte[combined.Length - nonce.Length - tag.Length];
            
            Buffer.BlockCopy(combined, 0, nonce, 0, nonce.Length);
            Buffer.BlockCopy(combined, nonce.Length, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(combined, nonce.Length + ciphertext.Length, tag, 0, tag.Length);
            
            using var aes = new AesGcm(_encryptionKeyBytes, 16); // 128-bit tag size
            var plainBytes = new byte[ciphertext.Length];
            
            aes.Decrypt(nonce, ciphertext, tag, plainBytes);
            
            return Encoding.UTF8.GetString(plainBytes);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Password decryption failed");
            throw new InvalidOperationException("Failed to decrypt password", ex);
        }
    }

    public async Task<List<UserAttribute>> AdminGetUserSchemaAsync()
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException("Client not initialized");
        }
        
        try
        {
            _logger.LogDebug("Getting user schema...");
            
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-Token", _settings.ClientToken);
            
            var response = await _httpClient.GetAsync("/u/schema");
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var schema = JsonSerializer.Deserialize<List<UserAttribute>>(json);
                return schema ?? throw new InvalidOperationException("Failed to deserialize user schema response");
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("ERR: Get user schema failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            throw new InvalidOperationException($"Get user schema failed with status {response.StatusCode}: {errorContent}");
        }
        catch (Exception ex) when (!(ex is InvalidOperationException))
        {
            _logger.LogDebug(ex, "ERR: Get user schema failed");
            throw new InvalidOperationException("Get user schema failed", ex);
        }
    }

    public async Task<bool> AdminDeleteUserAsync(AdminDeleteUserRequest request)
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException("Client not initialized");
        }
        
        try
        {
            _logger.LogDebug("Deleting user: {Identifier} (soft: {Soft})", request.Identifier, request.Soft);
            
            var queryParams = new List<string> { $"identifier={Uri.EscapeDataString(request.Identifier)}" };
            if (request.Soft.HasValue && request.Soft.Value)
            {
                queryParams.Add("soft=true");
            }
            
            var queryString = string.Join("&", queryParams);
            var url = $"/u?{queryString}";
            
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-Token", _settings.ClientToken);
            
            var response = await _httpClient.DeleteAsync(url);
            
            if (response.StatusCode == System.Net.HttpStatusCode.NoContent)
            {
                _logger.LogDebug("User deleted successfully: {Identifier}", request.Identifier);
                return true;
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogWarning("Delete user failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Admin delete user failed");
            return false;
        }
    }

    public async Task<bool> AdminRestoreUserAsync(AdminRestoreUserRequest request)
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException("Client not initialized");
        }
        
        try
        {
            _logger.LogDebug("Restoring user: {Identifier}", request.Identifier);
            
            var requestJson = JsonSerializer.Serialize(request);
            _logger.LogDebug("Admin restore user request body: {RequestBody}", requestJson);
            
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-Token", _settings.ClientToken);
            
            var response = await _httpClient.PostAsync("/u/restore",
                new StringContent(requestJson, Encoding.UTF8, "application/json"));
            
            if (response.StatusCode == System.Net.HttpStatusCode.NoContent)
            {
                _logger.LogDebug("User restored successfully: {Identifier}", request.Identifier);
                return true;
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogWarning("Restore user failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Admin restore user failed");
            return false;
        }
    }

    public async Task<bool> AdminResetUserPasswordAsync(AdminResetUserPasswordRequest request)
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException("Client not initialized");
        }
        
        // Validate password first - let validation exceptions bubble up
        ValidatePassword(request.Password);
        
        try
        {
            _logger.LogDebug("Resetting password for user: {Identifier}", request.Identifier);
            
            var encryptedPassword = EncryptPassword(request.Password);
            
            // Step 1: Request password reset token
            var requestPasswordReset = new RequestPasswordResetRequest
            {
                Identifier = request.Identifier
            };
            
            var requestJson = JsonSerializer.Serialize(requestPasswordReset);
            _logger.LogDebug("Request password reset token body: {RequestBody}", requestJson);
            
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-Token", _settings.ClientToken);
            
            var tokenResponse = await _httpClient.PostAsync("/u/request-password-reset",
                new StringContent(requestJson, Encoding.UTF8, "application/json"));
            
            if (!tokenResponse.IsSuccessStatusCode)
            {
                var errorContent = await tokenResponse.Content.ReadAsStringAsync();
                _logger.LogWarning("Request password reset token failed: {StatusCode} - Response: {ErrorContent}",
                    tokenResponse.StatusCode, errorContent);
                return false;
            }
            
            var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
            var tokenResponseObj = JsonSerializer.Deserialize<PasswordResetTokenResponse>(tokenJson);
            
            if (tokenResponseObj?.Token == null)
            {
                _logger.LogDebug("ERR: Password reset token is null");
                return false;
            }
            
            // Step 2: Confirm password reset with new encrypted password
            var confirmRequest = new PasswordResetConfirmRequest
            {
                Token = tokenResponseObj.Token,
                NewPassword = encryptedPassword
            };
            
            var confirmJson = JsonSerializer.Serialize(confirmRequest);
            _logger.LogDebug("Confirm password reset request body: {RequestBody}", confirmJson);
            
            var confirmResponse = await _httpClient.PostAsync("/u/confirm-password-reset",
                new StringContent(confirmJson, Encoding.UTF8, "application/json"));
            
            if (confirmResponse.StatusCode == System.Net.HttpStatusCode.NoContent)
            {
                _logger.LogDebug("Password reset successfully for user: {Identifier}", request.Identifier);
                return true;
            }
            
            // Read and log the error response body for better debugging
            var confirmErrorContent = await confirmResponse.Content.ReadAsStringAsync();
            _logger.LogWarning("Confirm password reset failed: {StatusCode} - Response: {ErrorContent}",
                confirmResponse.StatusCode, confirmErrorContent);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ERR: Admin reset user password failed");
            return false;
        }
    }

    public async Task<PagedResponse<TUser>> AdminListUsersAsync(PageOptions pageOptions, UserFilterOptions? filter = null)
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException("Client not initialized");
        }
        
        try
        {
            _logger.LogDebug("Listing users with page: {Page}, limit: {Limit}", pageOptions.Page, pageOptions.Limit);
            
            var requestBody = filter ?? new UserFilterOptions();
            var requestJson = JsonSerializer.Serialize(requestBody);
            _logger.LogDebug("Admin list users request body: {RequestBody}", requestJson);
            
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-Token", _settings.ClientToken);
            
            var queryParams = new List<string>
            {
                $"page={pageOptions.Page}",
                $"limit={pageOptions.Limit}",
                $"order={pageOptions.Order}"
            };
            
            if (!string.IsNullOrEmpty(pageOptions.Sort))
            {
                queryParams.Add($"sort={pageOptions.Sort}");
            }
            
            var queryString = string.Join("&", queryParams);
            var url = $"/u/list?{queryString}";
            
            var response = await _httpClient.PostAsync(url,
                new StringContent(requestJson, Encoding.UTF8, "application/json"));
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var pagedResponse = JsonSerializer.Deserialize<PagedResponse<TUser>>(json);
                return pagedResponse ?? throw new InvalidOperationException("Failed to deserialize users list response");
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("ERR: List users failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            throw new InvalidOperationException($"List users failed with status {response.StatusCode}: {errorContent}");
        }
        catch (Exception ex) when (!(ex is InvalidOperationException))
        {
            _logger.LogDebug(ex, "ERR: Admin list users failed");
            throw new InvalidOperationException("Admin list users failed", ex);
        }
    }

    public async Task<CountResponse<long>> AdminUpdateUsersAsync(List<TUser> users, params string[] onlyColumns)
    {
        if (!IsInitialized)
        {
            throw new InvalidOperationException("Client not initialized");
        }
        
        try
        {
            _logger.LogDebug("Updating {UserCount} users", users.Count);
            
            var requestJson = JsonSerializer.Serialize(users);
            _logger.LogDebug("Admin update users request body: {RequestBody}", requestJson);
            
            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("X-Token", _settings.ClientToken);
            
            var url = "/u";
            if (onlyColumns?.Length > 0)
            {
                var columnsParam = string.Join(",", onlyColumns);
                url += $"?columns={Uri.EscapeDataString(columnsParam)}";
            }
            
            var response = await _httpClient.PutAsync(url,
                new StringContent(requestJson, Encoding.UTF8, "application/json"));
            
            if (response.IsSuccessStatusCode)
            {
                var json = await response.Content.ReadAsStringAsync();
                var countResponse = JsonSerializer.Deserialize<CountResponse<long>>(json);
                return countResponse ?? throw new InvalidOperationException("Failed to deserialize update users response");
            }
            
            // Read and log the error response body for better debugging
            var errorContent = await response.Content.ReadAsStringAsync();
            _logger.LogDebug("ERR: Update users failed: {StatusCode} - Response: {ErrorContent}",
                response.StatusCode, errorContent);
            throw new InvalidOperationException($"Update users failed with status {response.StatusCode}: {errorContent}");
        }
        catch (Exception ex) when (!(ex is InvalidOperationException))
        {
            _logger.LogDebug(ex, "ERR: Admin update users failed");
            throw new InvalidOperationException("Admin update users failed", ex);
        }
    }

    private List<SecurityKey> ConvertJwkSetToSecurityKeys(JwkSet? jwkSet)
    {
        var keys = new List<SecurityKey>();
        
        if (jwkSet?.Keys == null) return keys;
        
        foreach (var jwk in jwkSet.Keys)
        {
            try
            {
                SecurityKey? key = jwk.KeyType.ToUpper() switch
                {
                    "RSA" => ConvertRsaJwkToSecurityKey(jwk),
                    "EC" => ConvertEcJwkToSecurityKey(jwk),
                    "OKP" => ConvertOkpJwkToSecurityKey(jwk),
                    _ => null
                };
                
                if (key != null)
                {
                    key.KeyId = jwk.KeyId;
                    keys.Add(key);
                    _logger.LogDebug("Successfully converted JWK {KeyId} ({KeyType}) to SecurityKey {SecurityKeyType}",
                        jwk.KeyId, jwk.KeyType, key.GetType().Name);
                }
                else
                {
                    _logger.LogWarning("Failed to convert JWK {KeyId} ({KeyType}) - key is null",
                        jwk.KeyId, jwk.KeyType);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to convert JWK {KeyId} to SecurityKey", jwk.KeyId);
            }
        }
        
        return keys;
    }

    private SecurityKey? ConvertRsaJwkToSecurityKey(JwkKey jwk)
    {
        if (string.IsNullOrEmpty(jwk.N) || string.IsNullOrEmpty(jwk.E))
            return null;
            
        using var rsa = RSA.Create();
        var parameters = new RSAParameters
        {
            Modulus = Base64UrlEncoder.DecodeBytes(jwk.N),
            Exponent = Base64UrlEncoder.DecodeBytes(jwk.E)
        };
        
        rsa.ImportParameters(parameters);
        return new RsaSecurityKey(rsa.ExportParameters(false));
    }

    private SecurityKey? ConvertEcJwkToSecurityKey(JwkKey jwk)
    {
        if (string.IsNullOrEmpty(jwk.X) || string.IsNullOrEmpty(jwk.Y) || string.IsNullOrEmpty(jwk.Curve))
            return null;
            
        using var ecdsa = ECDsa.Create();
        var curve = jwk.Curve switch
        {
            "P-256" => ECCurve.NamedCurves.nistP256,
            "P-384" => ECCurve.NamedCurves.nistP384,
            "P-521" => ECCurve.NamedCurves.nistP521,
            _ => throw new NotSupportedException($"Curve {jwk.Curve} not supported")
        };
        
        var parameters = new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = Base64UrlEncoder.DecodeBytes(jwk.X),
                Y = Base64UrlEncoder.DecodeBytes(jwk.Y)
            }
        };
        
        ecdsa.ImportParameters(parameters);
        return new ECDsaSecurityKey(ecdsa);
    }

    private SecurityKey? ConvertOkpJwkToSecurityKey(JwkKey jwk)
    {
        if (string.IsNullOrEmpty(jwk.X) || jwk.Curve != "Ed25519")
            return null;
            
        try
        {
            // For Ed25519, create a custom security key that can validate EdDSA signatures
            var publicKeyBytes = Base64UrlEncoder.DecodeBytes(jwk.X);
            return new EdDsaSecurityKey(publicKeyBytes, jwk.KeyId ?? "unknown");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to create EdDSA key from JWK {KeyId}", jwk.KeyId);
            return null;
        }
    }

    private void ValidatePassword(string password)
    {
        var minLength = _settings.PasswordStrengthLevel switch
        {
            "very weak" => 4,
            "weak" => 6,
            "medium" => 8,
            "strong" => 10,
            "very strong" => 12,
            _ => 8
        };
        
        if (password.Length < minLength)
        {
            throw new ArgumentException($"Password must be at least {minLength} characters long");
        }
    }
}

/// <summary>
/// Custom EdDSA security key for Ed25519 signature validation
/// </summary>
public class EdDsaSecurityKey : SecurityKey
{
    private readonly byte[] _publicKey;
    private readonly Ed25519PublicKeyParameters _publicKeyParam;
    
    public EdDsaSecurityKey(byte[] publicKey, string keyId)
    {
        _publicKey = publicKey;
        KeyId = keyId;
        
        // Pre-create the BouncyCastle public key parameter for performance
        _publicKeyParam = new Ed25519PublicKeyParameters(publicKey, 0);
    }
    
    public override int KeySize => 256;
    
    public byte[] PublicKey => _publicKey;
    
    public Ed25519PublicKeyParameters PublicKeyParam => _publicKeyParam;
}