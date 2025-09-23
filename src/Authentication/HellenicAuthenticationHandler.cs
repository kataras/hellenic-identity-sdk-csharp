using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication.Internal;
using Hellenic.Identity.SDK.Services;

namespace Hellenic.Identity.SDK.Authentication;

/// <summary>
/// Custom authentication handler for EdDSA tokens from Hellenic Identity Server
/// This replaces the standard JwtBearer authentication that doesn't support EdDSA.
/// </summary>
public class HellenicAuthenticationHandler<TUser> : AuthenticationHandler<HellenicAuthenticationOptions> where TUser : class
{
    private readonly IHellenicAuthenticationService _authService;

    public HellenicAuthenticationHandler(
        IOptionsMonitor<HellenicAuthenticationOptions> options,
        ILoggerFactory logger,
        IHellenicAuthenticationService authService)
        : base(options, logger, UrlEncoder.Default, new SystemClock())
    {
        _authService = authService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authHeader = Request.Headers["Authorization"].FirstOrDefault();
        string? token = null;

        try
        {
            // 1. OnMessageReceived event
            var messageReceivedContext = new MessageReceivedContext(Context, Scheme, Options)
            {
                AuthorizationHeader = authHeader
            };

            // Extract token from Authorization header
            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                token = authHeader.Substring("Bearer ".Length);
                messageReceivedContext.Token = token;
            }

            await Options.Events.OnMessageReceived(messageReceivedContext);

            // Check if the event handler handled the authentication
            if (messageReceivedContext.Result != null)
            {
                return messageReceivedContext.Result;
            }

            // Use the token from the context (might have been modified by event handler)
            var contextToken = messageReceivedContext.Token;
            var contextAuthHeader = !string.IsNullOrEmpty(contextToken) ? $"Bearer {contextToken}" : authHeader;

            // 2. Perform authentication
            var authenticateResult = await _authService.AuthenticateAsync(contextAuthHeader);

            if (authenticateResult.Succeeded)
            {
                // 3. OnTokenValidated event
                var tokenValidatedContext = new TokenValidatedContext(Context, Scheme, Options)
                {
                    Token = contextToken,
                    Principal = authenticateResult.Principal
                };

                await Options.Events.OnTokenValidated(tokenValidatedContext);

                // Check if the event handler modified the result
                if (tokenValidatedContext.Result != null)
                {
                    return tokenValidatedContext.Result;
                }

                // Update the principal if it was modified in the event
                if (tokenValidatedContext.Principal != authenticateResult.Principal)
                {
                    var ticket = new AuthenticationTicket(tokenValidatedContext.Principal, authenticateResult.Properties, Scheme.Name);
                    return AuthenticateResult.Success(ticket);
                }

                return authenticateResult;
            }
            else
            {
                // 4. OnAuthenticationFailed event
                var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
                {
                    Token = contextToken,
                    Exception = new InvalidOperationException(authenticateResult.Failure?.Message ?? "Authentication failed")
                };

                await Options.Events.OnAuthenticationFailed(authenticationFailedContext);

                // Check if the event handler handled the failure
                if (authenticationFailedContext.Result != null)
                {
                    return authenticationFailedContext.Result;
                }

                return authenticateResult;
            }
        }
        catch (Exception ex)
        {
            // OnAuthenticationFailed event for exceptions
            var authenticationFailedContext = new AuthenticationFailedContext(Context, Scheme, Options)
            {
                Token = token,
                Exception = ex
            };

            await Options.Events.OnAuthenticationFailed(authenticationFailedContext);

            // Check if the event handler handled the exception
            if (authenticationFailedContext.Result != null)
            {
                return authenticationFailedContext.Result;
            }

            // Only log critical authentication exceptions - not performance-impacting warnings
            // Logger.LogError(ex, "Authentication failed with exception");
            return AuthenticateResult.Fail(ex);
        }
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties? properties)
    {
        var challengeContext = new ChallengeContext(Context, Scheme, Options, properties)
        {
            AuthenticateFailure = AuthenticateResult.Fail("Authentication required")
        };

        await Options.Events.OnChallenge(challengeContext);

        if (challengeContext.Handled)
        {
            return;
        }

        Response.StatusCode = 401;
        Response.Headers.Append("WWW-Authenticate", "Bearer");
    }

    protected override async Task HandleForbiddenAsync(AuthenticationProperties? properties)
    {
        var forbiddenContext = new ForbiddenContext(Context, Scheme, Options)
        {
            Principal = Context.User
        };

        await Options.Events.OnForbidden(forbiddenContext);

        if (forbiddenContext.Result != null)
        {
            // Allow the event to override the default behavior
            return;
        }

        Response.StatusCode = 403;
    }
}

/// <summary>
/// Options for Hellenic authentication
/// </summary>
public class HellenicAuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Events for handling authentication lifecycle
    /// </summary>
    public new HellenicAuthenticationEvents Events { get; set; } = new HellenicAuthenticationEvents();

    // You can add custom options here if needed
    // For example: issuer validation, audience validation, etc.
    public string? ExpectedIssuer { get; set; }
    public string? ExpectedAudience { get; set; }
}

/// <summary>
/// Events for Hellenic authentication - mirrors JwtBearerEvents
/// </summary>
public class HellenicAuthenticationEvents
{
    /// <summary>
    /// A delegate assigned to this property will be invoked when the message is received.
    /// </summary>
    public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// A delegate assigned to this property will be invoked when the token has passed validation and a ClaimsIdentity has been generated.
    /// </summary>
    public Func<TokenValidatedContext, Task> OnTokenValidated { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// A delegate assigned to this property will be invoked when authentication fails.
    /// </summary>
    public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// A delegate assigned to this property will be invoked before a challenge is sent back to the caller.
    /// </summary>
    public Func<ChallengeContext, Task> OnChallenge { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// A delegate assigned to this property will be invoked when the user is forbidden from accessing the resource.
    /// </summary>
    public Func<ForbiddenContext, Task> OnForbidden { get; set; } = context => Task.CompletedTask;
}

/// <summary>
/// Context for message received event
/// </summary>
public class MessageReceivedContext : ResultContext<HellenicAuthenticationOptions>
{
    public MessageReceivedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        HellenicAuthenticationOptions options)
        : base(context, scheme, options) { }

    /// <summary>
    /// Bearer token from Authorization header
    /// </summary>
    public string? Token { get; set; }

    /// <summary>
    /// Raw Authorization header value
    /// </summary>
    public string? AuthorizationHeader { get; set; }
}

/// <summary>
/// Context for token validated event
/// </summary>
public class TokenValidatedContext : ResultContext<HellenicAuthenticationOptions>
{
    public TokenValidatedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        HellenicAuthenticationOptions options)
        : base(context, scheme, options) { }

    /// <summary>
    /// The JWT token that was validated
    /// </summary>
    public string? Token { get; set; }

    /// <summary>
    /// Claims principal created from the token
    /// </summary>
    public new ClaimsPrincipal? Principal { get; set; }
}

/// <summary>
/// Context for authentication failed event
/// </summary>
public class AuthenticationFailedContext : ResultContext<HellenicAuthenticationOptions>
{
    public AuthenticationFailedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        HellenicAuthenticationOptions options)
        : base(context, scheme, options) { }

    /// <summary>
    /// Exception that caused the authentication failure
    /// </summary>
    public Exception? Exception { get; set; }

    /// <summary>
    /// The token that failed validation (if available)
    /// </summary>
    public string? Token { get; set; }
}

/// <summary>
/// Context for challenge event
/// </summary>
public class ChallengeContext : PropertiesContext<HellenicAuthenticationOptions>
{
    public ChallengeContext(
        HttpContext context,
        AuthenticationScheme scheme,
        HellenicAuthenticationOptions options,
        AuthenticationProperties? properties)
        : base(context, scheme, options, properties) { }

    /// <summary>
    /// Any failures encountered during authentication
    /// </summary>
    public AuthenticateResult? AuthenticateFailure { get; set; }

    /// <summary>
    /// If true, will skip the default logic for this challenge
    /// </summary>
    public bool Handled { get; set; }
}

/// <summary>
/// Context for forbidden event
/// </summary>
public class ForbiddenContext : ResultContext<HellenicAuthenticationOptions>
{
    public ForbiddenContext(
        HttpContext context,
        AuthenticationScheme scheme,
        HellenicAuthenticationOptions options)
        : base(context, scheme, options) { }

    /// <summary>
    /// The authenticated principal that was forbidden access
    /// </summary>
    public new ClaimsPrincipal? Principal { get; set; }
}