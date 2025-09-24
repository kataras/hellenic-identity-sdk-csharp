using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Hellenic.Identity.SDK.Authentication;
using Hellenic.Identity.SDK.Models;
using Hellenic.Identity.SDK.Services;

namespace Hellenic.Identity.SDK.Extensions;

/// <summary>
/// Extension methods for adding Hellenic Authentication to the DI container
/// </summary>
public static class HellenicAuthenticationExtensions
{
    /// <summary>
    /// The default authentication scheme name used by Hellenic Authentication
    /// </summary>
    public const string DefaultScheme = "Hellenic";

    /// <summary>
    /// Adds complete Hellenic Authentication with EdDSA support using the default scheme name "Hellenic".
    /// This method registers everything needed: IdentityClient, AuthenticationService, Handler, and initializes JWKS keys.
    /// </summary>
    /// <typeparam name="TUser">The user model type that represents your application's user structure</typeparam>
    /// <param name="services">The service collection to add services to</param>
    /// <param name="configureOptions">Optional configuration for authentication options (events, validation settings, etc.)</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddHellenicAuthentication<TUser>(
        this IServiceCollection services,
        Action<HellenicAuthenticationOptions>? configureOptions = null)
        where TUser : class
    {
        return services.AddHellenicAuthentication<TUser>(DefaultScheme, configureOptions);
    }

    /// <summary>
    /// Adds complete Hellenic Authentication with EdDSA support using a custom authentication scheme name.
    /// This method registers everything needed: IdentityClient, AuthenticationService, Handler, and initializes JWKS keys.
    /// </summary>
    /// <typeparam name="TUser">The user model type that represents your application's user structure</typeparam>
    /// <param name="services">The service collection to add services to</param>
    /// <param name="authenticationScheme">The authentication scheme name (e.g., "Hellenic", "HellenicAdmin", "CustomAuth").
    /// This name is used by ASP.NET Core to identify this authentication handler and can be referenced in [Authorize] attributes.</param>
    /// <param name="configureOptions">Optional configuration for authentication options (events, validation settings, etc.)</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddHellenicAuthentication<TUser>(
        this IServiceCollection services,
        string authenticationScheme,
        Action<HellenicAuthenticationOptions>? configureOptions = null)
        where TUser : class
    {
        // Register HttpClient for IdentityClient (shared across all schemes)
        services.AddHttpClient<IdentityClient<TUser>>();
        
        // Register IdentityClient as singleton with initialization (shared across all schemes)
        services.TryAddSingleton<IIdentityClient<TUser>>(serviceProvider =>
        {
            var httpClientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();
            var httpClient = httpClientFactory.CreateClient(typeof(IdentityClient<TUser>).Name);
            
            var configuration = serviceProvider.GetRequiredService<IOptions<AppConfiguration>>();
            var logger = serviceProvider.GetRequiredService<ILogger<IdentityClient<TUser>>>();
            
            var identityClient = new IdentityClient<TUser>(configuration, logger, httpClient);
            
            // Initialize synchronously during registration
            var success = identityClient.Initialize();
            if (!success)
            {
                throw new InvalidOperationException("Failed to initialize Hellenic Identity Client - JWKS keys could not be loaded");
            }
            
            return identityClient;
        });

        // Register Authentication Service (shared across all schemes)
        services.TryAddScoped<IHellenicAuthenticationService, HellenicAuthenticationService<TUser>>();

        // Configure Authentication with the specified scheme as default
        services.AddAuthentication(authenticationScheme)
            .AddHellenicAuthentication<TUser>(authenticationScheme, configureOptions);

        return services;
    }

    /// <summary>
    /// Adds a Hellenic Authentication scheme to an existing AuthenticationBuilder.
    /// Use this method when you need multiple authentication schemes or when you've already called AddAuthentication().
    /// </summary>
    /// <typeparam name="TUser">The user model type that represents your application's user structure</typeparam>
    /// <param name="builder">The authentication builder to add the scheme to</param>
    /// <param name="authenticationScheme">The authentication scheme name (e.g., "Hellenic", "HellenicAdmin", "CustomAuth").
    /// This name is used by ASP.NET Core to identify this authentication handler and can be referenced in [Authorize] attributes.</param>
    /// <param name="configureOptions">Optional configuration for authentication options (events, validation settings, etc.)</param>
    /// <returns>The authentication builder for chaining</returns>
    public static AuthenticationBuilder AddHellenicAuthentication<TUser>(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<HellenicAuthenticationOptions>? configureOptions = null)
        where TUser : class
    {
        // Register the authentication scheme with ASP.NET Core's authentication system
        return builder.AddScheme<HellenicAuthenticationOptions, HellenicAuthenticationHandler<TUser>>(
            authenticationScheme,                    // Scheme name - used internally by ASP.NET Core and in [Authorize(AuthenticationSchemes = "...")]
            $"Hellenic Identity Authentication",     // Display name - shown in logs and error messages
            configureOptions);                       // Configuration delegate for setting up events, validation options, etc.
    }

    /// <summary>
    /// Adds a Hellenic Authentication scheme to an existing AuthenticationBuilder with a custom display name.
    /// Use this method when you need multiple authentication schemes with different display names.
    /// </summary>
    /// <typeparam name="TUser">The user model type that represents your application's user structure</typeparam>
    /// <param name="builder">The authentication builder to add the scheme to</param>
    /// <param name="authenticationScheme">The authentication scheme name (e.g., "Hellenic", "HellenicAdmin", "CustomAuth").
    /// This name is used by ASP.NET Core to identify this authentication handler and can be referenced in [Authorize] attributes.</param>
    /// <param name="displayName">The human-readable display name for this authentication scheme (shown in logs and error messages).
    /// For example: "Hellenic Identity Authentication", "Admin Authentication", "Customer Portal Auth"</param>
    /// <param name="configureOptions">Optional configuration for authentication options (events, validation settings, etc.)</param>
    /// <returns>The authentication builder for chaining</returns>
    public static AuthenticationBuilder AddHellenicAuthentication<TUser>(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        string displayName,
        Action<HellenicAuthenticationOptions>? configureOptions = null)
        where TUser : class
    {
        // Register the authentication scheme with custom display name
        return builder.AddScheme<HellenicAuthenticationOptions, HellenicAuthenticationHandler<TUser>>(
            authenticationScheme,    // Scheme name - used internally by ASP.NET Core and in [Authorize(AuthenticationSchemes = "...")]
            displayName,            // Display name - shown in logs and error messages (customizable)
            configureOptions);      // Configuration delegate for setting up events, validation options, etc.
    }
}