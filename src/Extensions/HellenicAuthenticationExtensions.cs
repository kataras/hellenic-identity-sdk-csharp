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
    /// Adds complete Hellenic Authentication with EdDSA support to handle [Authorize] routes.
    /// This method registers everything needed: IdentityClient, AuthenticationService, Handler, and initializes JWKS keys.
    /// </summary>
    /// <typeparam name="TUser">The user model type</typeparam>
    /// <param name="services">The service collection</param>
    /// <param name="configureOptions">Optional configuration for authentication options</param>
    /// <returns>The service collection for chaining</returns>
    public static IServiceCollection AddHellenicAuthentication<TUser>(
        this IServiceCollection services,
        Action<HellenicAuthenticationOptions>? configureOptions = null)
        where TUser : class
    {
        // Register HttpClient for IdentityClient
        services.AddHttpClient<IdentityClient<TUser>>();
        
        // Register IdentityClient as singleton with initialization
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

        // Register Authentication Service
        services.TryAddScoped<IHellenicAuthenticationService, HellenicAuthenticationService<TUser>>();

        // Configure Authentication with Hellenic scheme as default
        services.AddAuthentication("Hellenic")
            .AddScheme<HellenicAuthenticationOptions, HellenicAuthenticationHandler<TUser>>(
                "Hellenic",
                "Hellenic Identity Authentication",
                configureOptions);

        return services;
    }
}