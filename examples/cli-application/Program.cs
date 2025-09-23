using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.CommandLine;
using Hellenic.Identity.SDK.Services;
using Hellenic.Identity.SDK.Models;
using Hellenic.Identity.CLI.Example.Models;
using Hellenic.Identity.CLI.Example.Commands;

namespace Hellenic.Identity.CLI.Example;

/// <summary>
/// Example application demonstrating how to use the generic IdentityClient<TUser>
/// with a custom UserModel for JWT authentication and user management.
///
/// This example shows:
/// - How to configure and register the generic IdentityClient<TUser>
/// - How to create a custom UserModel that works with the SDK
/// - How to implement all authentication and admin operations using the generic interface
/// - Complete CLI application with comprehensive command support
/// </summary>
class Program
{
    static async Task<int> Main(string[] args)
    {
        Console.WriteLine("=== Hellenic Identity SDK Example Application ===");
        Console.WriteLine("Demonstrating generic IdentityClient<TUser> with custom UserModel");
        Console.WriteLine();

        // Build configuration
        var configuration = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") ?? "Production"}.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        // Build host
        var host = Host.CreateDefaultBuilder(args)
            .ConfigureServices((context, services) =>
            {
                // Configuration - bind IdentityClient section to IdentityClientOptions
                services.Configure<IdentityClientOptions>(configuration.GetSection("IdentityClient"));
                services.Configure<AppConfiguration>(configuration);
                
                // HTTP Client for the generic IdentityClient
                services.AddHttpClient<IIdentityClient<UserModel>, IdentityClient<UserModel>>();

                // Register the generic IdentityClient with our custom UserModel
                services.AddSingleton<IIdentityClient<UserModel>, IdentityClient<UserModel>>();
                
                // Register command line handler
                services.AddSingleton<CommandLineHandler>();
                
                // Logging
                services.AddLogging(builder =>
                {
                    builder.ClearProviders();
                    builder.AddConsole();
                    builder.SetMinimumLevel(LogLevel.Information);
                });
            })
            .Build();

        try
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Starting Identity SDK Example CLI Application");

            var commandLineHandler = host.Services.GetRequiredService<CommandLineHandler>();
            var rootCommand = commandLineHandler.CreateRootCommand();

            return await rootCommand.InvokeAsync(args);
        }
        catch (Exception ex)
        {
            var logger = host.Services.GetRequiredService<ILogger<Program>>();
            logger.LogError(ex, "Application terminated unexpectedly");
            return 1;
        }
        finally
        {
            await host.StopAsync();
        }
    }
}
