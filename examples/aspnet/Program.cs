using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Hellenic.Identity.SDK.Authentication;
using Hellenic.Identity.SDK.Extensions;
using Hellenic.Identity.SDK.Models;
using Hellenic.Identity.SDK.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure Hellenic Identity with Authentication using the SDK extension
// This registers everything automatically: Identity Client + Authentication Service + Handler
builder.Services.Configure<AppConfiguration>(builder.Configuration);
builder.Services.AddHellenicAuthentication<UserModel>(options =>
    {
        // Configure JWT Bearer-like events
        options.Events = new HellenicAuthenticationEvents
        {
            OnMessageReceived = async context =>
            {
                Console.WriteLine($"[OnMessageReceived] Authorization Header: {context.AuthorizationHeader}");
                
                // Custom token extraction logic (e.g., from query string)
                if (string.IsNullOrEmpty(context.Token))
                {
                    var queryToken = context.HttpContext.Request.Query["access_token"];
                    if (!string.IsNullOrEmpty(queryToken))
                    {
                        context.Token = queryToken;
                        Console.WriteLine($"[OnMessageReceived] Extracted token from query: {queryToken.ToString()[..10]}...");
                    }
                }
                
                await Task.CompletedTask;
            },

            OnTokenValidated = async context =>
            {
                Console.WriteLine($"[OnTokenValidated] Token validated successfully for user: {context.Principal?.Identity?.Name}");
                
                // Add custom claims
                if (context.Principal?.Identity is ClaimsIdentity identity)
                {
                    identity.AddClaim(new Claim("custom_claim", "added_by_event"));
                    identity.AddClaim(new Claim("validated_at", DateTimeOffset.UtcNow.ToString()));
                    
                    Console.WriteLine($"[OnTokenValidated] Added custom claims to user: {identity.Name}");
                }

                // Log all claims
                var claims = context.Principal?.Claims?.Select(c => $"{c.Type}: {c.Value}");
                if (claims != null)
                {
                    Console.WriteLine($"[OnTokenValidated] User claims: {string.Join(", ", claims)}");
                }
                
                await Task.CompletedTask;
            },

            OnAuthenticationFailed = async context =>
            {
                Console.WriteLine($"[OnAuthenticationFailed] Authentication failed: {context.Exception?.Message}");
                
                // Log additional details
                if (!string.IsNullOrEmpty(context.Token))
                {
                    Console.WriteLine($"[OnAuthenticationFailed] Failed token (first 20 chars): {context.Token[..Math.Min(20, context.Token.Length)]}...");
                }

                // Custom error handling - you could redirect or return custom response
                if (context.Exception?.Message?.Contains("expired") == true)
                {
                    context.HttpContext.Response.Headers["X-Token-Expired"] = "true";
                }
                
                await Task.CompletedTask;
            },

            OnChallenge = async context =>
            {
                Console.WriteLine($"[OnChallenge] Challenge triggered. Failure: {context.AuthenticateFailure?.Failure?.Message}");
                
                // Custom challenge response
                context.HttpContext.Response.Headers["X-Challenge-Reason"] = "hellenic_auth_required";
                
                // You could customize the challenge response here
                // For example, return a JSON response instead of default 401
                if (context.HttpContext.Request.Path.StartsWithSegments("/api"))
                {
                    context.HttpContext.Response.ContentType = "application/json";
                    await context.HttpContext.Response.WriteAsync(
                        """{"error": "authentication_required", "message": "Hellenic Identity token required"}""");
                    context.Handled = true; // Skip default challenge
                }
                
                await Task.CompletedTask;
            },

            OnForbidden = async context =>
            {
                Console.WriteLine($"[OnForbidden] Access forbidden for user: {context.Principal?.Identity?.Name}");
                
                // Log forbidden access attempts
                var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var requestPath = context.HttpContext.Request.Path;
                
                Console.WriteLine($"[OnForbidden] User {userId} attempted to access {requestPath}");
                
                // Custom forbidden response
                if (context.HttpContext.Request.Path.StartsWithSegments("/api"))
                {
                    context.HttpContext.Response.ContentType = "application/json";
                    await context.HttpContext.Response.WriteAsync(
                        """{"error": "access_denied", "message": "Insufficient permissions"}""");
                }
                
                await Task.CompletedTask;
            }
        };

    // Additional options
    // options.ExpectedIssuer = "https://your-hellenic-identity-server.com";
    // options.ExpectedAudience = "your-client-id";
});


var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Example protected endpoint
app.MapGet("/api/protected", [Authorize] (ClaimsPrincipal user) =>
{
    return new
    {
        Message = "Hello from protected endpoint!",
        User = user.Identity?.Name,
        Claims = user.Claims.Select(c => new { c.Type, c.Value })
    };
});

// Example endpoint requiring specific claims
app.MapGet("/api/admin", [Authorize] (ClaimsPrincipal user) =>
{
    // Check for admin role
    if (!user.IsInRole("admin"))
    {
        return Results.Forbid();
    }

    return Results.Ok(new
    {
        Message = "Welcome, admin!",
        User = user.Identity?.Name,
        CustomClaim = user.FindFirst("custom_claim")?.Value
    });
});

app.Run();

// Example User Model
public class UserModel
{
    public string? Id { get; set; }
    public string? Username { get; set; }
    public string? Email { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Phone { get; set; }
    public string? Role { get; set; }
}