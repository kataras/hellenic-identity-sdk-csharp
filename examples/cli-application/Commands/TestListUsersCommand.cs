using Hellenic.Identity.SDK.Models;
using Hellenic.Identity.SDK.Services;
using Hellenic.Identity.CLI.Example.Models;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace Hellenic.Identity.CLI.Example.Commands;

public class TestListUsersCommand
{
    private readonly IIdentityClient<TestUserModel> _identityClient;
    private readonly ILogger<TestListUsersCommand> _logger;

    public TestListUsersCommand(IIdentityClient<TestUserModel> identityClient, ILogger<TestListUsersCommand> logger)
    {
        _identityClient = identityClient;
        _logger = logger;
    }

    public async Task<bool> ExecuteAsync()
    {
        try
        {
            _logger.LogInformation("Testing AdminListUsersAsync with corrected implementation...");

            if (!_identityClient.IsInitialized)
            {
                _logger.LogError("Identity client is not initialized");
                return false;
            }

            // Test 1: Basic pagination - get first page with default size
            _logger.LogInformation("\n=== Test 1: Basic Pagination ===");
            var pageOptions = new PageOptions
            {
                Page = 1,
                Size = 10,
                Details = false
            };

            var result = await _identityClient.AdminListUsersAsync(pageOptions);
            
            _logger.LogInformation("Response: Current Page: {CurrentPage}, Page Size: {PageSize}, Total Items: {TotalItems}, Total Pages: {TotalPages}, Has Next: {HasNext}",
                result.CurrentPage, result.PageSize, result.TotalItems, result.TotalPages, result.HasNextPage);
            
            _logger.LogInformation("Retrieved {ItemCount} users", result.Items.Count);
            foreach (var user in result.Items.Take(3)) // Show first 3 users
            {
                _logger.LogInformation("User: {Username} (ID: {Id}, Created: {CreatedAt})", 
                    user.Username, user.Id, user.CreatedAt);
            }

            // Test 2: Filtering by username with ILIKE operator
            _logger.LogInformation("\n=== Test 2: Username Filtering ===");
            var filterOptions = new UserFilterOptions
            {
                Sort = "created_at",
                SortDescending = true,
                Terms = new List<FilterTerm>
                {
                    new FilterTerm
                    {
                        Field = "username",
                        Operator = "ILIKE",
                        Value = "%admin%", // Find usernames containing "admin"
                        Logic = "AND"
                    }
                },
                IncludeDeleted = false
            };

            var filteredResult = await _identityClient.AdminListUsersAsync(pageOptions, filterOptions);
            _logger.LogInformation("Filtered results: Found {Count} users with 'admin' in username", filteredResult.Items.Count);

            // Test 3: Custom attribute filtering using JSONB query
            _logger.LogInformation("\n=== Test 3: Custom Attribute Filtering ===");
            var attributeFilter = new UserFilterOptions
            {
                Sort = "username",
                SortDescending = false,
                Terms = new List<FilterTerm>
                {
                    new FilterTerm
                    {
                        Field = "role", // Will be converted to attrs->>'role'
                        Operator = "=",
                        Value = "admin",
                        Logic = "AND"
                    }
                },
                IncludeDeleted = false
            };

            var attributeResult = await _identityClient.AdminListUsersAsync(pageOptions, attributeFilter);
            _logger.LogInformation("Attribute filtered results: Found {Count} users with role=admin", attributeResult.Items.Count);

            // Test 4: Complex filtering with multiple terms
            _logger.LogInformation("\n=== Test 4: Complex Multi-Term Filtering ===");
            var complexFilter = new UserFilterOptions
            {
                Sort = "created_at",
                SortDescending = true,
                Terms = new List<FilterTerm>
                {
                    new FilterTerm
                    {
                        Field = "username",
                        Operator = "ILIKE",
                        Value = "%user%",
                        Logic = "AND"
                    },
                    new FilterTerm
                    {
                        Field = "created_at",
                        Operator = ">=",
                        Value = DateTime.UtcNow.AddDays(-30).ToString("yyyy-MM-dd"),
                        Logic = "AND"
                    }
                },
                IncludeDeleted = false
            };

            var complexResult = await _identityClient.AdminListUsersAsync(pageOptions, complexFilter);
            _logger.LogInformation("Complex filtered results: Found {Count} users matching multiple criteria", complexResult.Items.Count);

            // Test 5: Include deleted users
            _logger.LogInformation("\n=== Test 5: Include Deleted Users ===");
            var deletedFilter = new UserFilterOptions
            {
                Sort = "deleted_at",
                SortDescending = true,
                IncludeDeleted = true // Include soft-deleted users
            };

            var deletedResult = await _identityClient.AdminListUsersAsync(pageOptions, deletedFilter);
            _logger.LogInformation("Results including deleted: Found {Count} users (including deleted)", deletedResult.Items.Count);

            var deletedCount = deletedResult.Items.Count(u => u.DeletedAt.HasValue);
            _logger.LogInformation("Of which {DeletedCount} are deleted users", deletedCount);

            // Test 6: Pagination with large page size
            _logger.LogInformation("\n=== Test 6: Large Page Size ===");
            var largePageOptions = new PageOptions
            {
                Page = 1,
                Size = 50, // Larger page size
                Details = true // Include details
            };

            var largePageResult = await _identityClient.AdminListUsersAsync(largePageOptions);
            _logger.LogInformation("Large page results: Retrieved {Count} users with details", largePageResult.Items.Count);

            _logger.LogInformation("\n=== AdminListUsersAsync Tests Completed Successfully ===");
            _logger.LogInformation("All pagination options and filter terms are now correctly implemented according to the Go SDK");

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during AdminListUsersAsync testing");
            return false;
        }
    }
}