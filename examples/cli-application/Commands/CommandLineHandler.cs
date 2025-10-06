using System.CommandLine;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Hellenic.Identity.SDK.Services;
using Hellenic.Identity.SDK.Models;
using Hellenic.Identity.CLI.Example.Models;

namespace Hellenic.Identity.CLI.Example.Commands;

/// <summary>
/// Command line handler for the Hellenic Identity Client example application.
/// Demonstrates how to use the generic IdentitySDK<TUser> with a custom UserModel.
/// </summary>
public class CommandLineHandler
{
    private readonly IIdentityClient<UserModel> _identityClient;
    private readonly ILogger<CommandLineHandler> _logger;

    public CommandLineHandler(IIdentityClient<UserModel> identitySDK, ILogger<CommandLineHandler> logger)
    {
        _identityClient = identitySDK;
        _logger = logger;
    }

    public RootCommand CreateRootCommand()
    {
        var rootCommand = new RootCommand("Hellenic Identity Client Example - JWT Authentication and Management with Generic UserModel");

        // Add commands
        rootCommand.AddCommand(CreateSignupCommand());
        rootCommand.AddCommand(CreateLoginCommand());
        rootCommand.AddCommand(CreateValidateTokenCommand());
        rootCommand.AddCommand(CreateRefreshJwksCommand());
        rootCommand.AddCommand(CreateIntrospectCommand());
        
        // Add admin commands
        rootCommand.AddCommand(CreateAdminGetSchemaCommand());
        rootCommand.AddCommand(CreateAdminDeleteUserCommand());
        rootCommand.AddCommand(CreateAdminDeleteUsersCommand());
        rootCommand.AddCommand(CreateAdminRestoreUserCommand());
        rootCommand.AddCommand(CreateAdminResetPasswordCommand());
        rootCommand.AddCommand(CreateAdminListUsersCommand());
        rootCommand.AddCommand(CreateAdminUpdateUsersCommand());
        rootCommand.AddCommand(CreateAdminUpdateUsersPartialCommand());

        return rootCommand;
    }

    private Command CreateSignupCommand()
    {
        var command = new Command("signup", "Sign up a new user using the generic SDK");
        
        var usernameOption = new Option<string>(
            name: "--username",
            description: "Username for the new user, an email address")
        { IsRequired = true };
        
        var passwordOption = new Option<string>(
            name: "--password",
            description: "Password for the new user")
        { IsRequired = true };
        
        var firstNameOption = new Option<string>(
            name: "--firstname",
            description: "First name");
        
        var lastNameOption = new Option<string>(
            name: "--lastname",
            description: "Last name");

        var roleOption = new Option<int>(
            name: "--role",
            description: "Role");

        var phoneOption = new Option<string>(
            name: "--phone",
            description: "Phone number");

        command.AddOption(usernameOption);
        command.AddOption(passwordOption);
        command.AddOption(firstNameOption);
        command.AddOption(lastNameOption);
        command.AddOption(roleOption);
        command.AddOption(phoneOption);

        command.SetHandler(async (string username, string password, 
            string firstName, string lastName, int role, string? phone) =>
        {
            await HandleSignupAsync(username, password, firstName, lastName, role, phone);
        }, usernameOption, passwordOption, firstNameOption, lastNameOption, roleOption, phoneOption);

        return command;
    }

    private Command CreateLoginCommand()
    {
        var command = new Command("login", "Sign in a user using the generic SDK");
        
        var usernameOption = new Option<string>(
            name: "--username",
            description: "Username or email address")
        { IsRequired = true };
        
        var passwordOption = new Option<string>(
            name: "--password",
            description: "User password")
        { IsRequired = true };

        var adminOption = new Option<bool>(
            name: "--admin",
            description: "Perform admin signin (no password required, uses client token)");

        command.AddOption(usernameOption);
        command.AddOption(passwordOption);
        command.AddOption(adminOption);

        command.SetHandler(async (string username, string password, bool admin) =>
        {
            await HandleLoginAsync(username, password, admin);
        }, usernameOption, passwordOption, adminOption);

        return command;
    }

    private Command CreateValidateTokenCommand()
    {
        var command = new Command("validate-token", "Validate a JWT token");
        
        var tokenOption = new Option<string>(
            name: "--token",
            description: "JWT token to validate")
        { IsRequired = true };

        command.AddOption(tokenOption);

        command.SetHandler(async (string token) =>
        {
            await HandleValidateTokenAsync(token);
        }, tokenOption);

        return command;
    }

    private Command CreateRefreshJwksCommand()
    {
        var command = new Command("refresh-jwks", "Refresh JSON Web Key Set from remote server");

        command.SetHandler(async () =>
        {
            await HandleRefreshJwksAsync();
        });

        return command;
    }

    private Command CreateIntrospectCommand()
    {
        var command = new Command("introspect", "Introspect a token and show its claims");
        
        var tokenOption = new Option<string>(
            name: "--token",
            description: "JWT token to introspect")
        { IsRequired = true };

        var remoteOption = new Option<bool>(
            name: "--remote",
            description: "Use remote token introspection endpoint");

        command.AddOption(tokenOption);
        command.AddOption(remoteOption);

        command.SetHandler(async (string token, bool remote) =>
        {
            await HandleIntrospectAsync(token, remote);
        }, tokenOption, remoteOption);

        return command;
    }

    private Command CreateAdminGetSchemaCommand()
    {
        var command = new Command("admin-get-schema", "Get user schema from identity server (requires admin client token)");

        command.SetHandler(async () =>
        {
            await HandleAdminGetSchemaAsync();
        });

        return command;
    }

    private Command CreateAdminDeleteUserCommand()
    {
        var command = new Command("admin-delete-user", "Delete a user by ID or username (requires admin client token)");
        
        var identifierOption = new Option<string>(
            name: "--identifier",
            description: "User ID or username to delete")
        { IsRequired = true };
        
        var softOption = new Option<bool>(
            name: "--soft",
            description: "Perform soft delete (mark as deleted but keep in database)");

        command.AddOption(identifierOption);
        command.AddOption(softOption);

        command.SetHandler(async (string identifier, bool soft) =>
        {
            await HandleAdminDeleteUserAsync(identifier, soft);
        }, identifierOption, softOption);

        return command;
    }

    private Command CreateAdminDeleteUsersCommand()
    {
        var command = new Command("admin-delete-users", "Bulk delete multiple users by IDs (requires admin client token)");
        
        var idsOption = new Option<string[]>(
            name: "--ids",
            description: "User IDs to delete (comma-separated)")
        { IsRequired = true, AllowMultipleArgumentsPerToken = true };
        
        var softOption = new Option<bool>(
            name: "--soft",
            description: "Perform soft delete (mark as deleted but keep in database)");

        command.AddOption(idsOption);
        command.AddOption(softOption);

        command.SetHandler(async (string[] ids, bool soft) =>
        {
            await HandleAdminBulkDeleteUsersAsync(ids, soft);
        }, idsOption, softOption);

        return command;
    }

    private Command CreateAdminRestoreUserCommand()
    {
        var command = new Command("admin-restore-user", "Restore a deleted user by ID or username (requires admin client token)");
        
        var identifierOption = new Option<string>(
            name: "--identifier",
            description: "User ID or username to restore")
        { IsRequired = true };

        command.AddOption(identifierOption);

        command.SetHandler(async (string identifier) =>
        {
            await HandleAdminRestoreUserAsync(identifier);
        }, identifierOption);

        return command;
    }

    private Command CreateAdminResetPasswordCommand()
    {
        var command = new Command("admin-reset-password", "Reset user password by ID or username (requires admin client token)");
        
        var identifierOption = new Option<string>(
            name: "--identifier",
            description: "User ID or username")
        { IsRequired = true };
        
        var passwordOption = new Option<string>(
            name: "--password",
            description: "New password for the user")
        { IsRequired = true };

        command.AddOption(identifierOption);
        command.AddOption(passwordOption);

        command.SetHandler(async (string identifier, string password) =>
        {
            await HandleAdminResetPasswordAsync(identifier, password);
        }, identifierOption, passwordOption);

        return command;
    }

    private Command CreateAdminListUsersCommand()
    {
        var command = new Command("admin-list-users", "List users with pagination and filtering (requires admin client token)");
        
        var pageOption = new Option<int>(
            name: "--page",
            description: "Page number (default: 1)",
            getDefaultValue: () => 1);
        
        var limitOption = new Option<int>(
            name: "--limit",
            description: "Items per page (default: 20)",
            getDefaultValue: () => 20);
        
        var sortOption = new Option<string>(
            name: "--sort",
            description: "Sort field");
        
        var orderOption = new Option<string>(
            name: "--order",
            description: "Sort order (asc/desc, default: desc)",
            getDefaultValue: () => "desc");
        
        var usernameFilterOption = new Option<string>(
            name: "--username-filter",
            description: "Filter by username");
        
        var roleFilterOption = new Option<int?>(
            name: "--role-filter",
            description: "Filter by role");
        
        var deletedFilterOption = new Option<bool?>(
            name: "--deleted-filter",
            description: "Filter by deleted status");

        command.AddOption(pageOption);
        command.AddOption(limitOption);
        command.AddOption(sortOption);
        command.AddOption(orderOption);
        command.AddOption(usernameFilterOption);
        command.AddOption(roleFilterOption);
        command.AddOption(deletedFilterOption);

        command.SetHandler(async (int page, int limit, string sort, string order,
            string usernameFilter, int? roleFilter, bool? deletedFilter) =>
        {
            await HandleAdminListUsersAsync(page, limit, sort, order, usernameFilter, roleFilter, deletedFilter);
        }, pageOption, limitOption, sortOption, orderOption, usernameFilterOption, roleFilterOption, deletedFilterOption);

        return command;
    }

    private Command CreateAdminUpdateUsersCommand()
    {
        var command = new Command("admin-update-users", "Update multiple users from JSON file (requires admin client token)");
        
        var fileOption = new Option<string>(
            name: "--file",
            description: "JSON file containing array of users to update")
        { IsRequired = true };
        
        var columnsOption = new Option<string[]>(
            name: "--columns",
            description: "Only update specific columns (comma-separated)")
        { AllowMultipleArgumentsPerToken = true };

        command.AddOption(fileOption);
        command.AddOption(columnsOption);

        command.SetHandler(async (string file, string[] columns) =>
        {
            await HandleAdminUpdateUsersAsync(file, columns);
        }, fileOption, columnsOption);

        return command;
    }

    private Command CreateAdminUpdateUsersPartialCommand()
    {
        var command = new Command("admin-update-users-partial", "Perform partial updates on users with JSONB attrs support (requires admin client token)");
        
        var userIdOption = new Option<string>(
            name: "--user-id",
            description: "User ID to update")
        { IsRequired = true };
        
        var usernameOption = new Option<string>(
            name: "--new-username",
            description: "New username (core field)");
        
        var passwordOption = new Option<string>(
            name: "--new-password",
            description: "New password (core field, will be encrypted)");
        
        var setFieldOption = new Option<string[]>(
            name: "--set",
            description: "Set field values in format 'field=value' (e.g., 'profile.name=John Doe')")
        { AllowMultipleArgumentsPerToken = true };
        
        var removeFieldOption = new Option<string[]>(
            name: "--remove",
            description: "Remove field paths (e.g., 'profile.avatar', 'settings.theme')")
        { AllowMultipleArgumentsPerToken = true };

        command.AddOption(userIdOption);
        command.AddOption(usernameOption);
        command.AddOption(passwordOption);
        command.AddOption(setFieldOption);
        command.AddOption(removeFieldOption);

        command.SetHandler(async (string userId, string newUsername, string newPassword, string[] setFields, string[] removeFields) =>
        {
            await HandleAdminUpdateUsersPartialAsync(userId, newUsername, newPassword, setFields, removeFields);
        }, userIdOption, usernameOption, passwordOption, setFieldOption, removeFieldOption);

        return command;
    }

    private async Task HandleSignupAsync(string username, string password,
        string firstName, string lastName, int role, string? phone)
    {
        try
        {
            Console.WriteLine("Signing up user using generic SDK...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            var user = new UserModel
            {
                Username = username,
                FirstName = firstName,
                LastName = lastName,
                Phone = phone,
                Role = role
            };

            Console.WriteLine($"Creating user: {user}");

            var result = await _identityClient.AdminUserSignupAsync(user, password);
            
            if (result != null)
            {
                Console.WriteLine("✅ User signed up successfully using generic SDK!");
                Console.WriteLine($"Access Token: {result.AccessToken}");
                if (!string.IsNullOrEmpty(result.RefreshToken))
                {
                    Console.WriteLine($"Refresh Token: {result.RefreshToken}");
                }
                Console.WriteLine($"Expires In: {result.ExpiresIn} seconds");
            }
            else
            {
                Console.WriteLine("❌ Failed to sign up user");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error during signup: {ex.Message}");
            _logger.LogError(ex, "Signup command failed");
        }
    }

    private async Task HandleLoginAsync(string username, string password, bool admin)
    {
        try
        {
            Console.WriteLine("Signing in user using generic SDK...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            TokenResponse? result;
            
            if (admin)
            {
                Console.WriteLine("Performing admin signin...");
                result = await _identityClient.AdminUserSigninAsync(username);
            }
            else
            {
                result = await _identityClient.UserSigninAsync(username, password);
            }
            
            if (result != null)
            {
                Console.WriteLine("✅ User signed in successfully using generic SDK!");
                Console.WriteLine($"Access Token: {result.AccessToken}");
                if (!string.IsNullOrEmpty(result.RefreshToken))
                {
                    Console.WriteLine($"Refresh Token: {result.RefreshToken}");
                }
                Console.WriteLine($"Token Type: {result.TokenType}");
                Console.WriteLine($"Expires In: {result.ExpiresIn} seconds");
                if (!string.IsNullOrEmpty(result.Scope))
                {
                    Console.WriteLine($"Scope: {result.Scope}");
                }
            }
            else
            {
                Console.WriteLine("❌ Failed to sign in user");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error during login: {ex.Message}");
            _logger.LogError(ex, "Login command failed");
        }
    }

    private async Task HandleValidateTokenAsync(string token)
    {
        try
        {
            Console.WriteLine("Validating token...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            var isValid = await _identityClient.VerifyTokenAsync(token);
            
            if (isValid)
            {
                Console.WriteLine("✅ Token is valid!");
                
                // Also show token claims
                var claims = _identityClient.IntrospectToken<Dictionary<string, object>>(token);
                if (claims != null)
                {
                    Console.WriteLine("\nToken Claims:");
                    foreach (var claim in claims)
                    {
                        Console.WriteLine($"  {claim.Key}: {claim.Value}");
                    }
                }
            }
            else
            {
                Console.WriteLine("❌ Token is invalid or expired");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error during token validation: {ex.Message}");
            _logger.LogError(ex, "Token validation command failed");
        }
    }

    private async Task HandleRefreshJwksAsync()
    {
        try
        {
            Console.WriteLine("Refreshing JWKS...");
            
            await _identityClient.LoadKeysAsync();
            Console.WriteLine("✅ JWKS refreshed successfully!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error refreshing JWKS: {ex.Message}");
            _logger.LogError(ex, "JWKS refresh command failed");
        }
    }

    private async Task HandleIntrospectAsync(string token, bool remote)
    {
        try
        {
            Console.WriteLine("Introspecting token...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            if (remote)
            {
                var result = await _identityClient.TokenIntrospectAsync<Dictionary<string, object>>(token);
                if (result != null)
                {
                    Console.WriteLine("✅ Remote token introspection successful!");
                    Console.WriteLine("\nToken Data:");
                    var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
                    Console.WriteLine(json);
                }
                else
                {
                    Console.WriteLine("❌ Remote token introspection failed");
                }
            }
            else
            {
                var claims = _identityClient.IntrospectToken<Dictionary<string, object>>(token);
                if (claims != null)
                {
                    Console.WriteLine("✅ Local token introspection successful!");
                    Console.WriteLine("\nToken Claims:");
                    var json = JsonSerializer.Serialize(claims, new JsonSerializerOptions { WriteIndented = true });
                    Console.WriteLine(json);
                }
                else
                {
                    Console.WriteLine("❌ Failed to introspect token locally");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error during token introspection: {ex.Message}");
            _logger.LogError(ex, "Token introspection command failed");
        }
    }

    private async Task HandleAdminGetSchemaAsync()
    {
        try
        {
            Console.WriteLine("Getting user schema...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            var schema = await _identityClient.AdminGetUserSchemaAsync();
            
            if (schema != null)
            {
                Console.WriteLine("✅ User schema retrieved successfully!");
                Console.WriteLine("\nUser Schema:");
                var json = JsonSerializer.Serialize(schema, new JsonSerializerOptions { WriteIndented = true });
                Console.WriteLine(json);
            }
            else
            {
                Console.WriteLine("❌ Failed to get user schema");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error getting user schema: {ex.Message}");
            _logger.LogError(ex, "Get user schema command failed");
        }
    }

    private async Task HandleAdminDeleteUserAsync(string identifier, bool soft)
    {
        try
        {
            Console.WriteLine($"Deleting user: {identifier} (soft: {soft})...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            var request = new AdminDeleteUserRequest
            {
                Identifier = identifier,
                Soft = soft ? soft : null
            };

            var success = await _identityClient.AdminDeleteUserAsync(request);
            
            if (success)
            {
                Console.WriteLine($"✅ User {identifier} deleted successfully!");
            }
            else
            {
                Console.WriteLine($"❌ Failed to delete user {identifier}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error deleting user: {ex.Message}");
            _logger.LogError(ex, "Delete user command failed");
        }
    }

    private async Task HandleAdminBulkDeleteUsersAsync(string[] ids, bool soft)
    {
        try
        {
            Console.WriteLine($"Bulk deleting {ids.Length} users (soft: {soft})...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            var request = new BulkUserDeleteRequest
            {
                Ids = ids.ToList(),
                Soft = soft ? soft : null
            };

            Console.WriteLine($"User IDs to delete: {string.Join(", ", ids)}");

            var deletedCount = await _identityClient.AdminBulkDeleteUsersAsync(request);
            
            if (deletedCount > 0)
            {
                Console.WriteLine($"✅ Successfully deleted {deletedCount} user(s)!");
            }
            else
            {
                Console.WriteLine("❌ No users were deleted");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error bulk deleting users: {ex.Message}");
            _logger.LogError(ex, "Bulk delete users command failed");
        }
    }

    private async Task HandleAdminRestoreUserAsync(string identifier)
    {
        try
        {
            Console.WriteLine($"Restoring user: {identifier}...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            var request = new AdminRestoreUserRequest
            {
                Identifier = identifier
            };

            var success = await _identityClient.AdminRestoreUserAsync(request);
            
            if (success)
            {
                Console.WriteLine($"✅ User {identifier} restored successfully!");
            }
            else
            {
                Console.WriteLine($"❌ Failed to restore user {identifier}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error restoring user: {ex.Message}");
            _logger.LogError(ex, "Restore user command failed");
        }
    }

    private async Task HandleAdminResetPasswordAsync(string identifier, string password)
    {
        try
        {
            Console.WriteLine($"Resetting password for user: {identifier}...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            var request = new AdminResetUserPasswordRequest
            {
                Identifier = identifier,
                Password = password
            };

            var success = await _identityClient.AdminResetUserPasswordAsync(request);
            
            if (success)
            {
                Console.WriteLine($"✅ Password reset successfully for user {identifier}!");
            }
            else
            {
                Console.WriteLine($"❌ Failed to reset password for user {identifier}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error resetting password: {ex.Message}");
            _logger.LogError(ex, "Reset password command failed");
        }
    }

    private async Task HandleAdminListUsersAsync(int page, int limit, string sort, string order,
        string usernameFilter, int? roleFilter, bool? deletedFilter)
    {
        try
        {
            Console.WriteLine($"Listing users (page: {page}, size: {limit})...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            var pageOptions = new PageOptions
            {
                Page = page,
                Size = limit,  // Changed from Limit to Size
                Details = false
            };

            var filter = new UserFilterOptions
            {
                Sort = sort,
                SortDescending = order?.ToLower() == "desc",
                Terms = new List<FilterTerm>(),
                IncludeDeleted = deletedFilter ?? false
            };

            // Add username filter if provided
            if (!string.IsNullOrEmpty(usernameFilter))
            {
                filter.Terms.Add(new FilterTerm
                {
                    Field = "username",
                    Operator = "ILIKE",
                    Value = $"%{usernameFilter}%",
                    Logic = "AND"
                });
            }

            // Add role filter if provided
            if (roleFilter.HasValue)
            {
                filter.Terms.Add(new FilterTerm
                {
                    Field = "role", // Will be converted to attrs->>'role'
                    Operator = "=",
                    Value = roleFilter.Value,
                    Logic = "AND"
                });
            }

            var result = await _identityClient.AdminListUsersAsync(pageOptions, filter);
            
            if (result != null)
            {
                Console.WriteLine("✅ Users listed successfully using generic SDK!");
                Console.WriteLine($"\nTotal: {result.TotalItems}, Page: {result.CurrentPage}/{result.TotalPages}, Showing: {result.Items.Count}");
                Console.WriteLine($"Has Next Page: {result.HasNextPage}");
                Console.WriteLine("\nUsers:");
                var json = JsonSerializer.Serialize(result.Items, new JsonSerializerOptions { WriteIndented = true });
                Console.WriteLine(json);
            }
            else
            {
                Console.WriteLine("❌ Failed to list users");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error listing users: {ex.Message}");
            _logger.LogError(ex, "List users command failed");
        }
    }

    private async Task HandleAdminUpdateUsersAsync(string file, string[] columns)
    {
        try
        {
            Console.WriteLine($"Updating users from file: {file}...");
            
            if (!File.Exists(file))
            {
                Console.WriteLine($"❌ File not found: {file}");
                return;
            }

            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            var fileContent = await File.ReadAllTextAsync(file);
            var users = JsonSerializer.Deserialize<List<UserModel>>(fileContent);
            
            if (users == null || users.Count == 0)
            {
                Console.WriteLine("❌ No users found in file or invalid JSON format");
                return;
            }

            Console.WriteLine($"Found {users.Count} users in file");
            foreach (var user in users)
            {
                Console.WriteLine($"  - {user}");
            }

            var result = await _identityClient.AdminUpdateUsersAsync(users, columns);
            
            if (result != null)
            {
                Console.WriteLine($"✅ Users updated successfully using generic SDK! Updated count: {result.Count}");
            }
            else
            {
                Console.WriteLine("❌ Failed to update users");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error updating users: {ex.Message}");
            _logger.LogError(ex, "Update users command failed");
        }
    }

    private async Task HandleAdminUpdateUsersPartialAsync(string userId, string newUsername, string newPassword, string[] setFields, string[] removeFields)
    {
        try
        {
            Console.WriteLine($"Performing partial update on user: {userId}...");
            
            if (!_identityClient.IsInitialized)
            {
                Console.WriteLine("Initializing SDK...");
                if (!await _identityClient.InitializeAsync())
                {
                    Console.WriteLine("❌ Failed to initialize SDK");
                    return;
                }
            }

            var updateSpec = new PartialUpdateSpec
            {
                Id = userId,
                Set = new Dictionary<string, object>(),
                Remove = removeFields?.ToList()
            };

            // Add core field updates if provided
            if (!string.IsNullOrEmpty(newUsername))
            {
                updateSpec.Set["username"] = newUsername;
                Console.WriteLine($"  Setting username to: {newUsername}");
            }

            if (!string.IsNullOrEmpty(newPassword))
            {
                updateSpec.Set["password"] = newPassword; // Will be encrypted by SDK
                Console.WriteLine("  Setting new password (will be encrypted)");
            }

            // Parse set fields (format: "field=value")
            if (setFields != null)
            {
                foreach (var setField in setFields)
                {
                    var parts = setField.Split('=', 2);
                    if (parts.Length == 2)
                    {
                        var fieldName = parts[0].Trim();
                        var fieldValue = parts[1].Trim();
                        
                        // Try to parse as different types
                        object parsedValue = fieldValue;
                        if (int.TryParse(fieldValue, out var intValue))
                        {
                            parsedValue = intValue;
                        }
                        else if (bool.TryParse(fieldValue, out var boolValue))
                        {
                            parsedValue = boolValue;
                        }
                        else if (fieldValue.StartsWith("{") && fieldValue.EndsWith("}"))
                        {
                            // Try to parse as JSON object
                            try
                            {
                                parsedValue = JsonSerializer.Deserialize<Dictionary<string, object>>(fieldValue);
                            }
                            catch
                            {
                                // Keep as string if JSON parsing fails
                            }
                        }

                        updateSpec.Set[fieldName] = parsedValue!;
                        Console.WriteLine($"  Setting {fieldName} to: {parsedValue}");
                    }
                    else
                    {
                        Console.WriteLine($"⚠️  Invalid set field format: {setField} (expected 'field=value')");
                    }
                }
            }

            // Display remove operations
            if (removeFields != null && removeFields.Length > 0)
            {
                Console.WriteLine($"  Removing fields: {string.Join(", ", removeFields)}");
            }

            var updates = new List<PartialUpdateSpec> { updateSpec };
            var result = await _identityClient.AdminUpdateUsersPartialAsync(updates);
            
            if (result != null)
            {
                Console.WriteLine($"✅ Partial update completed successfully! Updated count: {result.Count}");
            }
            else
            {
                Console.WriteLine("❌ Failed to perform partial update");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error performing partial update: {ex.Message}");
            _logger.LogError(ex, "Partial update users command failed");
        }
    }
}