# NuGet Package Build & Publishing Guide

This folder contains the generated NuGet packages and serves as a guide for building and publishing the `Hellenic.Identity.SDK` package.

## Prerequisites

- .NET 9.0 SDK or higher
- NuGet account (for publishing to NuGet.org)
- API key from NuGet.org (for publishing)

## Building the Package

### 1. Automatic Build (Recommended)

The project is configured with `<GeneratePackageOnBuild>true</GeneratePackageOnBuild>` in the `.csproj` file, so packages are automatically generated on build:

```bash
# Build in Release mode (creates optimized package)
dotnet build --configuration Release

# The package will be created in: src/bin/Release/
```

### 2. Manual Package Creation

```bash
# Create package manually
dotnet pack src/Hellenic.Identity.SDK.csproj --configuration Release --output ./nupkg
# dotnet nuget push ./nupkg/Hellenic.Identity.SDK.1.0.7.nupkg --api-key YOUR-API-KEY --source https://api.nuget.org/v3/index.json

# Create package with specific version
dotnet pack src/Hellenic.Identity.SDK.csproj --configuration Release --output ./nupkg -p:PackageVersion=1.0.7
```

### 3. Clean Build

```bash
# Clean previous builds and create fresh package
dotnet clean
dotnet build --configuration Release
```

## Package Configuration

The package metadata is configured in [`src/Hellenic.Identity.SDK.csproj`](../src/Hellenic.Identity.SDK.csproj):

```xml
<PropertyGroup>
    <!-- Package metadata for NuGet publishing -->
    <PackageId>Hellenic.Identity.SDK</PackageId>
    <Version>1.0.7</Version>
    <Authors>Gerasimos Maropoulos</Authors>
    <Description>Hellenic Identity SDK for JWT authentication and user management with EdDSA/Ed25519 support and generic user model structure</Description>
    <PackageTags>jwt;authentication;identity;sdk;generic;hellenic;eddsa;ed25519</PackageTags>
    <RepositoryUrl>https://github.com/kataras/identity-sdk-csharp</RepositoryUrl>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
    <GeneratePackageOnBuild>true</GeneratePackageOnBuild>
</PropertyGroup>
```

## Version Management

### Semantic Versioning

Follow [Semantic Versioning (SemVer)](https://semver.org/) guidelines:

- **Major** (`1.0.0` → `2.0.0`): Breaking changes
- **Minor** (`1.0.0` → `1.1.0`): New features, backward compatible
- **Patch** (`1.0.0` → `1.0.1`): Bug fixes, backward compatible

### Update Version

1. **Edit the `.csproj` file**:
```xml
<Version>1.0.1</Version>
```

2. **Use command line**:
```bash
dotnet pack -p:PackageVersion=1.0.1
```

3. **Use MSBuild properties**:
```bash
dotnet build -p:Version=1.0.1 --configuration Release
```

## Publishing to NuGet.org

### 1. Get API Key

1. Login to [nuget.org](https://www.nuget.org)
2. Go to **Account Settings** → **API Keys**
3. Create new API key with appropriate permissions

### 2. Configure API Key

```bash
# Set API key (one-time setup)
dotnet nuget setapikey YOUR_API_KEY_HERE --source https://api.nuget.org/v3/index.json
```

### 3. Publish Package

```bash
# Publish latest package in nupkg folder
dotnet nuget push ./nupkg/Hellenic.Identity.SDK.1.0.7.nupkg --source https://api.nuget.org/v3/index.json

# Publish with specific API key
dotnet nuget push ./nupkg/Hellenic.Identity.SDK.1.0.7.nupkg --api-key YOUR_API_KEY --source https://api.nuget.org/v3/index.json
```

### 4. Verify Publication

Check your package at: `https://www.nuget.org/packages/Hellenic.Identity.SDK/`

## Local Package Testing

### 1. Create Local NuGet Feed

```bash
# Create local folder for packages
mkdir C:\LocalNuGetFeed

# Add local source
dotnet nuget add source C:\LocalNuGetFeed --name Local
```

### 2. Push to Local Feed

```bash
# Copy package to local feed
copy ./nupkg/Hellenic.Identity.SDK.1.0.7.nupkg C:\LocalNuGetFeed\
```

### 3. Test Local Package

```bash
# Create test project
dotnet new console -n TestApp
cd TestApp

# Add package from local feed
dotnet add package Hellenic.Identity.SDK --source Local

# Restore packages
dotnet restore
```

## Publishing Workflow

### Complete Release Process

1. **Update Version**
```bash
# Edit src/Hellenic.Identity.SDK.csproj version number
# Commit version change
git commit -am "Bump version to 1.0.1"
git tag v1.0.1
git push origin main --tags
```

2. **Build & Test**
```bash
# Clean build
dotnet clean
dotnet build --configuration Release

# Run tests
dotnet test

# Verify package contents
dotnet pack --configuration Release --output ./nupkg
```

3. **Publish**
```bash
# Publish to NuGet.org
dotnet nuget push ./nupkg/Hellenic.Identity.SDK.1.0.1.nupkg --source https://api.nuget.org/v3/index.json
```

4. **Verify**
- Check package appears on NuGet.org
- Test installation in a new project
- Update documentation if needed

## Package Contents Verification

### Inspect Package Contents

```bash
# Install NuGet Package Explorer tool
dotnet tool install -g NuGetPackageExplorer

# Or use command line to list contents
7z l ./nupkg/Hellenic.Identity.SDK.1.0.7.nupkg
```

### Expected Package Structure

```
Hellenic.Identity.SDK.1.0.7.nupkg
├── lib/
│   └── net9.0/
│       ├── Hellenic.Identity.SDK.dll
│       └── Hellenic.Identity.SDK.xml (documentation)
├── dependencies/
│   ├── Microsoft.Extensions.Logging.Abstractions (≥ 9.0.0)
│   ├── Microsoft.Extensions.Options (≥ 9.0.0)
│   ├── System.IdentityModel.Tokens.Jwt (≥ 8.2.1)
│   └── ... (other dependencies)
└── package metadata
```

## Troubleshooting

### Common Issues

1. **Build Errors**
```bash
# Clean solution and rebuild
dotnet clean
dotnet restore
dotnet build --configuration Release
```

2. **Missing Dependencies**
```bash
# Restore NuGet packages
dotnet restore
```

3. **Version Conflicts**
```bash
# Clear NuGet cache
dotnet nuget locals all --clear
```

4. **Publishing Permission Errors**
- Verify API key is valid and has push permissions
- Check package name doesn't conflict with existing packages
- Ensure you own the package ID (if updating existing package)

### Package Validation

```bash
# Validate package before publishing
dotnet nuget verify ./nupkg/Hellenic.Identity.SDK.1.0.7.nupkg
```

## Best Practices

1. **Always test packages locally before publishing**
2. **Use Release configuration for published packages**
3. **Include comprehensive XML documentation**
4. **Follow semantic versioning strictly**
5. **Test package installation in clean environments**
6. **Keep package metadata up to date**
7. **Use proper dependency version ranges**

## Automated Publishing (CI/CD)

### GitHub Actions Example

```yaml
# .github/workflows/publish.yml
name: Publish NuGet Package

on:
  push:
    tags: [ 'v*' ]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup .NET
      uses: actions/setup-dotnet@v3
      with:
        dotnet-version: '9.0.x'
    
    - name: Build
      run: dotnet build --configuration Release
      
    - name: Test
      run: dotnet test
      
    - name: Pack
      run: dotnet pack --configuration Release --output ./nupkg
      
    - name: Push to NuGet
      run: dotnet nuget push ./nupkg/*.nupkg --api-key ${{secrets.NUGET_API_KEY}} --source https://api.nuget.org/v3/index.json
```

---

**Happy packaging! 📦**