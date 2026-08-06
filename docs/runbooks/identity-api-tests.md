# Identity API E2E Tests

This document describes the end-to-end tests for the Identity API endpoints (Session and UserIdentity) exposed by auth-provider-zitadel.

## Overview

The Identity API tests verify that:
- **Session API**: Exposes active user sessions
- **UserIdentity API**: Exposes user's linked external identity providers

Both are **read-only, dynamic resources** that query Zitadel in real-time and don't persist in etcd.

## Test Coverage

### Session API Tests

1. **Resource Registration**
   - Verifies `sessions` resource is registered in `identity.miloapis.com` API group
   - Confirms the resource is accessible via kubectl

2. **List Operation**
   - Tests that Session resources can be listed successfully
   - Validates response structure (APIVersion, Kind)
   - Handles empty results gracefully

3. **Schema Validation**
   - If sessions exist, verifies required fields:
     - `userUID` - User's unique identifier
     - `provider` - Authentication provider used
   - Validates metadata (name, etc.)

4. **API Group/Version**
   - Confirms correct API group: `identity.miloapis.com/v1alpha1`
   - Verifies singular name: `session`

### UserIdentity API Tests

1. **Resource Registration**
   - Verifies `useridentities` resource is registered in `identity.miloapis.com` API group
   - Confirms the resource is accessible via kubectl

2. **List Operation**
   - Tests that UserIdentity resources can be listed successfully
   - Validates response structure (APIVersion, Kind)
   - Handles empty results gracefully

3. **Schema Validation**
   - If useridentities exist, verifies required fields:
     - `userUID` - User's unique identifier
     - `providerID` - Identity provider's unique identifier
     - `providerName` - Human-readable provider name (e.g., "GitHub", "Google")
     - `username` - User's username in the external provider
   - Validates metadata (name, etc.)
   - Displays found identities for debugging

4. **API Group/Version**
   - Confirms correct API group: `identity.miloapis.com/v1alpha1`
   - Verifies singular name: `useridentity`

### Integration Tests

1. **API Group Consistency**
   - Verifies both `sessions` and `useridentities` are in the same API group
   - Confirms they're both accessible

2. **Resource Explanation**
   - Tests that both resources can be described via `kubectl explain`
   - Validates API documentation is available

## Running the Tests

### Using Taskfile (Recommended)

The easiest way to run these tests is using the Taskfile commands:

```bash
# Run all Identity API tests
task test:identity-api

# Run only Session API tests
task test:identity-api:sessions

# Run only UserIdentity API tests
task test:identity-api:useridentities

# Run with verbose output (shows detailed test steps)
task test:identity-api:verbose
```

### Using Go Test Directly

You can also run the tests directly with `go test`:

### Prerequisites

Before running these tests, ensure:

1. **Cluster Access**
   - kubectl configured to access your cluster
   - Valid authentication credentials

2. **Deployments**
   - Milo API server is running
   - auth-provider-zitadel is deployed and connected to Zitadel
   - Zitadel instance is accessible

3. **Dependencies**
   - Go 1.21 or later
   - Ginkgo test framework

### Running All Identity API Tests

```bash
# Run only Identity API tests (skips image building)
go test -v ./test/e2e -ginkgo.focus="Identity API"
```

### Running Specific Test Suites

```bash
# Run only Session API tests
go test -v ./test/e2e -ginkgo.focus="Session API"

# Run only UserIdentity API tests
go test -v ./test/e2e -ginkgo.focus="UserIdentity API"

# Run only integration tests
go test -v ./test/e2e -ginkgo.focus="Identity API Integration"
```

### Running Specific Test Cases

```bash
# Test session resource registration
go test -v ./test/e2e -ginkgo.focus="should have the sessions resource registered"

# Test useridentity schema validation
go test -v ./test/e2e -ginkgo.focus="should return UserIdentity resources with correct schema"
```

### Running with Verbose Output

```bash
# Show detailed test output
go test -v ./test/e2e -ginkgo.focus="Identity API" -ginkgo.v
```

## Test Behavior

### Graceful Handling of Empty Results

The tests are designed to handle scenarios where no resources exist:

- **No Sessions**: Tests pass with a warning message if no active sessions are found
- **No UserIdentities**: Tests pass with a warning message if no external identities are linked

This is expected behavior since:
- Sessions are ephemeral and may not exist during testing
- UserIdentities only exist if users have linked external providers

### Expected Output

Successful test run:
```
Identity API
  Session API
    ✓ should have the sessions resource registered
    ✓ should be able to list Session resources
    ⚠️  No Session resources found - this is expected if no active sessions exist
    ✓ should have correct API group and version
  UserIdentity API
    ✓ should have the useridentities resource registered
    ✓ should be able to list UserIdentity resources
    ✓ Found UserIdentity: github-123 (Provider: GitHub, Username: johndoe)
    ✓ should have correct API group and version
  Identity API Integration
    ✓ should have both sessions and useridentities in the same API group
    ✓ should be able to describe both resource types

Ran 10 of 10 Specs in 2.345 seconds
SUCCESS!
```

## Troubleshooting

### "resource not found" errors

**Problem**: Tests fail with "the server doesn't have a resource type 'sessions'" or similar

**Solution**:
1. Verify auth-provider-zitadel is deployed:
   ```bash
   kubectl get pods -n auth-provider-zitadel-system
   ```

2. Check that the API server is running:
   ```bash
   kubectl get apiservices | grep identity.miloapis.com
   ```

3. Verify Milo API server is accessible:
   ```bash
   kubectl get --raw /apis/identity.miloapis.com/v1alpha1
   ```

### Connection errors

**Problem**: Tests fail with connection timeouts or authentication errors

**Solution**:
1. Verify kubectl context is correct:
   ```bash
   kubectl config current-context
   ```

2. Test basic cluster access:
   ```bash
   kubectl get nodes
   ```

3. Check authentication:
   ```bash
   kubectl auth can-i get sessions
   ```

### Schema validation failures

**Problem**: Tests fail when validating resource schema

**Solution**:
1. Check the actual resource structure:
   ```bash
   kubectl get sessions -o yaml
   kubectl get useridentities -o yaml
   ```

2. Verify milo types are up to date:
   ```bash
   # In milo repository
   git log --oneline pkg/apis/identity/v1alpha1/
   ```

3. Ensure auth-provider-zitadel is using the latest milo types:
   ```bash
   # In auth-provider-zitadel repository
   go list -m go.miloapis.com/milo
   ```

## Test Design Philosophy

These tests follow these principles:

1. **Lightweight**: Don't require building Docker images or deploying the operator
2. **Cluster-based**: Run against an existing deployment
3. **Graceful**: Handle missing resources without failing
4. **Informative**: Provide clear output about what was found
5. **Independent**: Can run separately from the full e2e suite

## Integration with CI/CD

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Identity API Tests
  run: |
    # Configure kubectl to access test cluster
    kubectl config use-context test-cluster
    
    # Run tests
    go test -v ./test/e2e -ginkgo.focus="Identity API"
```

## Related Documentation

- [Architecture Overview](../architecture.md)
- [Milo Identity API Documentation](https://github.com/milo-os/milo/blob/main/docs/api/identity.md)
- [Zitadel Integration](https://zitadel.com/docs)
