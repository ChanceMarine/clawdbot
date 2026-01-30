# Plugin Security

This document describes the security model for Clawdbot plugins, including verification, capabilities, and best practices.

## Plugin Sources

Plugins are classified by their source:

| Source | Description | Verification |
|--------|-------------|--------------|
| `builtin` | Plugins in `skills/` or `extensions/` directories | Trusted by default |
| `local` | Plugins from local workspace directories | Warning logged |
| `external` | Third-party plugins from npm or other sources | Warning logged |
| `unknown` | Source could not be determined | Warning logged |

## Plugin Verification

When plugins are loaded, Clawdbot performs verification checks:

1. **Path verification**: Checks if the plugin resides in a trusted directory
2. **Source classification**: Determines whether the plugin is builtin, local, or external
3. **Warning generation**: Logs warnings for unverified plugins

### Trusted Paths

The following paths are considered trusted:
- `skills/` - Built-in skill plugins
- `extensions/` - Official extension plugins

Plugins outside these paths will trigger security warnings but are still allowed to load.

## Plugin Capabilities

Plugins can request various capabilities through the registration API:

### Tools
- Register agent tools that can be invoked during conversations
- Tools have access to the current conversation context

### Hooks
- Register event handlers for system events
- Can intercept and modify message processing

### Channels
- Register messaging channel integrations
- Handle inbound/outbound messages for specific platforms

### Providers
- Register AI model providers
- Handle API communication with language models

### HTTP Handlers
- Register HTTP request handlers
- Extend the gateway's HTTP API

### Gateway Methods
- Register custom RPC methods
- Extend gateway functionality

### CLI Commands
- Register custom CLI commands
- Extend the command-line interface

### Services
- Register background services
- Long-running processes managed by the plugin system

## Security Best Practices

### For Plugin Users

1. **Review source code** before enabling external plugins
2. **Verify plugin authors** and check for known security issues
3. **Use official plugins** from the Clawdbot organization when possible
4. **Monitor plugin activity** through logs and diagnostics
5. **Keep plugins updated** to receive security patches

### For Plugin Developers

1. **Minimize permissions** - Only request capabilities your plugin needs
2. **Validate all inputs** - Never trust user-provided data
3. **Avoid storing secrets** in plugin code or config
4. **Use secure defaults** - Require explicit opt-in for sensitive features
5. **Document capabilities** - Clearly state what your plugin does
6. **Handle errors gracefully** - Don't expose sensitive information in errors

## Verification Warnings

When an unverified plugin is loaded, warnings are logged:

```
[plugins] my-plugin: External plugin not verified - use with caution
[plugins] my-plugin: External plugins may have elevated permissions
[plugins] my-plugin: Review plugin source code before enabling
```

These warnings appear in:
- Console output during startup
- Plugin diagnostics (`clawdbot plugins status`)

## Future Enhancements

The following security features are planned for future releases:

- **Cryptographic signatures**: Verify plugin integrity with digital signatures
- **Capability sandboxing**: Restrict plugin access to specific APIs
- **Runtime monitoring**: Detect and block suspicious plugin behavior
- **Audit logging**: Track all plugin activity for security review

## Reporting Security Issues

If you discover a security vulnerability in a Clawdbot plugin:

1. Do not disclose publicly
2. Contact the Clawdbot security team
3. Provide detailed reproduction steps
4. Allow time for a fix before disclosure
