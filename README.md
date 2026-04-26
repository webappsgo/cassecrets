# cassecrets

[![Build Status](https://jenkins.casjay.cc/buildStatus/icon?job=casapps/cassecrets)](https://jenkins.casjay.cc/job/casapps/job/cassecrets/)
[![GitHub release](https://img.shields.io/github/v/release/casapps/cassecrets)](https://github.com/casapps/cassecrets/releases)
[![License](https://img.shields.io/github/license/casapps/cassecrets)](LICENSE.md)

## About

cassecrets is a self-hosted secrets management platform that combines the best features of HashiCorp Vault, Doppler, and AWS Secrets Manager. It's completely free, open-source (MIT licensed), and has zero feature gating. Perfect for teams and individuals who want full control over their secrets infrastructure without enterprise pricing.

## Official Site

https://cassecrets.casapps.us

## Features

### Core Secrets Management
- **Encrypted Storage**: All secrets encrypted at rest with AES-256-GCM
- **Secret Versioning**: Full version history with rollback capability
- **Multiple Secret Types**: Strings, files, JSON, environment variables
- **Secret References**: Link secrets together for inheritance and dependencies
- **Access Audit Logs**: Complete audit trail of all secret access and modifications

### Team & Organization Support
- **Multi-tenant**: Full team/organization support
- **Custom Email Domains**: Restrict team access by email domain
- **Flexible Ownership**: Transfer ownership, invite members, manage permissions
- **Role-Based Access Control (RBAC)**: Granular permissions system
- **Individual & Team Modes**: Users can create personal spaces or team workspaces

### Authentication & Security
- **Multiple Auth Methods**: Local accounts, API keys, OIDC/OAuth2, LDAP
- **Two-Factor Authentication (2FA)**: Optional MFA for enhanced security
- **JWT & API Keys**: Flexible authentication for services and users
- **Token Rotation**: Automatic or manual token rotation policies
- **Rate Limiting**: Built-in protection against brute force attacks
- **IP Whitelisting**: Restrict secret access by IP address

### Developer Experience
- **REST API**: Complete RESTful API for all operations
- **CLI Tool**: Powerful command-line interface with interactive TUI mode
- **Environment Export**: Export secrets as environment variables
- **CI/CD Integration**: Built-in support for GitHub Actions, GitLab CI, Jenkins
- **Kubernetes Integration**: Secrets operator for K8s clusters
- **Docker Secrets**: Native Docker Secrets integration
- **Webhooks**: Real-time notifications on secret changes

### Advanced Features
- **Secret Sharing**: Share secrets with expiration times
- **Secret Templates**: Reusable secret templates
- **Environment-Specific**: Manage dev/staging/production secrets separately
- **Rotation Policies**: Automatic secret rotation with policies
- **Emergency Access**: Break-glass procedures for critical access
- **Clustering Support**: High availability with multi-node clustering
- **PostgreSQL/MySQL**: Support for external databases
- **Valkey/Redis**: Distributed caching and session management

### Self-Hosting First
- **Single Binary**: Deploy as a single static binary (no dependencies)
- **Docker Support**: Official Docker images for all platforms
- **8 Platform Builds**: Linux, macOS, Windows, FreeBSD (amd64, arm64)
- **SQLite Default**: Zero-configuration database out of the box
- **Tor Hidden Service**: Optional .onion address for enhanced privacy
- **Let's Encrypt**: Automatic SSL/TLS certificate management
- **Backup & Restore**: Built-in backup and restore functionality

## Production

### Docker (Recommended)

```bash
# Quick start with Docker Compose
docker-compose up -d

# Or with docker run
docker run -d \
  --name cassecrets \
  -p 80:80 \
  -v /var/lib/cassecrets:/var/lib/cassecrets \
  ghcr.io/casapps/cassecrets:latest
```

### Binary

```bash
# Download latest release
wget https://github.com/casapps/cassecrets/releases/latest/download/cassecrets-linux-amd64

# Make executable
chmod +x cassecrets-linux-amd64

# Run setup wizard
./cassecrets-linux-amd64 --maintenance setup

# Start server
./cassecrets-linux-amd64
```

## Configuration

Configuration is managed through `/etc/cassecrets/server.yml` (or custom path with `--config`).

```yaml
server:
  address: ":80"
  mode: production

database:
  type: sqlite
  path: /var/lib/cassecrets/db/server.db

secrets:
  encryption_key_path: /var/lib/cassecrets/keys/master.key
  versioning: true
  max_versions: 10

teams:
  allow_registration: false
  require_email_verification: true

auth:
  session_timeout: 24h
  jwt_secret_path: /var/lib/cassecrets/keys/jwt.key
  enable_oidc: false
  enable_ldap: false

security:
  enable_2fa: true
  rate_limit:
    enabled: true
    requests_per_minute: 100
```

## CLI Usage

The `cassecrets-cli` tool provides a powerful interface for managing secrets:

```bash
# Login to server
cassecrets-cli login https://secrets.example.com

# Get a secret
cassecrets-cli get production/api-key

# Set a secret
cassecrets-cli set production/database-url "postgresql://..."

# List secrets in a path
cassecrets-cli list production/

# Export as environment variables
export $(cassecrets-cli export production/ | xargs)

# Interactive TUI mode
cassecrets-cli --tui
```

## API

### Authentication

```bash
# Get API token
curl -X POST https://secrets.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'
```

### Secrets Management

```bash
# Get secret
curl -H "Authorization: Bearer $TOKEN" \
  https://secrets.example.com/api/v1/secrets/production/api-key

# Create/Update secret
curl -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value":"secret-value","type":"string"}' \
  https://secrets.example.com/api/v1/secrets/production/api-key

# List secrets
curl -H "Authorization: Bearer $TOKEN" \
  https://secrets.example.com/api/v1/secrets?path=production/

# Delete secret
curl -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  https://secrets.example.com/api/v1/secrets/production/api-key
```

## Migration Guides

### From HashiCorp Vault

```bash
# Export from Vault
vault kv get -format=json secret/data/myapp > vault-export.json

# Import to cassecrets
cassecrets-cli import vault-export.json --format vault
```

### From Doppler

```bash
# Export from Doppler
doppler secrets download --format json > doppler-export.json

# Import to cassecrets
cassecrets-cli import doppler-export.json --format doppler
```

### From AWS Secrets Manager

```bash
# Export from AWS
aws secretsmanager list-secrets --output json > aws-export.json

# Import to cassecrets
cassecrets-cli import aws-export.json --format aws
```

## Architecture

- **Backend**: Go (pure Go, CGO_ENABLED=0)
- **Database**: SQLite (default), PostgreSQL, MySQL
- **Cache**: Valkey/Redis (optional, for clustering)
- **Encryption**: AES-256-GCM for secrets at rest
- **Authentication**: Argon2id for passwords, JWT for API tokens
- **Frontend**: HTML templates with vanilla JavaScript
- **Deployment**: Single static binary or Docker container

## Clustering

cassecrets supports clustering for high availability:

```yaml
cluster:
  enabled: true
  node_name: node1
  
database:
  type: postgresql
  host: db.example.com
  port: 5432
  
cache:
  type: valkey
  hosts:
    - cache1.example.com:6379
    - cache2.example.com:6379
```

## Security Considerations

- **Encryption Keys**: Store master encryption keys securely (HSM, cloud KMS, or encrypted filesystem)
- **Network Security**: Use HTTPS/TLS in production (built-in Let's Encrypt support)
- **Access Control**: Enable RBAC and follow principle of least privilege
- **Audit Logs**: Regularly review access logs for suspicious activity
- **Backups**: Regularly backup your secrets database (encrypted)
- **Updates**: Keep cassecrets updated with latest security patches

## License

MIT License - see [LICENSE.md](LICENSE.md) for details.

## Development

See the development section in the full documentation for build instructions, testing, and contributing guidelines.

```bash
# Build from source
make dev

# Run tests
make test

# Build all platforms
make build

# Build Docker image
make docker
```

## Support

- **Documentation**: https://docs.cassecrets.casapps.us
- **Issues**: https://github.com/casapps/cassecrets/issues
- **Discussions**: https://github.com/casapps/cassecrets/discussions

---

Built with ❤️ by the casapps team. Self-hosted secrets management for everyone.
