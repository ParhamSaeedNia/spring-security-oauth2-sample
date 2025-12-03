# OAuth2 Authorization Server with Spring Security

A fully functional OAuth2 Authorization Server implementation using Spring Security with custom token handling, H2 database, and comprehensive Swagger documentation.

## Features

- ✅ **Authorization Code Grant Flow** - Complete OAuth2 authorization code flow
- ✅ **Access Token & Refresh Token** - JWT-based tokens with refresh capability
- ✅ **HTTP-only Cookies** - Secure token storage in HTTP-only cookies
- ✅ **Custom Token Validation** - Self-hosted token validation (no external dependencies)
- ✅ **H2 Database** - In-memory database for token persistence
- ✅ **Resource Server** - Protected resource endpoints with JWT validation
- ✅ **Swagger Documentation** - Complete API documentation with Swagger UI
- ✅ **API Consumer** - Ready-to-use client endpoints

## Technology Stack

- Spring Boot 4.0.0
- Spring Security OAuth2 Authorization Server
- Spring Security OAuth2 Resource Server
- H2 Database
- JPA/Hibernate
- Swagger/OpenAPI 3
- Thymeleaf (for login page)

## Prerequisites

- Java 17 or higher
- Maven 3.6+

## Getting Started

### 1. Build the Project

```bash
mvn clean install
```

### 2. Run the Application

```bash
mvn spring-boot:run
```

The application will start on `http://localhost:8080`

### 3. Access Points

- **Swagger UI**: http://localhost:8080/swagger-ui.html
- **API Docs**: http://localhost:8080/api-docs
- **H2 Console**: http://localhost:8080/h2-console
  - JDBC URL: `jdbc:h2:mem:oauth2db`
  - Username: `sa`
  - Password: (empty)

## Default Credentials

### User Accounts
- **Username**: `user` / **Password**: `password`
- **Username**: `admin` / **Password**: `admin`

### OAuth2 Client
- **Client ID**: `api-client`
- **Client Secret**: `secret`
- **Redirect URI**: `http://localhost:8080/login/oauth2/code/api-client`

## OAuth2 Flow

### 1. Get Authorization Code

Navigate to the authorization endpoint:

```
GET http://localhost:8080/oauth2/authorize?client_id=api-client&response_type=code&redirect_uri=http://localhost:8080/login/oauth2/code/api-client&scope=read write
```

You will be redirected to the login page. After successful login, you'll be redirected back with an authorization code.

### 2. Exchange Code for Tokens

```bash
POST http://localhost:8080/api/auth/token
Content-Type: application/x-www-form-urlencoded

code={authorization_code}&client_id=api-client&redirect_uri=http://localhost:8080/login/oauth2/code/api-client
```

**Response:**
- Access token and refresh token are set as HTTP-only cookies
- Response body also contains token information

### 3. Access Protected Resources

```bash
GET http://localhost:8080/api/resource/data
Authorization: Bearer {access_token}
```

Or the token will be automatically read from the HTTP-only cookie.

### 4. Refresh Access Token

```bash
POST http://localhost:8080/api/auth/refresh
```

The refresh token can be provided as a cookie (automatically) or in the request body.

## API Endpoints

### Public Endpoints

- `GET /api/public/info` - Get public information about the OAuth2 server

### Authentication Endpoints

- `POST /api/auth/token` - Exchange authorization code for tokens
- `POST /api/auth/refresh` - Refresh access token using refresh token
- `POST /api/auth/logout` - Logout and clear tokens
- `GET /api/auth/me` - Get current user information

### Resource Server Endpoints

- `GET /api/resource/data` - Get protected data (requires access token)
- `GET /api/resource/user` - Get user information from JWT
- `POST /api/resource/data` - Create data (requires write scope)

### OAuth2 Endpoints (Auto-configured)

- `GET /oauth2/authorize` - Authorization endpoint
- `POST /oauth2/token` - Token endpoint
- `GET /.well-known/jwks.json` - JWK Set endpoint

## Database Schema

The application uses H2 in-memory database with the following main table:

- `oauth2_authorization` - Stores authorization codes, access tokens, and refresh tokens

## Security Features

1. **HTTP-only Cookies**: Tokens are stored in HTTP-only cookies to prevent XSS attacks
2. **JWT Tokens**: Secure, stateless token format
3. **Custom Token Validation**: All token validation is handled internally
4. **Database Persistence**: Tokens are stored in H2 database for tracking and revocation

## Swagger Documentation

Access the interactive Swagger UI at:
- http://localhost:8080/swagger-ui.html

The Swagger documentation includes:
- All API endpoints
- Request/response schemas
- Authentication requirements
- Example requests

## Project Structure

```
src/main/java/ir/bpmellat/springsecurity/
├── config/
│   ├── AuthorizationServerConfig.java    # OAuth2 Authorization Server configuration
│   ├── ResourceServerConfig.java         # Resource Server configuration
│   ├── RegisteredClientConfig.java       # OAuth2 client registration
│   └── SwaggerConfig.java                # Swagger/OpenAPI configuration
├── controller/
│   ├── AuthController.java               # Authentication endpoints
│   ├── ResourceController.java           # Protected resource endpoints
│   ├── PublicController.java             # Public endpoints
│   └── LoginController.java              # Login page controller
├── entity/
│   └── OAuth2AuthorizationEntity.java    # Database entity for OAuth2 tokens
├── repository/
│   └── OAuth2AuthorizationRepository.java # Repository for OAuth2 tokens
└── service/
    └── CustomOAuth2AuthorizationService.java # Custom OAuth2 authorization service
```

## Configuration

### application.properties

Key configurations:
- H2 database settings
- JPA/Hibernate settings
- OAuth2 issuer URL
- Swagger/OpenAPI settings

## Testing

### Using Swagger UI

1. Open http://localhost:8080/swagger-ui.html
2. Use the "Authorize" button to authenticate
3. Test endpoints directly from the UI

### Using cURL

```bash
# Get authorization code (browser-based)
# Then exchange for token:
curl -X POST "http://localhost:8080/api/auth/token?code=YOUR_CODE&client_id=api-client&redirect_uri=http://localhost:8080/login/oauth2/code/api-client"

# Access protected resource
curl -X GET "http://localhost:8080/api/resource/data" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Notes

- Tokens are stored as HTTP-only cookies for security
- The H2 database is in-memory and will be cleared on restart
- For production, consider:
  - Using a persistent database (PostgreSQL, MySQL, etc.)
  - Enabling HTTPS and setting `secure` flag on cookies
  - Using proper password encoding for client secrets
  - Implementing token revocation
  - Adding rate limiting

## License

This project is provided as-is for educational purposes.

