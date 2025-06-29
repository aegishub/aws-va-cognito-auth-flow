# aws-va-cognito-auth-flow

# Simulation of authentication flow

**This project aims to demonstrate and explain the authentication process that makes use of components such as AWS Verified Access and AWS Cognito.**

**Task:** Demonstarate the ZeroTrust approach and study authentication flow. We publish the Web application to the Internet in a secure manner, without VPN and with the commonly used authentication function like (MFA, session control, password policies, abilities to integrate external identity provider OAuth/SAML).

**Tech stack:** Verified Access + Cognito + Nginx + FastAPI backend
- Verified Access is a secure gateway that allows us to publish an internal web app to users outside of the internal network.
- Cognito provides mature authentication functions (MFA, session control, password policies, and the ability to integrate external identity providers via OAuth or SAML).
- Nginx routes requests to the appropriate FastAPI backend endpoints.
- The FastAPI backend is an authentication backend that processes all authentication requests.
Nginx and the FastAPI backend together simulate a typical web application.

Betefits:

| Feature                    | Description                                                                                                      |
|----------------------------|------------------------------------------------------------------------------------------------------------------|
| No VPN                     | User path through secure authentication process with strict access controls.                                     |
| Seamless authentication    | Allows users to authenticate once on the *Verified Access* and get authorization to access the web application (specific backend configuration required). |
| Centralised user pool + external Identity provider | Google, Facebook, Apple. SAML, OIDC.                                                                       |
| Password policy            | Complexity, Temporary passwords                                                                                  |
| MFA                        | Authentication App, Email, Phone                                                                                 |
| Custom user attributes     | Set any attributes for auth tokens                                                                               |
| User account recovery      | Self-service recovery                                                                                            |
| User session management    | Manage session token lifetime                                                                                    |
| SDK support                | Amazon Cognito Identity Provider SDK for Python, Java, etc.                                                      |
| Extensions                 | Using Lambda functions:  <br> - Customize welcome messages and migrate users <br> - Customize tokens and log analytics events <br> - Custom challenges and responses for user sign-in, such as a CAPTCHA or a security question <br> - Customize email and SMS messages, senders, and localization |
| User login page customization | HTML style configuration                                                                                   |
| Logging                    | Log information about user connections and sessions.                                                              |

## The solution diagram

![Solution scheme](https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/images/Solution-scheme.jpg)

**Components:**
1. AWS EC2 instance for Web App (`t2.micro`)
2. Web App (simulates basic Auth requests)
- Nginx web server 
- Fast API auth backend (python)
3. AWS Internal Load balancer (with TLS termination)
4. AWS Cognito (one User pool)
5. AWS Verified Access for Web App publication (with authentication in the same Cognito User Pool)
6. AWS Certificate manager for domain test.my-site.com with DNS validation (the domain name is fictitious, but should have real DNS name that you own)
7. Cloudflare DNS records for test.my-site.com (Proxy mode)


## Authentication flow scheme
![Authentication flow](https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/images/auth_flow.png)

`Code of diagram` - https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/images/auth_flow_diagram_code.txt


## Step-by-Step Flow
 
### 1. User Opens the Website

- User navigates to: https://test.my-site.com
- Cloudflare resolves the domain and proxies the request to the Verified Access endpoint
`test.edge-xxxx.vai-xxxx.prod.verified-access.eu-central-1.amazonaws.com`

### 2. AWS Verified Access Intercepts and Authenticates

- Verified Access intercepts the request.
- If the user is not authenticated, it redirects the user to the Amazon Cognito Hosted UI (login screen).
- User authenticates via Cognito (username/password, social login, etc.).
- Cognito redirects back to Verified Access and with a session cookies + specific authorization header which Verified Access Endpoint check each time during user’s requests.
  `AWSVAAuthSessionCookies` - Verified Access Session cookies.
  `x-amzn-ava-user-context` - Verified Access JWT token (in the form of HTTP header, not in session cookies).

### 3. Verified Access check access policy

- Verified Access check access policy to make sure that user request is allowed (Based on Verified Access Access group policy)

### 4. Verified Access Validates Tokens and Grants Access

- Verified Access verifies the  Session cookies.via Cognito.
- It then:
  Establishes a secure session
  Sets cookies (containing the Cognito tokens)
  Forwards the original request to the backend (your Web Application), including: `x-amzn-ava-user-context` HTTP header with signed user context.

### 5. Verified Access Redirects to Web Application

- Verified Access completes authentication with a redirect to Web Application root directory (/) endpoint https://test.my-site.com
- However, since Web Application also configured to use Cognito for authentication, it checks for its own session or authentication tokens related to the user. Finding none, it redirects the user to Cognito's authorization endpoint to initiate the OAuth Authorization Code Grant flow. https://eu-central-1_abracadabra.auth.eu-central-1.amazoncognito.com/login
  In addition Web Application validate VA header `x-amzn-ava-user-context`

- But Cognito recognize that user already authenticated and have existing user session (based on Cognito user session cookies received during VA authentication) and immediately redirects the user back to the Web Application's callback URL with an authorization code. User don’t pass the Login sessions again.

> All further communication occurs through the internal network, requests are tunneled between the VA instance and the internal load balancer through which the web application is published. All requests are supplemented with VA session cookies + `x-amzn-ava-user-context` HTTP header. The head can be validated on the backend, additionally making sure that the user is authorized on the VA.


### The Web Application receives the request at /callback.
https://test.my-site.com/callback

- It extracts the authorization code from the query parameter.
- It exchanges the code for tokens at:
`POST https://eu-central-1_abracadabra.auth.eu-central-1.amazoncognito.com/oauth2/token`
- Tokens obtained:
  `id_token` (JWT)
  `access_token` (JWT)
  (Optional) `refresh_token`(JWT)
- Tokens are stored (typically in cookies), and the user is now authenticated inside the Web App.

### User is Fully Authenticated in the Web Application

- With the token exchange complete, the Web Application now establishes its own session for the user.
- The application can now:
  - Use claims in the id/access token for user identity and roles.
  - Authorize access to specific group membership.
- Subsequent requests to the Web Application are served as authenticated.

### Logout Flow

User accesses: 
https://test.my-site.com/signout
- The app clears session and cookies.
- Redirects user to Cognito’s logout endpoint:
https://eu-central-1_abracadabra.auth.eu-central-1.amazoncognito.com/logout?client_id=...&logout_uri=https://test.my-site.com/signout/complete
- Cognito logs user out and redirects to Cognito Login page

## Web application configuration

Web application developed for demonstration purposes. 
It shows the way of implementation OAuth client functions to support Cognito IdP auth flow.
These function implemented though Nginx routes + FastAPI Auth backend server.

> Nginx listen on HTTP 80 port.
termination of TLS traffic occurs on the Load balancer level, so Nginx doesn’t use double TLS termination. It is also possible use the k8S Ingres in front of the Nginx.

![Web application configuration](https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/images/webapp_components.png)
`Code of diagram` - https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/images/webapp_components.txt

## Authentication backend Flow

Authentication process in Web application and relationships between Web app components
![Authentication backend Flow](https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/images/webauth_flow_diagram.png)
`Code of diagram` - https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/images/webauth_flow_diagram.txt


## Nginx routes

Nginx have the endpoint definition to route traffic to Auth backend.

| Route                      | Description                                                                                                             |
|----------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `location /`               | All protected resources  <br> Checks for authorization; if not authorized, redirects to the login page for authorization.|
| `location = /login`        | Requires the user to pass through Cognito authentication.                                                              |
| `location = /auth/verify`  | Handles verification of the user auth tokens, called by the `auth_request` directive in the `/` location block.  |
| `location = /callback`     | Handles the response from Cognito after the user has logged in.                                                    |
| `location = /signout`      | Handles the signout process.                                                                                        |

This is a default Nginx config in `/etc/nginx/nginx.conf` - https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/nginx.conf
- Here we declare the the log format function only.

This is the main config where we described all necessary routes for Auth backend to support OAuth client functions `/etc/nginx/conf.d/main.conf` - https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/nginx_additional.conf
> You can supplement these routes depending on the function of your application.
> You can also define Nginx config in one sigle file, it is up to you.

---
## Auth backend
> Auth backend implemented in the form of Fast API application based on on python code.
It works as systemd service.
Auth backend code - https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/auth_backend.py
Auth bakcend systemd config - https://github.com/aegishub/aws-va-cognito-auth-flow/blob/main/auth-backend.service


### Main functions
These are the main functions that must be implemented for proper operation of OAuth 2.0 client.
It is critical to implement all necessary key checks and verification

| Function                      | Description                                                                                                             |
|-------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `verify`                      | Verifies the id_token and access_token from cookies. Decodes and validates the tokens, checks expiration times, and returns the verified user information.|
| `callback`                    | Handles the Cognito callback after user authentication. Exchanges the authorization code for tokens, validates the tokens, sets cookies (id_token, access_token), and redirects the user to the home page.|
| `exchange_code_for_token`     | Exchanges an authorization code for tokens (id_token, access_token, refresh_token) by making a POST request to Cognito's token endpoint.|
| `verify_amzn_context`         | Middleware that validates the x-amzn-ava-user-context header from Verified Access. If the header is missing or invalid, it raises a 403 Forbidden error.|
| `decode_jwt`                  | Decodes and validates a JWT token using the public key from Cognito's JWKS endpoint. Checks claims such as exp (expiration time) and optionally verifies the at_hash claim.|
| `verify_at_hash`              | Verifies the at_hash claim in the id_token by calculating the hash of the access_token and comparing it to the at_hash value in the token.|
| `http_exception_handler`      | Handles HTTPException errors, logs the status code and error details, and returns a JSON response with the error information.|
| `general_exception_handler`   | Handles general exceptions, logs the error details, and returns a JSON response with a generic "Internal Server Error" message.|
| `get_public_keys`        | Fetches the public keys from Cognito's JWKS endpoint for verifying JWT tokens.                                                |
| `get_verified_access_keys`    | Fetches the public key from Verified Access's JWKS endpoint for validating Verified Access tokens.|
| `validate_verified_access_token` | Validates the Verified Access token by decoding it using the public key from Verified Access's JWKS endpoint. Checks claims such as additional_user_context and exp.|
| `start_login`                 | Redirects the user to Cognito's Hosted UI for login by generating the login URL with required parameters (client_id, response_type, scope, redirect_uri).|
| `health_check`                | A simple health check endpoint that returns {"status": "ok"}.|
| `signout`                     | Handles user signout by redirecting to Cognito's logout endpoint and deleting cookies (id_token, access_token).|
| `home`                        | A simple endpoint that returns a welcome message for the FastAPI backend. |


#### Auth tokens

When user authenticated Cognito generate 2 tokens - id_token + access_token.
These are JWT tokens, stored in a cookes. Pay attention to all tokens verification that should be performed on the backend. 
| Token/Header              | Purpose                                                                                                                                                                                                                                          | Validations Performed                                                                                                                                                           |
|---------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `access_token`            | Issued by Cognito after user authentication. Used for authorizing API requests. Contains permissions and scopes for accessing protected resources.                                                                                                | Decoded using Cognito's JWKS public keys.  <br> Verification for this token:  <br> • `exp` (ensures the token is not expired) <br> • `aud` (matches the CLIENT_ID) <br> • `issuer` (matches the Cognito issuer URL) <br> • digital signatures of token |
| `x-amzn-ava-user-context` | Issued by AWS Verified Access. Contains additional user context information for authorization. Used to validate the user's access to the application. It is a supplemental verification, helps to avoid compromising requests that did not come through Verified Access. | Decoded using Verified Access's JWKS public keys.  <br> Verification for this token:  <br> • `additional_user_context` (ensures the field exists) <br> • `exp` (ensures the token is not expired) <br> • `signer` (matches the expected Verified Access signer) |
| Cookies (`id_token`, `access_token`) | Stored in the browser as `HTTP only` and `secure=True` cookies.  <br> Used for maintaining user authentication and authorization state across requests.                                                                                    | Retrieved and validated during `/auth/verify` and other protected routes. Validations are the same as those performed for `id_token` and `access_token`.                                                              |


**ID token**
<pre>`Header
{
  "kid": "yh2kulNwY7z1BCeWbJPHF2YzyZ6ihKtL4igtxS7YeCs=",
  "alg": "RS256"
}
Payload
{
  "at_hash": "9-_JzdWbZ4q6rFUcel1zPw",
  "sub": "0324b8a2-f0e1-7043-2242-8c04d6b58039",
  "cognito:groups": [
    "BO_users_Project_operators",
    "BO_users_Project_admins"
  ],
  "email_verified": true,
  "iss": "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_ukcGcV1yu",
  "cognito:username": "0324b8a2-f0e1-7043-2242-8c04d6b58039",
  "aud": "2q3m5ppkkvoc7bis8mfpm4g8gm",
  "token_use": "id",
  "auth_time": 1748859346,
  "exp": 1748888146,
  "iat": 1748859346,
  "email": "zelkoalex@gmail.com"
}`</pre>



