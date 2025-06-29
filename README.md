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
1. AWS EC2 instance for Web App (t2.micro)
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


## Step-by-Step Flow
 
### 1. User Opens the Website

- User navigates to: https://test.my-site.com
- Cloudflare resolves the domain and proxies the request to the Verified Access endpoint
test.edge-xxxx.vai-xxxx.prod.verified-access.eu-central-1.amazonaws.com

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
  Forwards the original request to the backend (your Web Application), including:
  x-amzn-ava-user-context HTTP header with signed user context.

### 5. Verified Access Redirects to Web Application

- Verified Access completes authentication with a redirect to Web Application root directory (/) endpoint https://test.my-site.com
- However, since Web Application also configured to use Cognito for authentication, it checks for its own session or authentication tokens related to the user. Finding none, it redirects the user to Cognito's authorization endpoint to initiate the OAuth Authorization Code Grant flow. https://eu-central-1_abracadabra.auth.eu-central-1.amazoncognito.com/login
  In addition Web Application validate VA header x-amzn-ava-user-context

- But Cognito recognize that user already authenticated and have existing user session (based on Cognito user session cookies received during VA authentication) and immediately redirects the user back to the Web Application's callback URL with an authorization code. User don’t pass the Login sessions again.

> All further communication occurs through the internal network, requests are tunneled between the VA instance and the internal load balancer through which the web application is published. All requests are supplemented with VA session cookies + x-amzn-ava-user-context HTTP header. The head can be validated on the backend, additionally making sure that the user is authorized on the VA.


### The Web Application receives the request at /callback.
https://test.my-site.com/callback

- It extracts the authorization code from the query parameter.
- It exchanges the code for tokens at:
'POST https://eu-central-1_abracadabra.auth.eu-central-1.amazoncognito.com/oauth2/token'
- Tokens obtained:
  'id_token' (JWT)
  'access_token' (JWT)
  (Optional) refresh_token
- Tokens are stored (typically in cookies), and the user is now authenticated inside the Web App.

### User is Fully Authenticated in the Web Application

- With the token exchange complete, the Web Application now establishes its own session for the user.
- The application can now:
  - Use claims in the ID/Access token for user identity and roles.
  - Authorize access to specific group membership.
- Subsequent requests to the Web Application are served as authenticated.

### Logout Flow

User accesses: 
https://test.my-site.com/signout
- The app clears session and cookies.
- Redirects user to Cognito’s logout endpoint:
https://eu-central-1_abracadabra.auth.eu-central-1.amazoncognito.com/logout?client_id=...&logout_uri=https://test.my-site.com/signout/complete
- Cognito logs user out and redirects to Cognito Login page



