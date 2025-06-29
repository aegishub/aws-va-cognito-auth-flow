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





