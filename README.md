# aws-va-cognito-auth-flow
Simulation of authentication flow

This project aims to demonstrate and explain the authentication process that makes use of components such as AWS Verified Access and AWS Cognito.

Task: Demonstarate the ZeroTrust approach and study authentication flow. We publish the Web application to the Internet in a secure manner, without VPN and with the commonly used authentication function like (MFA, session control, password policies, abilities to integrate external identity provider OAuth/SAML).

Tech stack: Verified Access + Cognito + Nginx + FastAPI backend
- Verified Access is a secure gateway that allows us to publish an internal web app to users outside of the internal network.
- Cognito provides mature authentication functions (MFA, session control, password policies, and the ability to integrate external identity providers via OAuth or SAML).
- Nginx routes requests to the appropriate FastAPI backend endpoints.
- The FastAPI backend is an authentication backend that processes all authentication requests.
Nginx and the FastAPI backend together simulate a typical web application.

