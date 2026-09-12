# PortSwigger Web Security Academy — User ID Controlled by Request Parameter

## Overview

- **Platform:** PortSwigger Web Security Academy
- **Category:** Access Control
- **Lab:** User ID controlled by request parameter
- **Difficulty:** Apprentice
- **Status:** Solved
- **Date:** 2026-09-13

## Objective

Identify a horizontal privilege-escalation vulnerability caused by a user-controlled account identifier and access another user's account information.

## Vulnerability Summary

The application uses a request parameter to decide which user's account page should be displayed, but it does not properly verify that the requested user is the currently authenticated user.

This is a **broken access control** vulnerability, specifically **horizontal privilege escalation**. A normal authenticated user can modify an identifier in the request and access data belonging to another user with the same privilege level.

## Discovery

After logging in, I opened the account page and observed that the requested account was selected through a user-controlled parameter in the URL.

The important observation was that the server trusted the supplied user identifier instead of binding the request to the identity stored in the authenticated session.

Because the identifier was editable, I tested whether changing it to another username would return that user's account information.

## Reproduction

1. Log in to the lab with the credentials provided by PortSwigger.
2. Open the account page.
3. Inspect the URL or request and identify the parameter used to select the user account.
4. Change the parameter value from the currently logged-in username to `carlos`.
5. Send the modified request.
6. Confirm that the server returns Carlos's account page even though the session belongs to a different user.
7. Obtain the API key displayed on Carlos's account page.
8. Submit the API key to complete the lab.
9. The lab reports the challenge as solved.

## Root Cause

The application performs authentication but fails to perform an object-level authorization check when serving account information.

The server effectively trusts a client-supplied user identifier. It does not verify that the authenticated session is authorized to access the requested account object.

The vulnerable logic can be summarized as:

- user is authenticated,
- request contains a target user identifier,
- server loads that target user's data,
- but server does not verify that the target user matches the authenticated user.

## Security Impact

In a real application, this type of vulnerability could allow one user to access another user's private information.

Depending on the affected endpoint, an attacker might be able to:

- view personal account information,
- obtain API keys or other credentials,
- access private documents or records,
- modify another user's data,
- or perform actions on another user's account.

If the same pattern exists across multiple endpoints, the impact can extend far beyond a single information-disclosure issue.

## Remediation

The server should perform authorization checks for every object or account requested by an authenticated user.

Recommended controls include:

1. Derive the current user's identity from the authenticated session rather than trusting a client-supplied username or user ID.
2. If an object identifier must be supplied by the client, verify that the authenticated user is authorized to access that specific object.
3. Apply object-level authorization consistently to both read and write operations.
4. Return an appropriate denial response when a user attempts to access another user's resources.
5. Do not assume that unpredictable or hidden identifiers are a substitute for authorization.

## What I Learned

This lab demonstrated the difference between authentication and authorization.

Being logged in only proves who the user is. The server must still check whether that user is allowed to access the specific account or object requested.

A user-controlled identifier such as a username, numeric account ID, or other object reference should always be treated as untrusted input when it affects access to sensitive resources.

## Scope and Ethics

This exercise was completed only inside the intentionally vulnerable PortSwigger Web Security Academy lab environment for educational purposes.
