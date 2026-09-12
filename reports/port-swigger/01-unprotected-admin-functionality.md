# PortSwigger Web Security Academy — Unprotected Admin Functionality

## Overview

- **Platform:** PortSwigger Web Security Academy
- **Category:** Access Control
- **Lab:** Unprotected admin functionality
- **Difficulty:** Apprentice
- **Status:** Solved
- **Date:** 2026-09-13

## Objective

Identify an exposed administrator interface and use the missing access-control protection to complete the lab objective.

## Vulnerability Summary

The application exposes an administrative endpoint without requiring authentication or verifying that the requester has administrator privileges.

This is a **broken access control** issue. A sensitive function exists at a predictable/discoverable URL, but the server does not enforce authorization before serving the page or processing administrative actions.

## Discovery

I checked the site's `robots.txt` file and found that it disclosed the path of the administrator panel through a `Disallow` entry.

This showed an important distinction:

- `robots.txt` can ask search-engine crawlers not to index a path.
- It does **not** provide access control.
- Sensitive routes should never rely on obscurity or crawler directives for protection.

## Reproduction

1. Open the lab application.
2. Request `/robots.txt`.
3. Identify the administrator-panel path disclosed in the file.
4. Navigate directly to the administrator panel.
5. Confirm that the page is accessible without administrator authentication.
6. Use the exposed administrative function to delete the target user specified by the lab.
7. The lab reports the challenge as solved.

## Root Cause

The server failed to enforce authorization checks on the administrator endpoint and its privileged actions.

The administrator URL being referenced by `robots.txt` made the endpoint easier to discover, but endpoint disclosure itself was not the core vulnerability. The critical issue was that an unauthenticated or unauthorized user could access privileged functionality.

## Security Impact

In a real application, this type of flaw could allow an attacker to perform administrator-only actions such as:

- deleting or modifying user accounts,
- viewing sensitive administrative data,
- changing application configuration,
- or abusing other privileged functions exposed by the panel.

The exact impact depends on which administrator operations are available.

## Remediation

The application should enforce access control on the server for every administrator page and administrative action.

Recommended controls include:

1. Require authentication before accessing administrative functionality.
2. Verify the authenticated user's role or permissions on every privileged request.
3. Return an appropriate denial response when authorization fails.
4. Do not treat hidden URLs, unusual paths, or `robots.txt` directives as security controls.
5. Apply authorization consistently to both the user interface and the underlying action endpoints.

## What I Learned

This lab demonstrated that discovering a hidden administrative route is only part of the problem. The real security boundary must be implemented by the server through authorization checks.

A path that is unlinked, difficult to guess, or excluded from search engines should still be considered reachable by an attacker.

## Scope and Ethics

This exercise was completed only inside the intentionally vulnerable PortSwigger Web Security Academy lab environment for educational purposes.
