# Security Policy

Supply Chain Guard is a local defensive tool. It can reduce accidental exposure to risky package artifacts, but it is not a malware sandbox and does not prove a package is safe.

## Reporting A Vulnerability

Please report security issues privately by opening a GitHub security advisory for this repository, or by contacting the maintainer through the GitHub profile associated with the repository.

Do not include live secrets, API keys, private packages, or proprietary source code in public issues.

## Supported Versions

The `main` branch is the only supported version while the project is pre-1.0.

## Secret Handling

Do not commit `.env`, `.env.local`, `.scguard/`, generated reports, package tarballs, or 1Password exports. Socket API keys should be stored in:

```sh
~/.config/supply-chain-guard/env
```
