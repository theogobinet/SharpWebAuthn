# SharpWebAuthn

A simple C# command-line tool to list and assert WebAuthN credentials using the Windows WebAuthN API.

## Features

- **List credentials:** Display all platform credentials available on the system.
- **Assert credential:** Perform an assertion (authentication) for a selected credential and challenge, outputting the result in a JSON format suitable for MFA validation.

## Installation

Build the project with Visual Studio 2022 or MSBuild.

### List credentials

Displays all available credentials with details such as version, credential ID, RP ID, user name, and more.

**Command:**
```
SharpWebAuthn.exe list
```

```
----------------------------------------
Credential 1
----------------------------------------
Version:             4
CredentialID (hex):  973C101E870856B6399F03ECD...
RP Id:               xxx.okta-emea.com
User Name:           xxx@yyy.com
Removable:           Yes
BackedUp:            No
ThirdPartyPayment:   No
----------------------------------------
Credential 2
----------------------------------------
Version:             4
CredentialID (hex):  53F5252108CA8DE98A496080E4...
RP Id:               login.microsoft.com
User Name:           xxx@yyy.com
Removable:           No
BackedUp:            No
ThirdPartyPayment:   No
========================================
```

### Assert a credential

```
SharpWebAuthn.exe assert <credential_number> <challenge_json>
```

- `credential_number`: The index of the credential as shown in the list output (starting from 1).
- `challenge_json`: The challenge string (usually a base64 or hex-encoded value) to use for the assertion.

**Example:**

```
SharpWebAuthn.exe assert 1 0-IRz_egA3jJZ1_vWvCm8jfE9Pd-WHOo
```

The output will be a JSON object:
```json
{"clientData": "eyJ0eXBlIjoid2ViYXV0aG4...","authenticatorData": "/LGjYJeD7A2wNo3AcD...","signatureData": "MEUCIBztyVAAkA7JXafGo73x..."}
```

This output can be used to validate Multi-Factor Authentication (MFA) on a server or service that supports WebAuthN.  
The fields are base64-encoded and correspond to the standard WebAuthN assertion response.

## Notes

- No external dependencies are required.
- The tool uses only the Windows WebAuthN API and standard .NET libraries.
- The assertion output is designed to be compatible with server-side MFA validation workflows.