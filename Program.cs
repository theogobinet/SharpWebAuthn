using System;
using System.Runtime.InteropServices;

using HRESULT = System.Int32;
internal static class User32
{
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
}

internal static class WebAuthN
{

    [DllImport("webauthn.dll", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    public static extern HRESULT WebAuthNGetPlatformCredentialList(
        ref WEBAUTHN_GET_CREDENTIALS_OPTIONS pGetCredentialsOptions,
        out IntPtr ppCredentialDetailsList // PWEBAUTHN_CREDENTIAL_DETAILS_LIST*
    );

    [DllImport("webauthn.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern void WebAuthNFreePlatformCredentialList(
        IntPtr pCredentialDetailsList // PWEBAUTHN_CREDENTIAL_DETAILS_LIST
    );

    [DllImport("webauthn.dll", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    public static extern HRESULT WebAuthNAuthenticatorGetAssertion(
        IntPtr hWnd, // HWND
        [MarshalAs(UnmanagedType.LPWStr)] string pwszRpId, // LPCWSTR
        ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
        IntPtr pWebAuthNGetAssertionOptions, // PCWEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
        out IntPtr ppWebAuthNAssertion // PWEBAUTHN_ASSERTION*
    );

    [DllImport("webauthn.dll", CallingConvention = CallingConvention.Winapi)]
    public static extern void WebAuthNFreeAssertion(
        IntPtr pWebAuthNAssertion // PWEBAUTHN_ASSERTION
    );
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_CREDENTIAL_DETAILS_LIST
{
    public uint cCredentialDetails;
    public IntPtr ppCredentialDetails; // PWEBAUTHN_CREDENTIAL_DETAILS*
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_CREDENTIAL_DETAILS
{
    public uint dwVersion;
    public uint cbCredentialID;
    public IntPtr pbCredentialID; // PBYTE
    public IntPtr pRpInformation; // PWEBAUTHN_RP_ENTITY_INFORMATION
    public IntPtr pUserInformation; // PWEBAUTHN_USER_ENTITY_INFORMATION
    [MarshalAs(UnmanagedType.Bool)]
    public bool bRemovable;
    [MarshalAs(UnmanagedType.Bool)]
    public bool bBackedUp;
    public IntPtr pwszAuthenticatorName; // PCWSTR
    public uint cbAuthenticatorLogo;
    public IntPtr pbAuthenticatorLogo; // PBYTE
    [MarshalAs(UnmanagedType.Bool)]
    public bool bThirdPartyPayment;
    public uint dwTransports;
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_RP_ENTITY_INFORMATION
{
    public uint dwVersion;
    public IntPtr pwszId; // PCWSTR
    public IntPtr pwszName; // PCWSTR
    public IntPtr pwszIcon; // PCWSTR
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_USER_ENTITY_INFORMATION
{
    public uint dwVersion;
    public uint cbId;
    public IntPtr pbId; // PBYTE
    public IntPtr pwszName; // PCWSTR
    public IntPtr pwszIcon; // PCWSTR
    public IntPtr pwszDisplayName; // PCWSTR
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_GET_CREDENTIALS_OPTIONS
{
    public uint dwVersion;
    public IntPtr pwszRpId; // LPCWSTR
    [MarshalAs(UnmanagedType.Bool)]
    public bool bBrowserInPrivateMode;
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_CREDENTIAL
{
    public uint dwVersion;
    public uint cbId;
    IntPtr pbId; // PBYTE
    IntPtr pwszCredentialType; // PCWSTR
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_CREDENTIALS
{
    public uint cCredentials;
    public IntPtr pCredentials; // PWEBAUTHN_CREDENTIAL
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
{
    public uint dwVersion;
    public uint dwTimeoutMilliseconds;
    public WEBAUTHN_CREDENTIALS CredentialList;
    public WEBAUTHN_EXTENSIONS Extensions;
    public uint dwAuthenticatorAttachment;
    public uint dwUserVerificationRequirement;
    public uint dwFlags;
    public IntPtr pwszU2fAppId; // PCWSTR
    public IntPtr pbU2fAppId; // BOOL*
    public IntPtr pCancellationId; // GUID*
    public IntPtr pAllowCredentialList; // PWEBAUTHN_CREDENTIAL_LIST
    public uint dwCredLargeBlobOperation;
    public uint cbCredLargeBlob;
    public IntPtr pbCredLargeBlob; // PBYTE
    public IntPtr pHmacSecretSaltValues; // PWEBAUTHN_HMAC_SECRET_SALT_VALUES
    [MarshalAs(UnmanagedType.Bool)]
    public bool bBrowserInPrivateMode;
    public IntPtr pLinkedDevice; // PCTAPCBOR_HYBRID_STORAGE_LINKED_DATA
    [MarshalAs(UnmanagedType.Bool)]
    public bool bAutoFill;
    public uint cbJsonExt;
    public IntPtr pbJsonExt; // PBYTE
    public uint cCredentialHints;
    public IntPtr ppwszCredentialHints; // LPCWSTR*
    public IntPtr pwszRemoteWebOrigin; // PCWSTR
    public uint cbPublicKeyCredentialRequestOptionsJSON;
    public IntPtr pbPublicKeyCredentialRequestOptionsJSON; // PBYTE
    public uint cbAuthenticatorId;
    public IntPtr pbAuthenticatorId; // PBYTE
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_EXTENSIONS
{
    public uint cExtensions;
    public IntPtr pExtensions; // PWEBAUTHN_EXTENSION
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_EXTENSION
{
    public IntPtr pwszExtensionIdentifier; // LPCWSTR
    public uint cbExtension;
    public IntPtr pvExtension; // PVOID
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_CLIENT_DATA
{
    public uint dwVersion;
    public uint cbClientDataJSON;
    public IntPtr pbClientDataJSON; // PBYTE
    public IntPtr pwszHashAlgId; // LPCWSTR
}

[StructLayout(LayoutKind.Sequential)]
public struct WEBAUTHN_ASSERTION
{
    public uint dwVersion;
    public uint cbAuthenticatorData;
    public IntPtr pbAuthenticatorData; // PBYTE
    public uint cbSignature;
    public IntPtr pbSignature; // PBYTE
    public WEBAUTHN_CREDENTIAL Credential;
    public uint cbUserId;
    public IntPtr pbUserId; // PBYTE
    public WEBAUTHN_EXTENSIONS Extensions;
    public uint cbCredLargeBlob;
    public IntPtr pbCredLargeBlob; // PBYTE
    public uint dwCredLargeBlobStatus;
    public IntPtr pHmacSecret; // PWEBAUTHN_HMAC_SECRET_SALT
    public uint dwUsedTransport;
    public uint cbUnsignedExtensionOutputs;
    public IntPtr pbUnsignedExtensionOutputs; // PBYTE
    public uint cbClientDataJSON;
    public IntPtr pbClientDataJSON; // PBYTE
    public uint cbAuthenticationResponseJSON;
    public IntPtr pbAuthenticationResponseJSON; // PBYTE
}

namespace SharpWebAuthn
{
    internal class Program
    {
        static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.Error.WriteLine("Usage:");
                Console.Error.WriteLine("  webauthn.exe list");
                Console.Error.WriteLine("  webauthn.exe assert <credential_number> <challenge_json>");
                return 1;
            }

            string command = args[0];

            if (command == "list")
            {
                ListCredentials();
                return 0;
            }
            else if (command == "assert")
            {
                if (args.Length != 3)
                {
                    Console.Error.WriteLine($"Usage: webauthn.exe assert <credential_number> <challenge_json>");
                    return 1;
                }

                if (!int.TryParse(args[1], out int credentialId))
                {
                    Console.Error.WriteLine($"Invalid credential_number: {args[1]}");
                    return 1;
                }

                string challenge = args[2];
                AssertCredential(credentialId, challenge);
                return 0;
            }
            else
            {
                Console.Error.WriteLine($"Unknown command: {command}");
                Console.Error.WriteLine("Valid commands are: list, assert");
                return 1;
            }
        }

        static void ListCredentials()
        {
            WEBAUTHN_GET_CREDENTIALS_OPTIONS options = new WEBAUTHN_GET_CREDENTIALS_OPTIONS
            {
                dwVersion = 1, // WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1
                pwszRpId = IntPtr.Zero,
                bBrowserInPrivateMode = false
            };

            IntPtr pCredentialList = IntPtr.Zero;
            HRESULT hr = WebAuthN.WebAuthNGetPlatformCredentialList(ref options, out pCredentialList);

            if (hr == 0 && pCredentialList != IntPtr.Zero) // S_OK
            {
                int structSize = Marshal.SizeOf(typeof(IntPtr));
                var credentialList = Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_DETAILS_LIST>(pCredentialList);
                Console.WriteLine($"Found {credentialList.cCredentialDetails} credentials:");
                for (uint i = 0; i < credentialList.cCredentialDetails; ++i)
                {
                    IntPtr credPtr = Marshal.ReadIntPtr(credentialList.ppCredentialDetails, (int)i * structSize);
                    var cred = Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_DETAILS>(credPtr);

                    Console.WriteLine(new string('-', 40));
                    Console.WriteLine($"Credential {i + 1}");
                    Console.WriteLine(new string('-', 40));

                    Console.WriteLine($"{"Version:",-20} {cred.dwVersion}");

                    if (cred.cbCredentialID != 0 && cred.pbCredentialID != IntPtr.Zero)
                    {
                        byte[] credentialId = new byte[cred.cbCredentialID];
                        Marshal.Copy(cred.pbCredentialID, credentialId, 0, (int)cred.cbCredentialID);
                        Console.WriteLine($"{"CredentialID (hex):",-20} {BitConverter.ToString(credentialId).Replace("-", "")}");
                    }

                    if (cred.pRpInformation != IntPtr.Zero)
                    {
                        var rpInfo = Marshal.PtrToStructure<WEBAUTHN_RP_ENTITY_INFORMATION>(cred.pRpInformation);
                        if (rpInfo.pwszId != IntPtr.Zero)
                        {
                            string rpId = Marshal.PtrToStringUni(rpInfo.pwszId);
                            Console.WriteLine($"{"RP Id:",-20} {rpId}");
                        }
                    }

                    if (cred.pUserInformation != IntPtr.Zero)
                    {
                        var userInfo = Marshal.PtrToStructure<WEBAUTHN_USER_ENTITY_INFORMATION>(cred.pUserInformation);
                        if (userInfo.pwszName != IntPtr.Zero)
                        {
                            string userName = Marshal.PtrToStringUni(userInfo.pwszName);
                            Console.WriteLine($"{"User Name:",-20} {userName}");
                        }
                    }

                    Console.WriteLine($"{"Removable:",-20} {(cred.bRemovable ? "Yes" : "No")}");
                    if (cred.dwVersion >= 2)
                        Console.WriteLine($"{"BackedUp:",-20} {(cred.bBackedUp ? "Yes" : "No")}");
                    if (cred.dwVersion >= 3)
                        Console.WriteLine($"{"ThirdPartyPayment:",-20} {(cred.bThirdPartyPayment ? "Yes" : "No")}");
                }
                Console.WriteLine(new string('=', 40));
                WebAuthN.WebAuthNFreePlatformCredentialList(pCredentialList);
            }
            else
            {
                Console.Error.WriteLine($"WebAuthNGetPlatformCredentialList failed. HRESULT: 0x{hr:X}");
            }
        }

        static void AssertCredential(int credentialId, string challenge)
        {
            var options = new WEBAUTHN_GET_CREDENTIALS_OPTIONS
            {
                dwVersion = 1,
                pwszRpId = IntPtr.Zero,
                bBrowserInPrivateMode = false
            };

            IntPtr pCredentialList = IntPtr.Zero;
            HRESULT hr = WebAuthN.WebAuthNGetPlatformCredentialList(ref options, out pCredentialList);

            if (hr != 0 || pCredentialList == IntPtr.Zero)
            {
                Console.Error.WriteLine($"WebAuthNGetPlatformCredentialList failed. HRESULT: 0x{hr:X}");
                return;
            }

            var credentialList = Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_DETAILS_LIST>(pCredentialList);

            IntPtr credPtr = IntPtr.Zero;
            int structSize = Marshal.SizeOf(typeof(IntPtr));
            for (uint i = 0; i < credentialList.cCredentialDetails; ++i)
            {
                if (credentialId == (int)(i + 1))
                {
                    credPtr = Marshal.ReadIntPtr(credentialList.ppCredentialDetails, (int)i * structSize);
                    break;
                }
            }

            if (credPtr == IntPtr.Zero)
            {
                Console.WriteLine("Credential not found");
                WebAuthN.WebAuthNFreePlatformCredentialList(pCredentialList);
                return;
            }

            var cred = Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_DETAILS>(credPtr);

            string rpId = "";
            if (cred.pRpInformation != IntPtr.Zero)
            {
                var rpInfo = Marshal.PtrToStructure<WEBAUTHN_RP_ENTITY_INFORMATION>(cred.pRpInformation);
                if (rpInfo.pwszId != IntPtr.Zero)
                    rpId = Marshal.PtrToStringUni(rpInfo.pwszId);
            }

            string clientDataJson = $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"https://{rpId}\"}}";
            Console.WriteLine($"ClientData JSON: {clientDataJson}");

            byte[] clientDataBytes = System.Text.Encoding.UTF8.GetBytes(clientDataJson);
            GCHandle clientDataHandle = GCHandle.Alloc(clientDataBytes, GCHandleType.Pinned);

            var clientData = new WEBAUTHN_CLIENT_DATA
            {
                dwVersion = 1, // WEBAUTHN_CLIENT_DATA_CURRENT_VERSION
                cbClientDataJSON = (uint)clientDataBytes.Length,
                pbClientDataJSON = clientDataHandle.AddrOfPinnedObject(),
                pwszHashAlgId = Marshal.StringToHGlobalUni("SHA-256") // WEBAUTHN_HASH_ALGORITHM_SHA_256
            };

            var assertionOptions = new WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
            {
                dwVersion = 7, // WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_7
                dwTimeoutMilliseconds = 60000,
                CredentialList = new WEBAUTHN_CREDENTIALS { cCredentials = 0, pCredentials = IntPtr.Zero },
                Extensions = new WEBAUTHN_EXTENSIONS { cExtensions = 0, pExtensions = IntPtr.Zero },
            };

            IntPtr assertionPtr = IntPtr.Zero;
            IntPtr optionsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(assertionOptions));
            Marshal.StructureToPtr(assertionOptions, optionsPtr, false);
            hr = WebAuthN.WebAuthNAuthenticatorGetAssertion(
                User32.GetForegroundWindow(),
                rpId,
                ref clientData,
                optionsPtr,
                out assertionPtr
            );
            Marshal.FreeHGlobal(optionsPtr);
            clientDataHandle.Free();
            Marshal.FreeHGlobal(clientData.pwszHashAlgId);

            if (hr == 0 && assertionPtr != IntPtr.Zero)
            {

                var clientDataBase64 = Convert.ToBase64String(clientDataBytes);
                var authenticatorDataBase64 = "";
                var signatureBase64 = "";

                var assertion = Marshal.PtrToStructure<WEBAUTHN_ASSERTION>(assertionPtr);

                Console.WriteLine("Assertion received for credential.");

                if (assertion.cbAuthenticatorData != 0 && assertion.pbAuthenticatorData != IntPtr.Zero)
                {
                    byte[] authData = new byte[assertion.cbAuthenticatorData];
                    Marshal.Copy(assertion.pbAuthenticatorData, authData, 0, (int)assertion.cbAuthenticatorData);
                    authenticatorDataBase64 = Convert.ToBase64String(authData);
                }

                if (assertion.cbSignature != 0 && assertion.pbSignature != IntPtr.Zero)
                {
                    byte[] signature = new byte[assertion.cbSignature];
                    Marshal.Copy(assertion.pbSignature, signature, 0, (int)assertion.cbSignature);
                    signatureBase64 = Convert.ToBase64String(signature);
                }

                Console.WriteLine($"{{\"clientData\": \"{clientDataBase64}\",\"authenticatorData\": \"{authenticatorDataBase64}\",\"signatureData\": \"{signatureBase64}\"}}");
                WebAuthN.WebAuthNFreeAssertion(assertionPtr);
            }
            else
            {
                Console.Error.WriteLine($"WebAuthNAuthenticatorGetAssertion failed. HRESULT: 0x{hr:X}");
            }

            WebAuthN.WebAuthNFreePlatformCredentialList(pCredentialList);
        }
    }
}
