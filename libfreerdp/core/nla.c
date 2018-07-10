/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Network Level Authentication (NLA)
 *
 * Copyright 2010-2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 * Copyright 2016 Martin Fleisz <martin.fleisz@thincast.com>
 * Copyright 2017 Dorian Ducournau <dorian.ducournau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#endif

#include <freerdp/log.h>
#include <freerdp/crypto/tls.h>
#include <freerdp/build-config.h>
#include <freerdp/peer.h>

#include <winpr/crt.h>
#include <winpr/sam.h>
#include <winpr/sspi.h>
#include <winpr/print.h>
#include <winpr/tchar.h>
#include <winpr/dsparse.h>
#include <winpr/library.h>
#include <winpr/registry.h>

#include "nla.h"

static const char* PREFIX_CONTAINER_NAME = "0x";
static const char* PREFIX_PIN_GLOBAL = "CredProv&PIN Global&";

#define TAG FREERDP_TAG("core.nla")

#define SERVER_KEY "Software\\"FREERDP_VENDOR_STRING"\\" \
	FREERDP_PRODUCT_STRING"\\Server"




static void print_identity(SEC_WINNT_AUTH_IDENTITY* identity)
{
#define PRINT_FIELD_POINTER(structure, field)								\
	do												\
	{												\
		WLog_DBG(TAG, "%-40s = %p %s", #structure "->" #field, (void *)structure->field,	\
		         structure->field ? (char *)structure->field : "");				\
	}while (0)
	WLog_DBG(TAG, "%-40s = %p", "identity", (void*)identity);

	if (identity)
	{
		PRINT_FIELD_POINTER(identity, User);
		PRINT_FIELD_POINTER(identity, Password);
		PRINT_FIELD_POINTER(identity, Domain);
		PRINT_FIELD_POINTER(identity, Pin);
		PRINT_FIELD_POINTER(identity, UserHint);
		PRINT_FIELD_POINTER(identity, DomainHint);
		WLog_DBG(TAG, "%-40s = %p", "identity->CspData", (void*)identity->CspData);

		if (identity->CspData)
		{
			PRINT_FIELD_POINTER(identity->CspData, CardName);
			PRINT_FIELD_POINTER(identity->CspData, ReaderName);
			PRINT_FIELD_POINTER(identity->CspData, ContainerName);
			PRINT_FIELD_POINTER(identity->CspData, CspName);
		}
	}
}


/* void* sspi_SecureHandleGetUpperPointer(void* handle); */
/* void* sspi_SecureHandleGetLowerPointer(void* handle); */

#include "winpr/libwinpr/sspi/Negotiate/negotiate.h"

static void print_credentials(void* credentials)
{
	SSPI_CREDENTIALS* sspi_credentials = (SSPI_CREDENTIALS*)sspi_SecureHandleGetLowerPointer(
	        credentials);
	WLog_DBG(TAG, "credentials = %s", sspi_SecureHandleGetUpperPointer(credentials));
	print_identity(&sspi_credentials->identity);
}



/**
* TSRequest ::= SEQUENCE {
*	version	   [0] INTEGER,
*	negoTokens [1] NegoData OPTIONAL,
*	authInfo   [2] OCTET STRING OPTIONAL,
*	pubKeyAuth [3] OCTET STRING OPTIONAL,
*	errorCode  [4] INTEGER OPTIONAL
* }
*
* NegoData ::= SEQUENCE OF NegoDataItem
*
* NegoDataItem ::= SEQUENCE {
*	negoToken [0] OCTET STRING
* }
*
* TSCredentials ::= SEQUENCE {
*	credType    [0] INTEGER,
*	credentials [1] OCTET STRING
* }
*
* TSPasswordCreds ::= SEQUENCE {
*	domainName  [0] OCTET STRING,
*	userName    [1] OCTET STRING,
*	password    [2] OCTET STRING
* }
*
* TSSmartCardCreds ::= SEQUENCE {
*	pin	   [0] OCTET STRING,
*	cspData	   [1] TSCspDataDetail,
*	userHint   [2] OCTET STRING OPTIONAL,
*	domainHint [3] OCTET STRING OPTIONAL
* }
*
* TSCspDataDetail ::= SEQUENCE {
*	keySpec	      [0] INTEGER,
*	cardName      [1] OCTET STRING OPTIONAL,
*	readerName    [2] OCTET STRING OPTIONAL,
*	containerName [3] OCTET STRING OPTIONAL,
*	cspName	      [4] OCTET STRING OPTIONAL
* }
*
*/

#define NLA_PKG_NAME	NEGO_SSP_NAME

#define TERMSRV_SPN_PREFIX	"TERMSRV/"

static BOOL nla_send(rdpNla* nla);
static int nla_recv(rdpNla* nla);
static void nla_buffer_print(rdpNla* nla);
static void nla_buffer_free(rdpNla* nla);
static SECURITY_STATUS nla_encrypt_public_key_echo(rdpNla* nla);
static SECURITY_STATUS nla_decrypt_public_key_echo(rdpNla* nla);
static SECURITY_STATUS nla_encrypt_ts_credentials(rdpNla* nla);
static SECURITY_STATUS nla_decrypt_ts_credentials(rdpNla* nla);
static BOOL nla_read_ts_password_creds(rdpNla* nla, wStream* s);
static BOOL nla_read_ts_smartcard_creds(rdpNla* nla, wStream* s);
static void nla_identity_free(SEC_WINNT_AUTH_IDENTITY* identity);

#define ber_sizeof_sequence_octet_string(length) ber_sizeof_contextual_tag(ber_sizeof_octet_string(length)) + ber_sizeof_octet_string(length)
#define ber_write_sequence_octet_string(stream, context, value, length) ber_write_contextual_tag(stream, context, ber_sizeof_octet_string(length), TRUE) + ber_write_octet_string(stream, value, length)


static void clean_and_free(void* memory, size_t size)
{
	if (memory)
	{
		memset_s(memory, size, 0, size);
		free(memory);
	}
}

#define CLEAN_AND_FREE_FIELD(structure, field)					\
	clean_and_free(structure->field, structure->field##Length *2);

static void nla_identity_free(SEC_WINNT_AUTH_IDENTITY* identity)
{
	/* The fields are already freed in sspi_CredentialsFree */
	/* print_identity(identity); */
	/* if (identity) */
	/* { */
	/*	   CLEAN_AND_FREE_FIELD(identity, User); */
	/*	   CLEAN_AND_FREE_FIELD(identity, Password); */
	/*	   CLEAN_AND_FREE_FIELD(identity, Domain); */
	/*	   CLEAN_AND_FREE_FIELD(identity, UserHint); */
	/*	   CLEAN_AND_FREE_FIELD(identity, DomainHint); */
	/*	CLEAN_AND_FREE_FIELD(identity, Pin); */
	/*  */
	/*	if (identity->CspData) */
	/*	{ */
	/*		   CLEAN_AND_FREE_FIELD(identity->CspData, CardName); */
	/*		   CLEAN_AND_FREE_FIELD(identity->CspData, ReaderName); */
	/*		   CLEAN_AND_FREE_FIELD(identity->CspData, ContainerName); */
	/*		   CLEAN_AND_FREE_FIELD(identity->CspData, CspName); */
	/*		   memset(identity->CspData, 0, sizeof(SEC_WINNT_AUTH_IDENTITY_CSPDATADETAIL)); */
	/*		   free(identity->CspData); */
	/*	} */
	/* } */
	memset(identity, 0, sizeof(SEC_WINNT_AUTH_IDENTITY));
	free(identity);
}

/**
 * @return whether the username is found in the SAM database.
 * @param username: C string.
 */
static BOOL user_is_in_sam_database(const char* username)
{
	char mutable_username[128]; /*	greater than the max of 104 on MS-Windows 2000,	 and 20 on MS-Windows 2003 */
	WINPR_SAM* sam = SamOpen(NULL, TRUE);
	BOOL is_in = FALSE;

	if (sizeof(mutable_username) - 1 < strlen(username))
	{
		return FALSE;
	}

	strcpy(mutable_username, username);

	if (sam)
	{
		WINPR_SAM_ENTRY* entry = SamLookupUserA(sam, mutable_username, strlen(mutable_username), NULL, 0);

		if (entry)
		{
			is_in = TRUE;
			SamFreeEntry(sam, entry);
		}

		SamClose(sam);
	}

	return is_in;
}


#define CHECK_MEMORY(pointer, result, description, ...)			\
	do								\
	{								\
		if (!pointer)						\
		{							\
			WLog_ERR(TAG, "%s:%d: " description,		\
			         __FUNCTION__, __LINE__,		 \
			         ##__VA_ARGS__);			 \
			return result;					\
		}							\
	}while (0)

/**
 * @return a fresh C string containing the concatenation of all
 * the C strings passed in argument.
 * @param string: Any number of C string can be passed as argument.
 * The last argument must be 0.
 */
static char* string_concatenate(const char* string, ...)
{
	char*	result;
	char*	current;
	/* sum the lengths of the strings */
	const char*   arg = string;
	int total_length = 0;
	va_list strings;
	va_start(strings, string);

	while (arg)
	{
		total_length += strlen(arg);
		arg = va_arg(strings, const char*);
	}

	va_end(strings);
	total_length += 1; /*  null byte */
	CHECK_MEMORY((result = malloc(total_length)),
	             0, "Could not allocate %d bytes.", total_length);
	/* start copying */
	current = result;
	strcpy(current, string);
	current += strlen(string);
	va_start(strings, string);

	while (arg)
	{
		strcpy(current, arg);
		current += strlen(arg);
		arg = va_arg(strings, const char*);
	}

	va_end(strings);
	/* strcpy copied the terminating null byte */
	return result;
}


/**
 set_identity_for_smartcard_logon fills nla->identity,
 from information obtained from a smartcard.
 */
static int set_identity_for_smartcard_logon(rdpNla* nla)
{
	rdpSettings* settings = nla->settings;
	nla->credType = settings->CredentialsType;
#if defined(WITH_PKCS11H) && defined(WITH_GSSAPI)

	if (get_info_smartcard(nla) != CKR_OK)
	{
		WLog_ERR(TAG, "Failed to retrieve UPN! Is there a smartcard in the reader?");
		return -1;
	}

#if defined(WITH_KERBEROS)

	if (get_TGT_kerberos(settings) == FALSE)
	{
		WLog_ERR(TAG, "Failed to get TGT from KDC !");
		return -1;
	}

#endif
#else
	WLog_ERR(TAG, "Enable PKCS11H and GSSAPI features to authenticate via Smartcard Logon thru NLA");
	return -1;
#endif

	if (settings->PinPadIsPresent)
	{
		/* The middleware talking to the card performs PIN caching and will provide
		* to its CSP (Cryptographic Service Provider) the PIN code
		* when asked. If PIN caching fails, or is not handled by the middleware,
		* the PIN code will be asked one more time before opening the session.
		* Thus, entering PIN code on pinpad does not give the PIN code explicitly to the CSP.
		* That's why we set it here to "0000".
		* The PIN code is not communicated to any software module, nor central processing unit.
		* Contrary to /pin option in command line or with getpass() which are less secure,
		* because the PIN code is communicated (at the present) in clear and transit via the code.
		*/
		settings->Password = string_concatenate(PREFIX_PIN_GLOBAL, "0000", 0);
	}
	else if (settings->Pin)
	{
		settings->Password = string_concatenate(PREFIX_PIN_GLOBAL, settings->Pin, 0);
	}
	else
	{
		settings->Password = strdup("");
	}

	CHECK_MEMORY(settings->Password, -1, "Could not allocate memory for password.");
	settings->Username = NULL;

	if (settings->UserPrincipalName != NULL)
	{
		settings->Username = strdup(settings->UserPrincipalName);
		CHECK_MEMORY(settings->Username,
		             -1, "Could not strdup the UserPrincipalName (length = %d)",
		             strlen(settings->UserPrincipalName));
	}

	/* if (!settings->Domain) */
	/* { */
	/*	WLog_ERR(TAG, "/domain option is  required for Smartcard Logon + NLA"); */
	/*	   return -1; */
	/* } */
	if (settings->Domain)
	{
		if (settings->DomainHint)
		{
			free(settings->DomainHint);
		}

		settings->DomainHint = strdup(settings->Domain); /* They're freed separately! */
	}

	if (settings->DomainHint != NULL)
	{
		if (settings->CanonicalizedUserHint != NULL)
		{
			CHECK_MEMORY((settings->UserHint = strdup(settings->CanonicalizedUserHint)),
			             -1, "Could not strdup the UserPrincipalName (length = %d)",
			             strlen(settings->UserPrincipalName));
		}
		else
		{
			WLog_ERR(TAG, "User Hint NOT canonicalized");
			return -1;
		}
	}

	CHECK_MEMORY((settings->ContainerName = string_concatenate(PREFIX_CONTAINER_NAME,
	                                        settings->IdCertificate, 0)),
	             -1, "Could not allocate memory for container name.");

	if ((settings->CspName == NULL) || (settings->CspName != NULL && strlen(settings->CspName) == 0))
	{
		WLog_ERR(TAG, "/csp argument is mandatory for smartcard-logon ");
		return -1;
	}

	if (!settings->RedirectSmartCards && !settings->DeviceRedirection)
	{
		WLog_ERR(TAG, "/smartcard argument is mandatory for smartcard-logon ");
		return -1;
	}

	WLog_DBG(TAG, "SmartcardReaderName=%s", settings->SmartcardReaderName);
	int ret = sspi_SetAuthIdentity_Smartcard(nla->identity,
	          settings->Password,
	          AT_KEYEXCHANGE /*AT_AUTHENTICATE*/,
	          settings->CardName,
	          settings->SmartcardReaderName,
	          settings->ContainerName,
	          settings->CspName,
	          settings->UserHint,
	          settings->DomainHint);

	if (ret < 0)
	{
		WLog_ERR(TAG, "%s:%d: Failed to set smartcard authentication parameters !",
		         __FUNCTION__, __LINE__);
		return -1;
	}

	return 0;
}

static void*   security_package_name(rdpNla* nla)
{
	void* package_name = 0;
#if defined(WITH_PKCS11H) && defined(WITH_GSSAPI)
	/* Smartcard Logon +  NLA */
#if defined(WITH_KERBEROS)
	/* Smartcard Logon +  Kerberos (SSO) */
	package_name = KERBEROS_SSP_NAME;
#else
	package_name = NLA_PKG_NAME;
#endif
#else
	/* Not Smartcard Logon */
#ifdef WITH_GSSAPI /* KERBEROS SSP */
	package_name = KERBEROS_SSP_NAME;
#else /* NTLM SSP */
	package_name = NLA_PKG_NAME;
#endif
#endif
	return package_name;
}

static void*   acquire_package_name(rdpNla* nla)
{
	void* package_name = 0;
#if defined(WITH_PKCS11H) && defined(WITH_GSSAPI)
	/* Smartcard Logon +  NLA */
#if defined(WITH_KERBEROS)
	/* Smartcard Logon +  Kerberos (SSO) */
	package_name = NEGO_SSP_NAME;
#else

	if (nla->settings->SmartcardLogon)
	{
		package_name = "CREDSSP";
	}
	else
	{
		package_name = NEGO_SSP_NAME;
	}

#endif
#else
	/* Not Smartcard Logon */
	package_name = NEGO_SSP_NAME;
#endif
	return package_name;
}

static int query_security_package_info(rdpNla* nla, void* package_name)
{
	nla->status = nla->table->QuerySecurityPackageInfo(package_name, &nla->pPackageInfo);

	if (nla->status != SEC_E_OK)
	{
		WLog_ERR(TAG, "QuerySecurityPackageInfo status %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(nla->status), nla->status);
		return -1;
	}

	nla->cbMaxToken = nla->pPackageInfo->cbMaxToken;
	nla->packageName = nla->pPackageInfo->Name;
	WLog_DBG(TAG, "packageName=%s ; cbMaxToken=%d", nla->packageName, nla->cbMaxToken);
	return 0;
}


/**
 * @brief Extracts the Service Principal Name from the settings.
 * @param settings: rdpSettings
 * @return a LPTSTR (either ANSI or UNICODE string depending on compilation-time UNICODE setting).
 */
LPTSTR settings_service_principal_name(rdpSettings* settings)
{
	int length = sizeof(TERMSRV_SPN_PREFIX) + strlen(settings->ServerHostname);
	SEC_CHAR* spn = (SEC_CHAR*) malloc(length + 1);

	if (!spn)
	{
		return 0;
	}

	if (settings->SmartcardLogon)
	{
		sprintf(spn, "%s", settings->ServerHostname);
	}
	else
	{
		sprintf(spn, "%s%s", TERMSRV_SPN_PREFIX, settings->ServerHostname);
	}

#ifdef UNICODE
	{
		LPTSTR result = 0;
		ConvertToUnicode(CP_UTF8, 0, spn, -1, &result, 0);
		free(spn);
		return result;
	}
#else
	return (LPTSTR)spn;
#endif
}


/**
 * Initialize NTLM,  Kerberos SSP, or Smartcard Login CreSSP authentication module (client).
 * @param credssp
 */
static int nla_client_init(rdpNla* nla)
{
	rdpTls* tls = NULL;
	BOOL PromptPassword = FALSE;
	BOOL PromptPin = FALSE;
	freerdp* instance = nla->instance;
	rdpSettings* settings = nla->settings;
	nla->state = NLA_STATE_INITIAL;
	nla->credType = SEC_DEFAULT_DELEGATION_CRED_TYPE;

	if (settings->RestrictedAdminModeRequired)
		settings->DisableCredentialsDelegation = TRUE;

	if (((!settings->Password) || (!settings->Username)
	     || (!strlen(settings->Password)) || (!strlen(settings->Username)))
	    && !settings->SmartcardLogon)
		PromptPassword = TRUE;

	if (settings->SmartcardLogon)
		PromptPin = TRUE;

	if (PromptPassword && settings->Username && strlen(settings->Username))
	{
		/* Use entry in SAM database later instead of prompt when user is in the SAM database */
		PromptPassword = !user_is_in_sam_database(settings->Username);
	}

#ifndef _WIN32

	if (PromptPassword)
	{
		if (settings->RestrictedAdminModeRequired)
		{
			if ((settings->PasswordHash) && (strlen(settings->PasswordHash) > 0))
				PromptPassword = FALSE;
		}
	}

#endif

	if (PromptPassword || PromptPin)
	{
		if (instance->Authenticate)
		{
			BOOL proceed = instance->Authenticate(instance,
			                                      &settings->Username, &settings->Password, &settings->Domain);

			if (!proceed)
			{
				freerdp_set_last_error(instance->context, FREERDP_ERROR_CONNECT_CANCELLED);
				return 0;
			}
		}
	}

	if (true /* DEBUG */ || settings->SmartcardLogon)
	{
		if (set_identity_for_smartcard_logon(nla) < 0)
		{
			return -1;
		}
	}
	else
	{
		if (settings->Username)
		{
			if (sspi_SetAuthIdentity(nla->identity, settings->Username, settings->Domain,
			                         settings->Password) < 0)
				return -1;
		}
		else
		{
			nla_identity_free(nla->identity);
			nla->identity = NULL;
		}
	}

#if !defined(_WIN32) && !defined(WITH_PKCS11H)
	{
		SEC_WINNT_AUTH_IDENTITY* identity = nla->identity;

		if (!identity)
		{
			WLog_ERR(TAG, "NLA identity=%p", (void*) identity);
			return -1;
		}

		if (settings->RestrictedAdminModeRequired)
		{
			if (settings->PasswordHash)
			{
				if (strlen(settings->PasswordHash) == 32)
				{
					free(identity->Password);
					identity->PasswordLength = ConvertToUnicode(CP_UTF8, 0,
					                           settings->PasswordHash, -1, &identity->Password, 0) - 1;
					/**
					 * Multiply password hash length by 64 to obtain a length exceeding
					 * the maximum (256) and use it this for hash identification in WinPR.
					 */
					identity->PasswordLength = 32 * 64; /* 2048 */
				}
			}
		}
	}
#endif
	tls = nla->transport->tls;

	if (!tls)
	{
		WLog_ERR(TAG, "Unknown NLA transport layer");
		return -1;
	}

	if (!sspi_SecBufferAlloc(&nla->PublicKey, tls->PublicKeyLength))
	{
		WLog_ERR(TAG, "Failed to allocate sspi secBuffer");
		return -1;
	}

	CopyMemory(nla->PublicKey.pvBuffer, tls->PublicKey, tls->PublicKeyLength);

	if ((nla->ServicePrincipalName = settings_service_principal_name(settings)) == 0)
	{
		return -1;
	}

	nla->table = InitSecurityInterfaceEx(0);

	if (query_security_package_info(nla, NLA_PKG_NAME) < 0)
	{
		return -1;
	}

	nla->status = nla->table->AcquireCredentialsHandle(NULL, NLA_PKG_NAME,
	              SECPKG_CRED_OUTBOUND, NULL, nla->identity, NULL, NULL,
	              &nla->credentials, &nla->expiration);

	if (nla->status != SEC_E_OK)
	{
		WLog_ERR(TAG, "AcquireCredentialsHandle status %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(nla->status), nla->status);
		return -1;
	}

	WLog_DBG(TAG, "AcquireCredentialsHandle credentials = %s",
	         (char*)sspi_SecureHandleGetUpperPointer(&(nla->credentials)));
	print_credentials(&nla->credentials);
	nla->haveContext = FALSE;
	nla->haveInputBuffer = FALSE;
	nla->havePubKeyAuth = FALSE;
	ZeroMemory(&nla->inputBuffer, sizeof(SecBuffer));
	ZeroMemory(&nla->outputBuffer, sizeof(SecBuffer));
	ZeroMemory(&nla->ContextSizes, sizeof(SecPkgContext_Sizes));
	/*
	 * from tspkg.dll: 0x00000132
	 * ISC_REQ_MUTUAL_AUTH
	 * ISC_REQ_CONFIDENTIALITY
	 * ISC_REQ_USE_SESSION_KEY
	 * ISC_REQ_ALLOCATE_MEMORY
	 */
	nla->fContextReq = ISC_REQ_MUTUAL_AUTH | ISC_REQ_CONFIDENTIALITY | ISC_REQ_USE_SESSION_KEY;
	return 1;
}


/**
 * @brief initializes the output buffer.
 * @return negative on error.
 */
static int nla_output_buffer_initialize(rdpNla* nla)
{
	nla->outputBufferDesc.ulVersion = SECBUFFER_VERSION;
	nla->outputBufferDesc.cBuffers = 1;
	nla->outputBufferDesc.pBuffers = &nla->outputBuffer;
	return (sspi_SecBufferAllocType( & nla->outputBuffer, nla->cbMaxToken, SECBUFFER_TOKEN))
			? 0
			: -1;
}


static const char* nla_state_label(NLA_STATE state)
{
	switch (state)
	{
		case NLA_STATE_INITIAL:
			return "INITIAL";

		case NLA_STATE_NEGO_TOKEN:
			return "NEGO_TOKEN";

		case NLA_STATE_PUB_KEY_AUTH:
			return "PUB_KEY_AUTH";

		case NLA_STATE_AUTH_INFO:
			return "AUTH_INFO";

		case NLA_STATE_POST_NEGO:
			return "POST_NEGO";

		case NLA_STATE_FINAL:
			return "STATE_FINAL";

		default:
			{
				static char buffer[80];
				sprintf(buffer, "#<unknown state %d>", state);
				return buffer;
			}
	}
}

int nla_client_begin(rdpNla* nla)
{
	rdpSettings* settings = nla->settings;

	if (!((nla_client_init(nla) >= 0) &&
	      (nla->state == NLA_STATE_INITIAL) &&
	      (nla_output_buffer_initialize(nla) >= 0)))
	{
		return -1;
	}

	WLog_DBG(TAG, "nla state = %s", nla_state_label(nla->state));
	WLog_DBG(TAG, "nla->ServicePrincipalName = %s", nla->ServicePrincipalName);

	if (settings->SmartcardLogon)
	{
		/* Smartcard Logon on NLA: TSRequest.negoTokens will contain
		   only the SPNEGO token TSCredentials.TSSmartcardCreds. */
	}
	else
	{
		/* Kerberos or NTLM on NLA: TSRequest.negoTokens will contain
		   the Kerberos or NTLM packets.*/
	}
	sspi_CheckSecBuffer( & nla->outputBuffer);
	print_credentials(&nla->credentials);
	WLog_DBG(TAG, "nla->ServicePrincipalName = %s", nla->ServicePrincipalName);
	nla->status = nla->table->InitializeSecurityContext(&nla->credentials,
	              NULL, nla->ServicePrincipalName, nla->fContextReq, 0,
	              SECURITY_NATIVE_DREP, NULL, 0, &nla->context,
	              &nla->outputBufferDesc, &nla->pfContextAttr, &nla->expiration);
	/* DEBUG HERE! */
	traceSecurityStatusError(nla->status, nla->table, "InitializeSecurityContext");
	sspi_CheckSecBuffer( & nla->outputBuffer);

	/* Handle kerberos context initialization failure.
	 * After kerberos failed initialize NTLM context */
	if (nla->status == SEC_E_NO_CREDENTIALS)
	{
		nla->status = nla->table->InitializeSecurityContext(&nla->credentials,
		              NULL, nla->ServicePrincipalName, nla->fContextReq, 0,
		              SECURITY_NATIVE_DREP, NULL, 0, &nla->context,
		              &nla->outputBufferDesc, &nla->pfContextAttr, &nla->expiration);
		traceSecurityStatusError(nla->status, nla->table, "InitializeSecurityContext");

		if (nla->status)
		{
			if (query_security_package_info(nla, /* security_package_name(nla) */ NTLM_SSP_NAME) < 0)
			{
				return -1;
			}
		}
		sspi_CheckSecBuffer( & nla->outputBuffer);
	}
	if ((nla->status == SEC_I_COMPLETE_AND_CONTINUE) || (nla->status == SEC_I_COMPLETE_NEEDED))
	{
		if (nla->table->CompleteAuthToken)
		{
			SECURITY_STATUS status;
			status = nla->table->CompleteAuthToken(&nla->context, &nla->outputBufferDesc);

			if (status != SEC_E_OK)
			{
				traceSecurityStatusError(nla->status, nla->table, "CompleteAuthToken");
				return -1;
			}
			sspi_CheckSecBuffer( & nla->outputBuffer);
		}

		if (nla->status == SEC_I_COMPLETE_NEEDED)
			nla->status = SEC_E_OK;
		else if (nla->status == SEC_I_COMPLETE_AND_CONTINUE)
			nla->status = SEC_I_CONTINUE_NEEDED;
	}

	if (nla->status != SEC_I_CONTINUE_NEEDED)
		return -1;

	if (nla->outputBuffer.cbBuffer < 1)
		return -1;

	sspi_SecBufferDeepCopy( & nla->negoToken, & nla->outputBuffer);
	WLog_DBG(TAG, "%s() Sending Authentication Token", __FUNCTION__);
	winpr_HexDump(TAG, WLOG_DEBUG, nla->negoToken.pvBuffer, nla->negoToken.cbBuffer);

	if (!nla_send(nla))
	{
		nla_buffer_free(nla);
		return -1;
	}

	nla_buffer_free(nla);
	nla->state = NLA_STATE_NEGO_TOKEN;
	WLog_DBG(TAG, "nla new state = %s", nla_state_label(nla->state));
	return 1;
}

static int nla_client_recv(rdpNla* nla)
{
	int status = -1;
	WLog_DBG(TAG, "nla state = %s", nla_state_label(nla->state));

	if (nla->state == NLA_STATE_NEGO_TOKEN)
	{
		nla->inputBufferDesc.ulVersion = SECBUFFER_VERSION;
		nla->inputBufferDesc.cBuffers = 1;
		nla->inputBufferDesc.pBuffers = &nla->inputBuffer;
		sspi_SecBufferDeepCopy( & nla->inputBuffer, & nla->negoToken);
		nla->inputBuffer.BufferType = SECBUFFER_TOKEN;

		nla->outputBufferDesc.ulVersion = SECBUFFER_VERSION;
		nla->outputBufferDesc.cBuffers = 1;
		nla->outputBufferDesc.pBuffers = &nla->outputBuffer;

		if (!sspi_SecBufferAllocType( & nla->outputBuffer, nla->cbMaxToken, SECBUFFER_TOKEN))
			return -1;

		nla->status = nla->table->InitializeSecurityContext(&nla->credentials,
		              &nla->context, nla->ServicePrincipalName, nla->fContextReq, 0,
		              SECURITY_NATIVE_DREP, &nla->inputBufferDesc,
		              0, &nla->context, &nla->outputBufferDesc, &nla->pfContextAttr, &nla->expiration);
		traceSecurityStatusError(nla->status, nla->table, "InitializeSecurityContext");
		sspi_SecBufferFree( & nla->inputBuffer);

		if ((nla->status == SEC_I_COMPLETE_AND_CONTINUE) || (nla->status == SEC_I_COMPLETE_NEEDED))
		{
			if (nla->table->CompleteAuthToken)
			{
				SECURITY_STATUS status;
				status = nla->table->CompleteAuthToken(&nla->context, &nla->outputBufferDesc);

				if (status != SEC_E_OK)
				{
					traceSecurityStatusError(nla->status, nla->table, "CompleteAuthToken");
					return -1;
				}
			}

			if (nla->status == SEC_I_COMPLETE_NEEDED)
				nla->status = SEC_E_OK;
			else if (nla->status == SEC_I_COMPLETE_AND_CONTINUE)
				nla->status = SEC_I_CONTINUE_NEEDED;
		}

		if (nla->status == SEC_E_OK)
		{
			nla->havePubKeyAuth = TRUE;
			nla->status = nla->table->QueryContextAttributes(&nla->context, SECPKG_ATTR_SIZES,
			              &nla->ContextSizes);

			if (nla->status != SEC_E_OK)
			{
				WLog_ERR(TAG, "QueryContextAttributes SECPKG_ATTR_SIZES failure %s [0x%08"PRIX32"]",
				         GetSecurityStatusString(nla->status), nla->status);
				return -1;
			}

			nla->status = nla_encrypt_public_key_echo(nla);

			if (nla->status != SEC_E_OK)
				return -1;
		}

		sspi_SecBufferFree( & nla->negoToken);
		sspi_SecBufferDeepCopy( & nla->negoToken, & nla->outputBuffer);
		WLog_DBG(TAG, "%s() Sending Authentication Token", __FUNCTION__);
		winpr_HexDump(TAG, WLOG_DEBUG, nla->negoToken.pvBuffer, nla->negoToken.cbBuffer);

		if (!nla_send(nla))
		{
			nla_buffer_free(nla);
			return -1;
		}

		nla_buffer_free(nla);

		if (nla->status == SEC_E_OK)
			nla->state = NLA_STATE_PUB_KEY_AUTH;

		status = 1;
	}
	else if (nla->state == NLA_STATE_PUB_KEY_AUTH)
	{
		/* Verify Server Public Key Echo */
		WLog_DBG(TAG, "Verify Server Public Key Echo");

		nla->status = nla_decrypt_public_key_echo(nla);
		nla_buffer_free(nla);

		if (nla->status != SEC_E_OK)
		{
			WLog_ERR(TAG, "Could not verify public key echo %s [0x%08"PRIX32"]",
			         GetSecurityStatusString(nla->status), nla->status);
			return -1;
		}

		/* Send encrypted credentials */
		WLog_DBG(TAG, "Send encrypted credentials");
		nla->status = nla_encrypt_ts_credentials(nla);

		if (nla->status != SEC_E_OK)
		{
			WLog_ERR(TAG, "nla_encrypt_ts_credentials status %s [0x%08"PRIX32"]",
			         GetSecurityStatusString(nla->status), nla->status);
			return -1;
		}

		if (!nla_send(nla))
		{
			nla_buffer_free(nla);
			return -1;
		}

		nla_buffer_free(nla);

		if (SecIsValidHandle(&nla->credentials))
		{
			nla->table->FreeCredentialsHandle(&nla->credentials);
			SecInvalidateHandle(&nla->credentials);
		}

		if (nla->status != SEC_E_OK)
		{
			WLog_ERR(TAG, "FreeCredentialsHandle status %s [0x%08"PRIX32"]",
			         GetSecurityStatusString(nla->status), nla->status);
		}

		nla->status = nla->table->FreeContextBuffer(nla->pPackageInfo);

		if (nla->status != SEC_E_OK)
		{
			WLog_ERR(TAG, "FreeContextBuffer status %s [0x%08"PRIX32"]",
			         GetSecurityStatusString(nla->status), nla->status);
		}

		if (nla->status != SEC_E_OK)
			return -1;

		nla->state = NLA_STATE_AUTH_INFO;
		status = 1;
	}

	WLog_DBG(TAG, "nla new state = %s", nla_state_label(nla->state));
	return status;
}

static int nla_client_authenticate(rdpNla* nla)
{
	wStream* s;
	int status;
	s = Stream_New(NULL, 4096);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return -1;
	}

	if (nla_client_begin(nla) < 1)
	{
		Stream_Free(s, TRUE);
		return -1;
	}

	while (nla->state < NLA_STATE_AUTH_INFO)
	{
		WLog_DBG(TAG, "nla state = %s", nla_state_label(nla->state));
		Stream_SetPosition(s, 0);
		status = transport_read_pdu(nla->transport, s);

		if (status < 0)
		{
			WLog_ERR(TAG, "nla_client_authenticate failure");
			Stream_Free(s, TRUE);
			return -1;
		}

		status = nla_recv_pdu(nla, s);

		if (status < 0)
		{
			Stream_Free(s, TRUE);
			return -1;
		}
	}

	WLog_DBG(TAG, "nla new state = %s", nla_state_label(nla->state));
	Stream_Free(s, TRUE);
	return 1;
}

/**
 * Initialize NTLMSSP authentication module (server).
 * @param credssp
 */

static int nla_server_init(rdpNla* nla)
{
	rdpTls* tls = nla->transport->tls;

	if (!sspi_SecBufferAlloc(&nla->PublicKey, tls->PublicKeyLength))
	{
		WLog_ERR(TAG, "Failed to allocate SecBuffer for public key");
		return -1;
	}

	CopyMemory(nla->PublicKey.pvBuffer, tls->PublicKey, tls->PublicKeyLength);

	if (nla->SspiModule)
	{
		HMODULE hSSPI;
		INIT_SECURITY_INTERFACE pInitSecurityInterface;
		hSSPI = LoadLibrary(nla->SspiModule);

		if (!hSSPI)
		{
			WLog_ERR(TAG, "Failed to load SSPI module: %s", nla->SspiModule);
			return -1;
		}

#ifdef UNICODE
		pInitSecurityInterface = (INIT_SECURITY_INTERFACE) GetProcAddress(hSSPI, "InitSecurityInterfaceW");
#else
		pInitSecurityInterface = (INIT_SECURITY_INTERFACE) GetProcAddress(hSSPI, "InitSecurityInterfaceA");
#endif
		nla->table = pInitSecurityInterface();
	}
	else
	{
		nla->table = InitSecurityInterfaceEx(0);
	}

	if (query_security_package_info(nla, NLA_PKG_NAME) < 0)
	{
		return -1;
	}

	nla->status = nla->table->AcquireCredentialsHandle(NULL, NLA_PKG_NAME,
	              SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL,
	              &nla->credentials, &nla->expiration);

	if (nla->status != SEC_E_OK)
	{
		WLog_ERR(TAG, "AcquireCredentialsHandle status %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(nla->status), nla->status);
		return -1;
	}

	nla->haveContext = FALSE;
	nla->haveInputBuffer = FALSE;
	nla->havePubKeyAuth = FALSE;
	ZeroMemory(&nla->inputBuffer, sizeof(SecBuffer));
	ZeroMemory(&nla->outputBuffer, sizeof(SecBuffer));
	ZeroMemory(&nla->inputBufferDesc, sizeof(SecBufferDesc));
	ZeroMemory(&nla->outputBufferDesc, sizeof(SecBufferDesc));
	ZeroMemory(&nla->ContextSizes, sizeof(SecPkgContext_Sizes));
	/*
	 * from tspkg.dll: 0x00000112
	 * ASC_REQ_MUTUAL_AUTH
	 * ASC_REQ_CONFIDENTIALITY
	 * ASC_REQ_ALLOCATE_MEMORY
	 */
	nla->fContextReq = 0;
	nla->fContextReq |= ASC_REQ_MUTUAL_AUTH;
	nla->fContextReq |= ASC_REQ_CONFIDENTIALITY;
	nla->fContextReq |= ASC_REQ_CONNECTION;
	nla->fContextReq |= ASC_REQ_USE_SESSION_KEY;
	nla->fContextReq |= ASC_REQ_REPLAY_DETECT;
	nla->fContextReq |= ASC_REQ_SEQUENCE_DETECT;
	nla->fContextReq |= ASC_REQ_EXTENDED_ERROR;
	return 1;
}

/**
 * Authenticate with client using CredSSP (server).
 * @param credssp
 * @return 1 if authentication is successful
 */

static int nla_server_authenticate(rdpNla* nla)
{
	if (nla_server_init(nla) < 1)
		return -1;

	while (TRUE)
	{
		/* receive authentication token */
		nla->inputBufferDesc.ulVersion = SECBUFFER_VERSION;
		nla->inputBufferDesc.cBuffers = 1;
		nla->inputBufferDesc.pBuffers = &nla->inputBuffer;
		nla->inputBuffer.BufferType = SECBUFFER_TOKEN;

		if (nla_recv(nla) < 0)
			return -1;

		WLog_DBG(TAG, "Receiving Authentication Token");
		nla_buffer_print(nla);
		sspi_SecBufferDeepCopy( & nla->inputBuffer, & nla->negoToken);

		if (nla->negoToken.cbBuffer < 1)
		{
			WLog_ERR(TAG, "CredSSP: invalid negoToken!");
			return -1;
		}

		nla->outputBufferDesc.ulVersion = SECBUFFER_VERSION;
		nla->outputBufferDesc.cBuffers = 1;
		nla->outputBufferDesc.pBuffers = &nla->outputBuffer;

		if (!sspi_SecBufferAllocType( & nla->outputBuffer, nla->cbMaxToken, SECBUFFER_TOKEN))
			return -1;

		nla->status = nla->table->AcceptSecurityContext(&nla->credentials,
		              nla->haveContext ? &nla->context : NULL,
		              &nla->inputBufferDesc, nla->fContextReq, SECURITY_NATIVE_DREP, &nla->context,
		              &nla->outputBufferDesc, &nla->pfContextAttr, &nla->expiration);
		WLog_VRB(TAG, "AcceptSecurityContext status %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(nla->status), nla->status);
		sspi_SecBufferDeepCopy( & nla->negoToken, & nla->outputBuffer);

		if ((nla->status == SEC_I_COMPLETE_AND_CONTINUE) || (nla->status == SEC_I_COMPLETE_NEEDED))
		{
			freerdp_peer* peer = nla->instance->context->peer;

			if (peer->ComputeNtlmHash)
			{
				SECURITY_STATUS status;
				status = nla->table->SetContextAttributes(&nla->context, SECPKG_ATTR_AUTH_NTLM_HASH_CB,
				         peer->ComputeNtlmHash, 0);

				if (status != SEC_E_OK)
				{
					WLog_ERR(TAG, "SetContextAttributesA(hash cb) status %s [0x%08"PRIX32"]",
					         GetSecurityStatusString(status), status);
				}

				status = nla->table->SetContextAttributes(&nla->context, SECPKG_ATTR_AUTH_NTLM_HASH_CB_DATA, peer,
				         0);

				if (status != SEC_E_OK)
				{
					WLog_ERR(TAG, "SetContextAttributesA(hash cb data) status %s [0x%08"PRIX32"]",
					         GetSecurityStatusString(status), status);
				}
			}
			else if (nla->SamFile)
			{
				nla->table->SetContextAttributes(&nla->context, SECPKG_ATTR_AUTH_NTLM_SAM_FILE, nla->SamFile,
				                                 strlen(nla->SamFile) + 1);
			}

			if (nla->table->CompleteAuthToken)
			{
				SECURITY_STATUS status;
				status = nla->table->CompleteAuthToken(&nla->context, &nla->outputBufferDesc);

				if (status != SEC_E_OK)
				{
					WLog_WARN(TAG, "CompleteAuthToken status %s [0x%08"PRIX32"]",
					          GetSecurityStatusString(status), status);
					return -1;
				}
			}

			if (nla->status == SEC_I_COMPLETE_NEEDED)
				nla->status = SEC_E_OK;
			else if (nla->status == SEC_I_COMPLETE_AND_CONTINUE)
				nla->status = SEC_I_CONTINUE_NEEDED;
		}

		if (nla->status == SEC_E_OK)
		{
			if (nla->outputBuffer.cbBuffer != 0)
			{
				if (!nla_send(nla))
				{
					nla_buffer_free(nla);
					return -1;
				}

				if (nla_recv(nla) < 0)
					return -1;

				WLog_DBG(TAG, "Receiving pubkey Token");
				nla_buffer_print(nla);
			}

			nla->havePubKeyAuth = TRUE;
			nla->status = nla->table->QueryContextAttributes(&nla->context, SECPKG_ATTR_SIZES,
			              &nla->ContextSizes);

			if (nla->status != SEC_E_OK)
			{
				WLog_ERR(TAG, "QueryContextAttributes SECPKG_ATTR_SIZES failure %s [0x%08"PRIX32"]",
				         GetSecurityStatusString(nla->status), nla->status);
				return -1;
			}

			nla->status = nla_decrypt_public_key_echo(nla);

			if (nla->status != SEC_E_OK)
			{
				WLog_ERR(TAG, "Error: could not verify client's public key echo %s [0x%08"PRIX32"]",
				         GetSecurityStatusString(nla->status), nla->status);
				return -1;
			}

			sspi_SecBufferFree(&nla->negoToken);
			nla->status = nla_encrypt_public_key_echo(nla);

			if (nla->status != SEC_E_OK)
				return -1;
		}

		if ((nla->status != SEC_E_OK) && (nla->status != SEC_I_CONTINUE_NEEDED))
		{
			/* Special handling of these specific error codes as NTSTATUS_FROM_WIN32
			   unfortunately does not map directly to the corresponding NTSTATUS values
			 */
			switch (GetLastError())
			{
				case ERROR_PASSWORD_MUST_CHANGE:
					nla->errorCode = STATUS_PASSWORD_MUST_CHANGE;
					break;

				case ERROR_PASSWORD_EXPIRED:
					nla->errorCode = STATUS_PASSWORD_EXPIRED;
					break;

				case ERROR_ACCOUNT_DISABLED:
					nla->errorCode = STATUS_ACCOUNT_DISABLED;
					break;

				default:
					nla->errorCode = NTSTATUS_FROM_WIN32(GetLastError());
					break;
			}

			WLog_ERR(TAG, "AcceptSecurityContext status %s [0x%08"PRIX32"]",
			         GetSecurityStatusString(nla->status), nla->status);
			nla_send(nla);
			return -1; /* Access Denied */
		}

		/* send authentication token */
		WLog_DBG(TAG, "%s() Sending Authentication Token", __FUNCTION__);
		nla_buffer_print(nla);

		if (!nla_send(nla))
		{
			nla_buffer_free(nla);
			return -1;
		}

		nla_buffer_free(nla);

		if (nla->status != SEC_I_CONTINUE_NEEDED)
			break;

		nla->haveContext = TRUE;
	}

	/* Receive encrypted credentials */

	if (nla_recv(nla) < 0)
		return -1;

	nla->status = nla_decrypt_ts_credentials(nla);

	if (nla->status != SEC_E_OK)
	{
		WLog_ERR(TAG, "Could not decrypt TSCredentials status %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(nla->status), nla->status);
		return -1;
	}

	nla->status = nla->table->ImpersonateSecurityContext(&nla->context);

	if (nla->status != SEC_E_OK)
	{
		WLog_ERR(TAG, "ImpersonateSecurityContext status %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(nla->status), nla->status);
		return -1;
	}
	else
	{
		nla->status = nla->table->RevertSecurityContext(&nla->context);

		if (nla->status != SEC_E_OK)
		{
			WLog_ERR(TAG, "RevertSecurityContext status %s [0x%08"PRIX32"]",
			         GetSecurityStatusString(nla->status), nla->status);
			return -1;
		}
	}

	nla->status = nla->table->FreeContextBuffer(nla->pPackageInfo);

	if (nla->status != SEC_E_OK)
	{
		WLog_ERR(TAG, "DeleteSecurityContext status %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(nla->status), nla->status);
		return -1;
	}

	return 1;
}

/**
 * Authenticate using CredSSP.
 * @param credssp
 * @return 1 if authentication is successful
 */

int nla_authenticate(rdpNla* nla)
{
	if (nla->server)
		return nla_server_authenticate(nla);
	else
		return nla_client_authenticate(nla);
}

static void ap_integer_increment_le(BYTE* number, int size)
{
	int index;

	for (index = 0; index < size; index++)
	{
		if (number[index] < 0xFF)
		{
			number[index]++;
			break;
		}
		else
		{
			number[index] = 0;
			continue;
		}
	}
}

static void ap_integer_decrement_le(BYTE* number, int size)
{
	int index;

	for (index = 0; index < size; index++)
	{
		if (number[index] > 0)
		{
			number[index]--;
			break;
		}
		else
		{
			number[index] = 0xFF;
			continue;
		}
	}
}

SECURITY_STATUS nla_encrypt_public_key_echo(rdpNla* nla)
{
	SecBuffer Buffers[2] = {{0}};
	SecBufferDesc Message;
	SECURITY_STATUS status;
	int public_key_length;

	sspi_CheckSecBuffer( & nla->pubKeyAuth);
	public_key_length = nla->PublicKey.cbBuffer;

	if (!sspi_SecBufferAlloc(&nla->pubKeyAuth, public_key_length + 2 * nla->ContextSizes.cbSecurityTrailer))
		return SEC_E_INSUFFICIENT_MEMORY;

	if (strcmp(nla->packageName, KERBEROS_SSP_NAME) == 0)
	{
		Buffers[0].BufferType = SECBUFFER_DATA; /* TLS Public Key */
		Buffers[0].cbBuffer = public_key_length;
		Buffers[0].pvBuffer = nla->pubKeyAuth.pvBuffer;
		CopyMemory(Buffers[0].pvBuffer, nla->PublicKey.pvBuffer, Buffers[0].cbBuffer);
	}
	else if ((strcmp(nla->packageName, NEGO_SSP_NAME) == 0) ||
	         (strcmp(nla->packageName, NTLM_SSP_NAME) == 0))
	{
		Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
		Buffers[0].pvBuffer = nla->pubKeyAuth.pvBuffer;
		Buffers[0].cbBuffer = nla->ContextSizes.cbSecurityTrailer;
		Buffers[0].cbBuffer2 = nla->ContextSizes.cbSecurityTrailer;

		Buffers[1].BufferType = SECBUFFER_DATA; /* TLS Public Key */
		Buffers[1].pvBuffer = ((BYTE*) nla->pubKeyAuth.pvBuffer) + nla->ContextSizes.cbSecurityTrailer;
		Buffers[1].cbBuffer = public_key_length;
		Buffers[1].cbBuffer2 = public_key_length + nla->ContextSizes.cbSecurityTrailer;

		CopyMemory(Buffers[1].pvBuffer, nla->PublicKey.pvBuffer, Buffers[1].cbBuffer);
	}

	if ((strcmp(nla->packageName, KERBEROS_SSP_NAME) != 0) && nla->server)
	{
		/* server echos the public key +1 */
		ap_integer_increment_le((BYTE*) Buffers[1].pvBuffer, Buffers[1].cbBuffer);
	}

	Message.cBuffers = 2;
	Message.ulVersion = SECBUFFER_VERSION;
	Message.pBuffers = (PSecBuffer) &Buffers;
	status = nla->table->EncryptMessage(&nla->context, 0, &Message, nla->sendSeqNum++);
	if (status != SEC_E_OK)
	{
		WLog_ERR(TAG, "EncryptMessage status %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(status), status);
		return status;
	}
	sspi_CheckSecBuffer( & nla->pubKeyAuth);

	return status;
}

SECURITY_STATUS nla_decrypt_public_key_echo(rdpNla* nla)
{
	int length;
	BYTE* buffer;
	ULONG pfQOP = 0;
	BYTE* public_key1 = NULL;
	BYTE* public_key2 = NULL;
	int public_key_length = 0;
	int signature_length;
	SecBuffer Buffers[2] = {{0}};
	SecBufferDesc Message;
	SECURITY_STATUS status;

	sspi_CheckSecBuffer( & nla->pubKeyAuth);
	signature_length = nla->pubKeyAuth.cbBuffer - nla->PublicKey.cbBuffer;

	if (signature_length < 0 || signature_length > nla->ContextSizes.cbSecurityTrailer)
	{
		WLog_ERR(TAG, "unexpected pubKeyAuth buffer size: %"PRIu32"", nla->pubKeyAuth.cbBuffer);
		return SEC_E_INVALID_TOKEN;
	}

	if ((nla->PublicKey.cbBuffer + nla->ContextSizes.cbSecurityTrailer) != nla->pubKeyAuth.cbBuffer)
	{
		WLog_ERR(TAG, "unexpected pubKeyAuth buffer size: %"PRIu32"", (int) nla->pubKeyAuth.cbBuffer);
		return SEC_E_INVALID_TOKEN;
	}

	length = nla->pubKeyAuth.cbBuffer;
	buffer = (BYTE*) malloc(length);

	if (!buffer)
		return SEC_E_INSUFFICIENT_MEMORY;

	if (strcmp(nla->packageName, KERBEROS_SSP_NAME) == 0)
	{
		CopyMemory(buffer, nla->pubKeyAuth.pvBuffer, length);
		Buffers[0].BufferType = SECBUFFER_DATA; /* Wrapped and encrypted TLS Public Key */
		Buffers[0].cbBuffer = length;
		Buffers[0].pvBuffer = buffer;
		Message.cBuffers = 1;
		Message.ulVersion = SECBUFFER_VERSION;
		Message.pBuffers = (PSecBuffer) &Buffers;
	}
	else if ((strcmp(nla->packageName, NEGO_SSP_NAME) == 0) ||
	         (strcmp(nla->packageName,  NTLM_SSP_NAME) == 0))
	{
		CopyMemory(buffer, nla->pubKeyAuth.pvBuffer, length);
		public_key_length = nla->PublicKey.cbBuffer;
		Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
		Buffers[0].cbBuffer = signature_length;
		Buffers[0].pvBuffer = buffer;
		Buffers[1].BufferType = SECBUFFER_DATA; /* Encrypted TLS Public Key */
		Buffers[1].cbBuffer = length - signature_length;
		Buffers[1].pvBuffer = buffer + signature_length;
		Message.cBuffers = 2;
		Message.ulVersion = SECBUFFER_VERSION;
		Message.pBuffers = (PSecBuffer) &Buffers;
	}

	status = nla->table->DecryptMessage(&nla->context, &Message, nla->recvSeqNum++, &pfQOP);

	if (status != SEC_E_OK)
	{
		WLog_ERR(TAG, "DecryptMessage failure %s [%08"PRIX32"]",
		         GetSecurityStatusString(status), status);
		free(buffer);
		return status;
	}

	if (strcmp(nla->packageName, KERBEROS_SSP_NAME) == 0)
	{
		public_key1 = public_key2 = (BYTE*) nla->pubKeyAuth.pvBuffer ;
		public_key_length = length;
	}
	else if ((strcmp(nla->packageName, NEGO_SSP_NAME) == 0) ||
	         (strcmp(nla->packageName, NTLM_SSP_NAME) == 0))
	{
		public_key1 = (BYTE*) nla->PublicKey.pvBuffer;
		public_key2 = (BYTE*) Buffers[1].pvBuffer;
	}

	if (!nla->server)
	{
		/* server echos the public key +1 */
		ap_integer_decrement_le(public_key2, public_key_length);
	}

	if (!public_key1 || !public_key2 || memcmp(public_key1, public_key2, public_key_length) != 0)
	{
		WLog_ERR(TAG, "Could not verify server's public key echo");
		WLog_ERR(TAG, "Expected (length = %d):", public_key_length);
		winpr_HexDump(TAG, WLOG_ERROR, public_key1, public_key_length);
		WLog_ERR(TAG, "Actual (length = %d):", public_key_length);
		winpr_HexDump(TAG, WLOG_ERROR, public_key2, public_key_length);
		free(buffer);
		return SEC_E_MESSAGE_ALTERED; /* DO NOT SEND CREDENTIALS! */
	}

	sspi_CheckSecBuffer( & nla->pubKeyAuth);
	free(buffer);
	return SEC_E_OK;
}

int nla_sizeof_ts_password_creds(rdpNla* nla)
{
	int length = 0;

	if (nla->identity)
	{
		length += ber_sizeof_sequence_octet_string(nla->identity->DomainLength * 2);
		length += ber_sizeof_sequence_octet_string(nla->identity->UserLength * 2);
		length += ber_sizeof_sequence_octet_string(nla->identity->PasswordLength * 2);
	}

	return length;
}

static int nla_sizeof_ts_cspdatadetail(rdpNla* nla)
{
	int length = 0;

	if (nla->identity->CspData)
	{
		length += ber_sizeof_contextual_tag(ber_sizeof_integer(nla->identity->CspData->KeySpec));
		length += ber_sizeof_integer(nla->identity->CspData->KeySpec);
		length += ber_sizeof_sequence_octet_string(nla->identity->CspData->CardNameLength * 2);
		length += ber_sizeof_sequence_octet_string(nla->identity->CspData->ReaderNameLength * 2);
		length += ber_sizeof_sequence_octet_string(nla->identity->CspData->ContainerNameLength * 2);
		length += ber_sizeof_sequence_octet_string(nla->identity->CspData->CspNameLength * 2);
	}

	return length;
}

int nla_sizeof_sequence_ts_cspdatadetail(rdpNla* nla)
{
	int length = 0;
	length += nla_sizeof_ts_cspdatadetail(nla);
	length += ber_sizeof_sequence_tag(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

int nla_sizeof_ts_smartcard_creds(rdpNla* nla)
{
	int length = 0;

	if (nla->identity)
	{
		length += ber_sizeof_sequence_octet_string(nla->identity->PinLength * 2);
		length += nla_sizeof_sequence_ts_cspdatadetail(nla);
		length += ber_sizeof_sequence_octet_string(nla->identity->UserHintLength * 2);
		length += ber_sizeof_sequence_octet_string(nla->identity->DomainHintLength * 2);
	}

	return length;
}

int nla_sizeof_ts_pwd_or_sc_creds(rdpNla* nla, SEC_DELEGATION_CREDENTIALS_TYPE credType)
{
	switch (credType)
	{
		case SEC_PASSWORD_DELEGATION_CRED_TYPE:
			return nla_sizeof_ts_password_creds(nla);

		case SEC_SMARTCARD_DELEGATION_CRED_TYPE:
			return nla_sizeof_ts_smartcard_creds(nla);

		default:
			return 0;
	}
}

int nla_sizeof_ts_credentials(rdpNla* nla)
{
	int size = 0;
	size += ber_sizeof_integer(nla->credType);
	size += ber_sizeof_contextual_tag(ber_sizeof_integer(nla->credType));
	size += ber_sizeof_sequence_octet_string(ber_sizeof_sequence((nla_sizeof_ts_pwd_or_sc_creds(nla,
	        nla->credType))));
	return size;
}

BOOL nla_read_ts_password_creds(rdpNla* nla, wStream* s)
{
	int length;

	if (!nla->identity)
	{
		WLog_ERR(TAG, "nla->identity is NULL!");
		return FALSE;
	}

	/* TSPasswordCreds (SEQUENCE)
	 * Initialise to default values. */
	nla->identity->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
	nla->identity->UserLength = (UINT32) 0;
	nla->identity->User = NULL;
	nla->identity->DomainLength = (UINT32) 0;
	nla->identity->Domain = NULL;
	nla->identity->Password = NULL;
	nla->identity->PasswordLength = (UINT32) 0;

	if (!ber_read_sequence_tag(s, &length))
		return FALSE;

	/* The sequence is empty, return early,
	 * TSPasswordCreds (SEQUENCE) is optional. */
	if (length == 0)
		return TRUE;

	/* [0] domainName (OCTET STRING) */
	if (!ber_read_contextual_tag(s, 0, &length, TRUE) ||
	    !ber_read_octet_string_tag(s, &length))
	{
		return FALSE;
	}

	nla->identity->DomainLength = (UINT32) length;

	if (nla->identity->DomainLength > 0)
	{
		nla->identity->Domain = (UINT16*) malloc(length);

		if (!nla->identity->Domain)
			return FALSE;

		CopyMemory(nla->identity->Domain, Stream_Pointer(s), nla->identity->DomainLength);
		Stream_Seek(s, nla->identity->DomainLength);
		nla->identity->DomainLength /= 2;
	}

	/* [1] userName (OCTET STRING) */
	if (!ber_read_contextual_tag(s, 1, &length, TRUE) ||
	    !ber_read_octet_string_tag(s, &length))
	{
		return FALSE;
	}

	nla->identity->UserLength = (UINT32) length;

	if (nla->identity->UserLength > 0)
	{
		nla->identity->User = (UINT16*) malloc(length);

		if (!nla->identity->User)
			return FALSE;

		CopyMemory(nla->identity->User, Stream_Pointer(s), nla->identity->UserLength);
		Stream_Seek(s, nla->identity->UserLength);
		nla->identity->UserLength /= 2;
	}

	/* [2] password (OCTET STRING) */
	if (!ber_read_contextual_tag(s, 2, &length, TRUE) ||
	    !ber_read_octet_string_tag(s, &length))
	{
		return FALSE;
	}

	nla->identity->PasswordLength = (UINT32) length;

	if (nla->identity->PasswordLength > 0)
	{
		nla->identity->Password = (UINT16*) malloc(length);

		if (!nla->identity->Password)
			return FALSE;

		CopyMemory(nla->identity->Password, Stream_Pointer(s), nla->identity->PasswordLength);
		Stream_Seek(s, nla->identity->PasswordLength);
		nla->identity->PasswordLength /= 2;
	}

	return TRUE;
}

BOOL nla_read_ts_cspdatadetail(rdpNla* nla, wStream* s, int* length)
{
	if (!nla->identity->CspData)
		return FALSE;

	/* TSCspDataDetail (SEQUENCE)
	 * Initialise to default values. */
	nla->identity->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
	nla->identity->CspData->KeySpec = (UINT32) 0;
	nla->identity->CspData->CardNameLength = (UINT32) 0;
	nla->identity->CspData->CardName = NULL;
	nla->identity->CspData->ReaderNameLength = (UINT32) 0;
	nla->identity->CspData->ReaderName = NULL;
	nla->identity->CspData->ContainerNameLength = (UINT32) 0;
	nla->identity->CspData->ContainerName = NULL;
	nla->identity->CspData->CspNameLength = (UINT32) 0;
	nla->identity->CspData->CspName = NULL;

	if (!ber_read_sequence_tag(s, length))
	{
		return FALSE;
	}

	/* The sequence is empty, return early,
	 * TSCspDataDetail (SEQUENCE) is optional. */
	if (*length == 0)
		return TRUE;

	/* [0] keySpec (INTEGER) */
	if (!ber_read_contextual_tag(s, 0, length, TRUE) ||
	    !ber_read_integer(s, &nla->identity->CspData->KeySpec))
		return FALSE;

	/* [1] cardName (OCTET STRING) */
	if (!ber_read_contextual_tag(s, 1, length, TRUE) ||
	    !ber_read_octet_string_tag(s, length))
		return FALSE;

	nla->identity->CspData->CardNameLength = (UINT32)(*length);

	if (nla->identity->CspData->CardNameLength > 0)
	{
		nla->identity->CspData->CardName = (UINT16*) calloc(1, *length);

		if (!nla->identity->CspData->CardName)
			return FALSE;

		CopyMemory(nla->identity->CspData->CardName, Stream_Pointer(s),
		           nla->identity->CspData->CardNameLength);
		Stream_Seek(s, nla->identity->CspData->CardNameLength);
		nla->identity->CspData->CardNameLength /= 2;
	}

	/* [2] readerName (OCTET STRING) */
	if (!ber_read_contextual_tag(s, 2, length, TRUE) ||
	    !ber_read_octet_string_tag(s, length))
		return FALSE;

	nla->identity->CspData->ReaderNameLength = (UINT32)(*length);

	if (nla->identity->CspData->ReaderNameLength > 0)
	{
		nla->identity->CspData->ReaderName = (UINT16*) calloc(1, *length);

		if (!nla->identity->CspData->ReaderName)
			return FALSE;

		CopyMemory(nla->identity->CspData->ReaderName, Stream_Pointer(s),
		           nla->identity->CspData->ReaderNameLength);
		Stream_Seek(s, nla->identity->CspData->ReaderNameLength);
		nla->identity->CspData->ReaderNameLength /= 2;
	}

	/* [3] containerName (OCTET STRING) */
	if (!ber_read_contextual_tag(s, 3, length, TRUE) ||
	    !ber_read_octet_string_tag(s, length))
		return FALSE;

	nla->identity->CspData->ContainerNameLength = (UINT32)(*length);

	if (nla->identity->CspData->ContainerNameLength > 0)
	{
		nla->identity->CspData->ContainerName = (UINT16*) calloc(1, *length);

		if (!nla->identity->CspData->ContainerName)
			return FALSE;

		CopyMemory(nla->identity->CspData->ContainerName, Stream_Pointer(s),
		           nla->identity->CspData->ContainerNameLength);
		Stream_Seek(s, nla->identity->CspData->ContainerNameLength);
		nla->identity->CspData->ContainerNameLength /= 2;
	}

	/* [4] cspName (OCTET STRING) */
	if (!ber_read_contextual_tag(s, 4, length, TRUE) ||
	    !ber_read_octet_string_tag(s, length))
		return FALSE;

	nla->identity->CspData->CspNameLength = (UINT32)(*length);

	if (nla->identity->CspData->CspNameLength > 0)
	{
		nla->identity->CspData->CspName = (UINT16*) calloc(1, *length);

		if (!nla->identity->CspData->CspName)
			return FALSE;

		CopyMemory(nla->identity->CspData->CspName, Stream_Pointer(s),
		           nla->identity->CspData->CspNameLength);
		Stream_Seek(s, nla->identity->CspData->CspNameLength);
		nla->identity->CspData->CspNameLength /= 2;
	}

	return TRUE;
}


BOOL nla_read_ts_smartcard_creds(rdpNla* nla, wStream* s)
{
	int length = 0 ;

	if (!nla->identity)
		return FALSE;

	/* TSSmartCardCreds (SEQUENCE)
	 * Initialize to default values. */
	nla->identity->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
	nla->identity->Pin = NULL;
	nla->identity->PinLength = (UINT32) 0;
	nla->identity->CspData = NULL;
	nla->identity->UserHint = NULL;
	nla->identity->UserHintLength = (UINT32) 0;
	nla->identity->DomainHint = NULL;
	nla->identity->DomainLength = (UINT32) 0;

	if (!ber_read_sequence_tag(s, &length))
		return FALSE;

	/* The sequence is empty, return early,
	 * TSSmartCardCreds (SEQUENCE) is optional. */
	if (length == 0)
		return TRUE;

	/* [0] Pin (OCTET STRING) */
	if (!ber_read_contextual_tag(s, 0, &length, TRUE) ||
	    !ber_read_octet_string_tag(s, &length))
		return FALSE;

	nla->identity->PinLength = (UINT32) length;

	if (nla->identity->PinLength > 0)
	{
		nla->identity->Pin = (UINT16*) malloc(length);

		if (!nla->identity->Pin)
			return FALSE;

		CopyMemory(nla->identity->Pin, Stream_Pointer(s), nla->identity->PinLength);
		Stream_Seek(s, nla->identity->PinLength);
		nla->identity->PinLength /= 2;
	}

	/* [1] CspDataDetail (TSCspDataDetail) */
	nla->identity->CspData = (SEC_WINNT_AUTH_IDENTITY_CSPDATADETAIL*) calloc(1,
	                         sizeof(SEC_WINNT_AUTH_IDENTITY_CSPDATADETAIL));

	if (!nla->identity->CspData)
		return FALSE;

	if (!nla_read_ts_cspdatadetail(nla, s, &length))
		return FALSE;

	/* [2] UserHint (OCTET STRING) */
	if (!ber_read_contextual_tag(s, 2, &length, TRUE) ||
	    !ber_read_octet_string_tag(s, &length))
		return FALSE;

	nla->identity->UserHintLength = (UINT32) length;

	if (nla->identity->UserHintLength > 0)
	{
		nla->identity->UserHint = (UINT16*) malloc(length);

		if (!nla->identity->UserHint)
			return FALSE;

		CopyMemory(nla->identity->UserHint, Stream_Pointer(s), nla->identity->UserHintLength);
		Stream_Seek(s, nla->identity->UserHintLength);
		nla->identity->UserHintLength /= 2;
	}

	/* [3] DomainHint (OCTET STRING) */
	if (!ber_read_contextual_tag(s, 3, &length, TRUE) ||
	    !ber_read_octet_string_tag(s, &length))
		return FALSE;

	nla->identity->DomainHintLength = (UINT32) length;

	if (nla->identity->DomainHintLength > 0)
	{
		nla->identity->DomainHint = (UINT16*) malloc(length);

		if (!nla->identity->DomainHint)
			return FALSE;

		CopyMemory(nla->identity->DomainHint, Stream_Pointer(s), nla->identity->DomainHintLength);
		Stream_Seek(s, nla->identity->DomainHintLength);
		nla->identity->DomainHintLength /= 2;
	}

	return TRUE;
}

static int nla_write_ts_password_creds(rdpNla* nla, wStream* s)
{
	int size = 0;
	int innerSize = nla_sizeof_ts_password_creds(nla);
	/* TSPasswordCreds (SEQUENCE) */
	size += ber_write_sequence_tag(s, innerSize);

	if (nla->identity)
	{
		/* [0] domainName (OCTET STRING) */
		size += ber_write_sequence_octet_string(
		            s, 0, (BYTE*) nla->identity->Domain,
		            nla->identity->DomainLength * 2);
		/* [1] userName (OCTET STRING) */
		size += ber_write_sequence_octet_string(
		            s, 1, (BYTE*) nla->identity->User,
		            nla->identity->UserLength * 2);
		/* [2] password (OCTET STRING) */
		size += ber_write_sequence_octet_string(
		            s, 2, (BYTE*) nla->identity->Password,
		            nla->identity->PasswordLength * 2);
	}

	return size;
}

int nla_write_ts_smartcard_creds(rdpNla* nla, wStream* s)
{
	int size = 0;
	int innerSize = nla_sizeof_ts_smartcard_creds(nla);
	/* TSSmartCardCreds (SEQUENCE) */
	size += ber_write_sequence_tag(s, innerSize);

	if (nla->identity)
	{
		/* [0] Pin (OCTET STRING) */
		size += ber_write_sequence_octet_string(
		            s, 0, (BYTE*) nla->identity->Pin,
		            nla->identity->PinLength * 2);
		/* [1] CspDataDetail (TSCspDataDetail) (SEQUENCE) */
		size += ber_write_contextual_tag(s, 1, ber_sizeof_sequence(nla_sizeof_ts_cspdatadetail(nla)), TRUE);
		size += ber_write_sequence_tag(s, nla_sizeof_ts_cspdatadetail(nla));
		/* [0] KeySpec (INTEGER) */
		size += ber_write_contextual_tag(s, 0, ber_sizeof_integer(nla->identity->CspData->KeySpec), TRUE);
		size += ber_write_integer(s, nla->identity->CspData->KeySpec);
		/* [1] CardName (OCTER STRING) */
		size += ber_write_sequence_octet_string(s, 1, (BYTE*) nla->identity->CspData->CardName,
		                                        nla->identity->CspData->CardNameLength * 2);  /* OCTET STRING */
		/* [2] ReaderName (OCTER STRING) */
		size += ber_write_sequence_octet_string(s, 2, (BYTE*) nla->identity->CspData->ReaderName,
		                                        nla->identity->CspData->ReaderNameLength * 2);	/* OCTET STRING */
		/* [3] ContainerName (OCTER STRING) */
		size += ber_write_sequence_octet_string(s, 3, (BYTE*) nla->identity->CspData->ContainerName,
		                                        nla->identity->CspData->ContainerNameLength * 2);  /* OCTET STRING */
		/* [4] CspName (OCTER STRING) */
		size += ber_write_sequence_octet_string(s, 4, (BYTE*) nla->identity->CspData->CspName,
		                                        nla->identity->CspData->CspNameLength * 2);  /* OCTET STRING */
		/* [2] userHint (OCTET STRING) */
		size += ber_write_sequence_octet_string(
		            s, 2, (BYTE*) nla->identity->UserHint,
		            nla->identity->UserHintLength * 2);
		/* [3] domainHint (OCTET STRING) */
		size += ber_write_sequence_octet_string(
		            s, 3, (BYTE*) nla->identity->DomainHint,
		            nla->identity->DomainHintLength * 2);
	}

	return size;
}

int nla_write_ts_creds(rdpNla* nla, wStream* s, SEC_DELEGATION_CREDENTIALS_TYPE credType)
{
	switch (credType)
	{
		case SEC_PASSWORD_DELEGATION_CRED_TYPE:
			return nla_write_ts_password_creds(nla, s);

		case SEC_SMARTCARD_DELEGATION_CRED_TYPE:
			return nla_write_ts_smartcard_creds(nla, s);

		case SEC_REMOTE_GUARD_CRED_TYPE:
			WLog_ERR(TAG,  "%s:%d:%s(): credType not implemented: %d (%s)\n",
			         __FILE__, __LINE__, __FUNCTION__,
			         credType, "SEC_REMOTE_GUARD_CRED_TYPE");
			return 0;

		default:
			WLog_ERR(TAG,  "%s:%d:%s(): credType unknown: %d\n",
			         __FILE__, __LINE__, __FUNCTION__,
			         credType);
			return 0;
	}
}

int nla_read_ts_creds(rdpNla* nla, wStream* s, SEC_DELEGATION_CREDENTIALS_TYPE credType)
{
	switch (credType)
	{
		case SEC_PASSWORD_DELEGATION_CRED_TYPE:
			return nla_read_ts_password_creds(nla, s);

		case SEC_SMARTCARD_DELEGATION_CRED_TYPE:
			return nla_read_ts_smartcard_creds(nla, s);

		case SEC_REMOTE_GUARD_CRED_TYPE:
			WLog_ERR(TAG,  "%s:%d:%s(): credType not implemented: %d (%s)\n",
			         __FILE__, __LINE__, __FUNCTION__,
			         credType, "SEC_REMOTE_GUARD_CRED_TYPE");
			return 0;

		default:
			WLog_ERR(TAG,  "%s:%d:%s(): credType unknown: %d\n",
			         __FILE__, __LINE__, __FUNCTION__,
			         credType);
			return 0;
	}
}


BOOL nla_read_ts_credentials(rdpNla* nla, PSecBuffer ts_credentials)
{
	wStream* s;
	int length = 0;
	int ts_creds_length = 0;
	UINT32* value = NULL;
	BOOL ret;

	if (!ts_credentials || !ts_credentials->pvBuffer)
		return FALSE;

	s = Stream_New(ts_credentials->pvBuffer, ts_credentials->cbBuffer);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return FALSE;
	}

	/* TSCredentials (SEQUENCE) */
	ret = ber_read_sequence_tag(s, &length) &&
	      /* [0] credType (INTEGER) */
	      ber_read_contextual_tag(s, 0, &length, TRUE) &&
	      ber_read_integer(s, value) &&
	      /* [1] credentials (OCTET STRING) */
	      ber_read_contextual_tag(s, 1, &length, TRUE) &&
	      ber_read_octet_string_tag(s, &ts_creds_length) &&
	      (nla_read_ts_creds(nla, s, *value)) ;
	Stream_Free(s, FALSE);
	return ret;
}

static int nla_write_ts_credentials(rdpNla* nla, wStream* s)
{
	int size = 0;
	int credSize = 0;
	int innerSize = nla_sizeof_ts_credentials(nla);
	/* TSCredentials (SEQUENCE) */
	size += ber_write_sequence_tag(s, innerSize);
	/* [0] credType (INTEGER) */
	size += ber_write_contextual_tag(s, 0, ber_sizeof_integer(nla->credType), TRUE);
	size += ber_write_integer(s, nla->credType);
	/* [1] credentials (OCTET STRING) */
	credSize = ber_sizeof_sequence((nla_sizeof_ts_pwd_or_sc_creds(nla, nla->credType)));
	size += ber_write_contextual_tag(s, 1, ber_sizeof_octet_string(credSize), TRUE);
	size += ber_write_octet_string_tag(s, credSize);
	size += nla_write_ts_creds(nla, s, nla->credType);
	return size;
}

/**
 * Encode TSCredentials structure.
 * @param credssp
 */

static BOOL nla_encode_ts_credentials(rdpNla* nla)
{
	wStream* s;
	int length;
	int DomainLength = 0;
	int UserLength = 0;
	int PasswordLength = 0;
	int PinLength = 0;
	int CardNameLength = 0;
	int ReaderNameLength = 0;
	int ContainerNameLength = 0;
	int CspNameLength = 0;
	int UserHintLength = 0;
	int DomainHintLength = 0;

	if (nla->identity)
	{
		if (nla->identity->PasswordLength)
		{
			/* TSPasswordCreds */
			DomainLength = nla->identity->DomainLength;
			UserLength = nla->identity->UserLength;
			PasswordLength = nla->identity->PasswordLength;
		}
		else
		{
			/* TSSmartCardCreds */
			if (nla->identity->CspData != NULL)
			{
				PinLength = nla->identity->PinLength;
				CardNameLength = nla->identity->CspData->CardNameLength;
				ReaderNameLength = nla->identity->CspData->ReaderNameLength;
				ContainerNameLength = nla->identity->CspData->ContainerNameLength;
				CspNameLength = nla->identity->CspData->CspNameLength;
				UserHintLength = nla->identity->UserHintLength;
				DomainHintLength = nla->identity->DomainHintLength;
			}
		}
	}

	if (nla->settings->DisableCredentialsDelegation && nla->identity)
	{
		/* TSPasswordCreds */
		nla->identity->DomainLength = 0;
		nla->identity->UserLength = 0;
		nla->identity->PasswordLength = 0;

		/* TSSmartCardCreds */
		if (nla->identity->CspData != NULL)
		{
			nla->identity->PinLength = 0;
			nla->identity->CspData->CardNameLength = 0;
			nla->identity->CspData->ReaderNameLength = 0;
			nla->identity->CspData->ContainerNameLength = 0;
			nla->identity->CspData->CspNameLength = 0;
			nla->identity->UserHintLength = 0;
			nla->identity->DomainHintLength = 0;
		}
	}

	length = ber_sizeof_sequence(nla_sizeof_ts_credentials(nla));

	if (!sspi_SecBufferAlloc(&nla->tsCredentials, length))
	{
		WLog_ERR(TAG, "sspi_SecBufferAlloc failed!");
		return FALSE;
	}

	s = Stream_New((BYTE*) nla->tsCredentials.pvBuffer, length);

	if (!s)
	{
		sspi_SecBufferFree(&nla->tsCredentials);
		WLog_ERR(TAG, "Stream_New failed!");
		return FALSE;
	}

	nla_write_ts_credentials(nla, s);

	if (nla->settings->DisableCredentialsDelegation)
	{
		/* TSPasswordCreds */
		nla->identity->DomainLength = DomainLength;
		nla->identity->UserLength = UserLength;
		nla->identity->PasswordLength = PasswordLength;
		/* TSSmartCardCreds */
		nla->identity->PinLength = PinLength;
		nla->identity->CspData->CardNameLength = CardNameLength;
		nla->identity->CspData->ReaderNameLength = ReaderNameLength;
		nla->identity->CspData->ContainerNameLength = ContainerNameLength;
		nla->identity->CspData->CspNameLength = CspNameLength;
		nla->identity->UserHintLength = UserHintLength;
		nla->identity->DomainHintLength = DomainHintLength;
	}

	Stream_Free(s, FALSE);
	return TRUE;
}

static SECURITY_STATUS nla_encrypt_ts_credentials(rdpNla* nla)
{
	SecBuffer Buffers[2] = {{0}};
	SecBufferDesc Message;
	SECURITY_STATUS status;

	if (!nla_encode_ts_credentials(nla))
		return SEC_E_INSUFFICIENT_MEMORY;

	if (!sspi_SecBufferAlloc(&nla->authInfo,
	                         nla->tsCredentials.cbBuffer + nla->ContextSizes.cbSecurityTrailer))
		return SEC_E_INSUFFICIENT_MEMORY;

	if (strcmp(nla->packageName, KERBEROS_SSP_NAME) == 0)
	{
		Buffers[0].BufferType = SECBUFFER_DATA; /* TSCredentials */
		Buffers[0].cbBuffer = nla->tsCredentials.cbBuffer;
		Buffers[0].pvBuffer = nla->authInfo.pvBuffer;
		CopyMemory(Buffers[0].pvBuffer, nla->tsCredentials.pvBuffer, Buffers[0].cbBuffer);
		Message.cBuffers = 1;
		Message.ulVersion = SECBUFFER_VERSION;
		Message.pBuffers = (PSecBuffer) &Buffers;
	}
	else if ((strcmp(nla->packageName, NEGO_SSP_NAME) == 0) ||
	         (strcmp(nla->packageName, NTLM_SSP_NAME) == 0))
	{
		Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
		Buffers[0].cbBuffer = nla->ContextSizes.cbSecurityTrailer;
		Buffers[0].pvBuffer = nla->authInfo.pvBuffer;
		MoveMemory(Buffers[0].pvBuffer, nla->authInfo.pvBuffer, Buffers[0].cbBuffer);
		Buffers[1].BufferType = SECBUFFER_DATA; /* TSCredentials */
		Buffers[1].cbBuffer = nla->tsCredentials.cbBuffer;
		Buffers[1].pvBuffer = &((BYTE*) nla->authInfo.pvBuffer)[Buffers[0].cbBuffer];
		CopyMemory(Buffers[1].pvBuffer, nla->tsCredentials.pvBuffer, Buffers[1].cbBuffer);
		Message.cBuffers = 2;
		Message.ulVersion = SECBUFFER_VERSION;
		Message.pBuffers = (PSecBuffer) &Buffers;
	}

	status = nla->table->EncryptMessage(&nla->context, 0, &Message, nla->sendSeqNum++);

	if (status != SEC_E_OK)
	{
		WLog_ERR(TAG, "EncryptMessage failure %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(status), status);
		return status;
	}

	return SEC_E_OK;
}

static SECURITY_STATUS nla_decrypt_ts_credentials(rdpNla* nla)
{
	int length;
	BYTE* buffer;
	ULONG pfQOP;
	SecBuffer Buffers[2] = {{0}};
	SecBufferDesc Message;
	SECURITY_STATUS status;

	if (nla->authInfo.cbBuffer < 1)
	{
		WLog_ERR(TAG, "nla_decrypt_ts_credentials missing authInfo buffer");
		return SEC_E_INVALID_TOKEN;
	}

	length = nla->authInfo.cbBuffer;
	buffer = (BYTE*) malloc(length);

	if (!buffer)
		return SEC_E_INSUFFICIENT_MEMORY;

	if (strcmp(nla->packageName, KERBEROS_SSP_NAME) == 0)
	{
		CopyMemory(buffer, nla->authInfo.pvBuffer, length);
		Buffers[0].BufferType = SECBUFFER_DATA; /* Wrapped and encrypted TSCredentials */
		Buffers[0].cbBuffer = length;
		Buffers[0].pvBuffer = buffer;
		Message.cBuffers = 1;
		Message.ulVersion = SECBUFFER_VERSION;
		Message.pBuffers = (PSecBuffer) &Buffers;
	}
	else if ((strcmp(nla->packageName,  NEGO_SSP_NAME) == 0) ||
	         (strcmp(nla->packageName, NTLM_SSP_NAME) == 0))
	{
		CopyMemory(buffer, nla->authInfo.pvBuffer, length);
		Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
		Buffers[0].cbBuffer = nla->ContextSizes.cbSecurityTrailer;
		Buffers[0].pvBuffer = buffer;
		Buffers[1].BufferType = SECBUFFER_DATA; /* TSCredentials */
		Buffers[1].cbBuffer = length - nla->ContextSizes.cbSecurityTrailer;
		Buffers[1].pvBuffer = &buffer[ Buffers[0].cbBuffer ];
		Message.cBuffers = 2;
		Message.ulVersion = SECBUFFER_VERSION;
		Message.pBuffers = (PSecBuffer) &Buffers;
	}

	status = nla->table->DecryptMessage(&nla->context, &Message, nla->recvSeqNum++, &pfQOP);

	if (status != SEC_E_OK)
	{
		WLog_ERR(TAG, "DecryptMessage failure %s [0x%08"PRIX32"]",
		         GetSecurityStatusString(status), status);
		free(buffer);
		return status;
	}

	if (!nla_read_ts_credentials(nla, &Buffers[1]))
	{
		free(buffer);
		return SEC_E_INSUFFICIENT_MEMORY;
	}

	free(buffer);
	return SEC_E_OK;
}

static int nla_sizeof_nego_token(int length)
{
	length = ber_sizeof_octet_string(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

static int nla_sizeof_nego_tokens(int length)
{
	length = nla_sizeof_nego_token(length);
	length += ber_sizeof_sequence_tag(length);
	length += ber_sizeof_sequence_tag(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

static int nla_sizeof_pub_key_auth(int length)
{
	length = ber_sizeof_octet_string(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

static int nla_sizeof_auth_info(int length)
{
	length = ber_sizeof_octet_string(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

static int nla_sizeof_ts_request(int length)
{
	length += ber_sizeof_integer(2);
	length += ber_sizeof_contextual_tag(3);
	return length;
}

/**
 * Send CredSSP message.
 * @param credssp
 */

BOOL nla_send(rdpNla* nla)
{
	wStream* s;
	int length;
	int ts_request_length;
	int nego_tokens_length = 0;
	int pub_key_auth_length = 0;
	int auth_info_length = 0;
	int error_code_context_length = 0;
	int error_code_length = 0;

	sspi_CheckSecBuffer( & nla->pubKeyAuth);
	if (nla->version < 3 || nla->errorCode == 0)
	{
		nego_tokens_length = (nla->negoToken.cbBuffer > 0) ? nla_sizeof_nego_tokens(
		                         nla->negoToken.cbBuffer) : 0;
		pub_key_auth_length = (nla->pubKeyAuth.cbBuffer > 0) ? nla_sizeof_pub_key_auth(
		                          nla->pubKeyAuth.cbBuffer) : 0;
		auth_info_length = (nla->authInfo.cbBuffer > 0) ? nla_sizeof_auth_info(nla->authInfo.cbBuffer) : 0;
	}
	else
	{
		error_code_length = ber_sizeof_integer(nla->errorCode);
		error_code_context_length = ber_sizeof_contextual_tag(error_code_length);
	}

	length = nego_tokens_length + pub_key_auth_length + auth_info_length + error_code_context_length +
	         error_code_length;
	ts_request_length = nla_sizeof_ts_request(length);
	s = Stream_New(NULL, ber_sizeof_sequence(ts_request_length));

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return FALSE;
	}

	/* TSRequest */
	ber_write_sequence_tag(s, ts_request_length); /* SEQUENCE */
	/* [0] version */
	ber_write_contextual_tag(s, 0, 3, TRUE);
	ber_write_integer(s, nla->version); /* INTEGER */

	/* [1] negoTokens (NegoData) */
	if (nego_tokens_length > 0)
	{
		int length = ber_write_contextual_tag(s, 1,
		                                      ber_sizeof_sequence(ber_sizeof_sequence(ber_sizeof_sequence_octet_string(nla->negoToken.cbBuffer))),
		                                      TRUE); /* NegoData */
		length += ber_write_sequence_tag(s,
		                                 ber_sizeof_sequence(ber_sizeof_sequence_octet_string(
		                                         nla->negoToken.cbBuffer))); /* SEQUENCE OF NegoDataItem */
		length += ber_write_sequence_tag(s,
		                                 ber_sizeof_sequence_octet_string(nla->negoToken.cbBuffer)); /* NegoDataItem */
		length += ber_write_sequence_octet_string(s, 0, (BYTE*) nla->negoToken.pvBuffer,
		          nla->negoToken.cbBuffer);  /* OCTET STRING */

		if (length != nego_tokens_length)
			return FALSE;
	}

	/* [2] authInfo (OCTET STRING) */
	if (auth_info_length > 0)
	{
		if (ber_write_sequence_octet_string(s, 2, nla->authInfo.pvBuffer,
		                                    nla->authInfo.cbBuffer) != auth_info_length)
			return FALSE;
	}

	/* [3] pubKeyAuth (OCTET STRING) */
	if (pub_key_auth_length > 0)
	{
		if (ber_write_sequence_octet_string(s, 3, nla->pubKeyAuth.pvBuffer,
		                                    nla->pubKeyAuth.cbBuffer) != pub_key_auth_length)
			return FALSE;
	}

	/* [4] errorCode (INTEGER) */
	if (error_code_length > 0)
	{
		ber_write_contextual_tag(s, 4, error_code_length, TRUE);
		ber_write_integer(s, nla->errorCode);
	}

	Stream_SealLength(s);
	transport_write(nla->transport, s);
	Stream_Free(s, TRUE);
	sspi_CheckSecBuffer( & nla->pubKeyAuth);
	return TRUE;
}

static int nla_decode_ts_request(rdpNla* nla, wStream* s)
{
	int length;
	sspi_CheckSecBuffer( & nla->pubKeyAuth);

	/* TSRequest */
	if (!ber_read_sequence_tag(s, &length) ||
	    !ber_read_contextual_tag(s, 0, &length, TRUE) ||
	    !ber_read_integer(s, &nla->version))
	{
		return -1;
	}

	/* [1] negoTokens (NegoData) */
	if (ber_read_contextual_tag(s, 1, &length, TRUE) != FALSE)
	{
		if (!ber_read_sequence_tag(s, &length) || /* SEQUENCE OF NegoDataItem */
		    !ber_read_sequence_tag(s, &length) || /* NegoDataItem */
		    !ber_read_contextual_tag(s, 0, &length, TRUE) || /* [0] negoToken */
		    !ber_read_octet_string_tag(s, &length) || /* OCTET STRING */
		    ((int) Stream_GetRemainingLength(s)) < length)
		{
			return -1;
		}

		if (!sspi_SecBufferAlloc(&nla->negoToken, length))
			return -1;

		Stream_Read(s, nla->negoToken.pvBuffer, length);
		nla->negoToken.cbBuffer = length;
	}

	/* [2] authInfo (OCTET STRING) */
	if (ber_read_contextual_tag(s, 2, &length, TRUE) != FALSE)
	{
		if (!ber_read_octet_string_tag(s, &length) || /* OCTET STRING */
		    ((int) Stream_GetRemainingLength(s)) < length)
			return -1;

		if (!sspi_SecBufferAlloc(&nla->authInfo, length))
			return -1;

		Stream_Read(s, nla->authInfo.pvBuffer, length);
		nla->authInfo.cbBuffer = length;
	}

	/* [3] pubKeyAuth (OCTET STRING) */
	if (ber_read_contextual_tag(s, 3, &length, TRUE) != FALSE)
	{
		if (!ber_read_octet_string_tag(s, &length) || /* OCTET STRING */
		    ((int) Stream_GetRemainingLength(s)) < length)
			return -1;

		if (!sspi_SecBufferAlloc(&nla->pubKeyAuth, length))
			return -1;

		Stream_Read(s, nla->pubKeyAuth.pvBuffer, length);
		nla->pubKeyAuth.cbBuffer = length;
	}

	/* [4] errorCode (INTEGER) */
	if (nla->version >= 3)
	{
		if (ber_read_contextual_tag(s, 4, &length, TRUE) != FALSE)
		{
			if (!ber_read_integer(s, &nla->errorCode))
				return -1;
		}
	}

	sspi_CheckSecBuffer( & nla->pubKeyAuth);
	return 1;
}

int nla_recv_pdu(rdpNla* nla, wStream* s)
{
	if (nla_decode_ts_request(nla, s) < 1)
		return -1;

	if (nla->errorCode)
	{
		UINT32 code;

		switch (nla->errorCode)
		{
			case STATUS_PASSWORD_MUST_CHANGE:
				code = FREERDP_ERROR_CONNECT_PASSWORD_MUST_CHANGE;
				break;

			case STATUS_PASSWORD_EXPIRED:
				code = FREERDP_ERROR_CONNECT_PASSWORD_EXPIRED;
				break;

			case STATUS_ACCOUNT_DISABLED:
				code = FREERDP_ERROR_CONNECT_ACCOUNT_DISABLED;
				break;

			case STATUS_LOGON_FAILURE:
				code = FREERDP_ERROR_CONNECT_LOGON_FAILURE;
				break;

			case STATUS_WRONG_PASSWORD:
				code = FREERDP_ERROR_CONNECT_WRONG_PASSWORD;
				break;

			case STATUS_ACCESS_DENIED:
				code = FREERDP_ERROR_CONNECT_ACCESS_DENIED;
				break;

			case STATUS_ACCOUNT_RESTRICTION:
				code = FREERDP_ERROR_CONNECT_ACCOUNT_RESTRICTION;
				break;

			case STATUS_ACCOUNT_LOCKED_OUT:
				code = FREERDP_ERROR_CONNECT_ACCOUNT_LOCKED_OUT;
				break;

			case STATUS_ACCOUNT_EXPIRED:
				code = FREERDP_ERROR_CONNECT_ACCOUNT_EXPIRED;
				break;

			case STATUS_LOGON_TYPE_NOT_GRANTED:
				code = FREERDP_ERROR_CONNECT_LOGON_TYPE_NOT_GRANTED;
				break;

			default:
				WLog_ERR(TAG, "SPNEGO failed with NTSTATUS: 0x%08"PRIX32"", nla->errorCode);
				code = FREERDP_ERROR_AUTHENTICATION_FAILED;
				break;
		}

		freerdp_set_last_error(nla->instance->context, code);
		return -1;
	}

	if (nla_client_recv(nla) < 1)
		return -1;

	return 1;
}

int nla_recv(rdpNla* nla)
{
	wStream* s;
	int status;
	s = Stream_New(NULL, 4096);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return -1;
	}

	status = transport_read_pdu(nla->transport, s);

	if (status < 0)
	{
		WLog_ERR(TAG, "nla_recv() error: %d", status);
		Stream_Free(s, TRUE);
		return -1;
	}

	if (nla_decode_ts_request(nla, s) < 1)
	{
		Stream_Free(s, TRUE);
		return -1;
	}

	Stream_Free(s, TRUE);
	return 1;
}

void nla_buffer_print(rdpNla* nla)
{
	if (nla->negoToken.cbBuffer > 0)
	{
		WLog_DBG(TAG, "NLA.negoToken (length = %"PRIu32"):", nla->negoToken.cbBuffer);
		winpr_HexDump(TAG, WLOG_DEBUG, nla->negoToken.pvBuffer, nla->negoToken.cbBuffer);
	}

	if (nla->pubKeyAuth.cbBuffer > 0)
	{
		WLog_DBG(TAG, "NLA.pubKeyAuth (length = %"PRIu32"):", nla->pubKeyAuth.cbBuffer);
		winpr_HexDump(TAG, WLOG_DEBUG, nla->pubKeyAuth.pvBuffer, nla->pubKeyAuth.cbBuffer);
	}

	if (nla->authInfo.cbBuffer > 0)
	{
		WLog_DBG(TAG, "NLA.authInfo (length = %"PRIu32"):", nla->authInfo.cbBuffer);
		winpr_HexDump(TAG, WLOG_DEBUG, nla->authInfo.pvBuffer, nla->authInfo.cbBuffer);
	}
	sspi_CheckSecBuffer( & nla->negoToken);
	sspi_CheckSecBuffer( & nla->pubKeyAuth);
	sspi_CheckSecBuffer( & nla->authInfo);
}

void nla_buffer_free(rdpNla* nla)
{
	sspi_SecBufferFree(&nla->negoToken);
	sspi_SecBufferFree(&nla->pubKeyAuth);
	sspi_SecBufferFree(&nla->authInfo);
}


static LPTSTR string_to_generic_windows_string(const char* string)
{
	if (string)
	{
#ifdef UNICODE
		LPTSTR windows_string = 0;
		ConvertToUnicode(CP_UTF8, 0, string, -1, &windows_string, 0);
		return windows_string;
#else
		return strdup(string);
#endif
	}
	else
	{
		return 0;
	}
}


LPTSTR nla_make_spn(const char* service_class, const char* host_name)
{
	if (!service_class)
	{
		return string_to_generic_windows_string(host_name);
	}
	else
	{
		DWORD status = 0;
		DWORD spn_size = 0;
		LPTSTR host_name_g = string_to_generic_windows_string(host_name);
		LPTSTR service_class_g = string_to_generic_windows_string(service_class);
		LPTSTR service_principal_name = 0;

		if (!host_name_g || !service_class_g)
		{
			goto done;
		}

		/* Contrarily to its name DsMakeSpn returns a size (includes the terminating TCHAR),
		   not a length (count of TCHAR in spn) in spn_size! */
		if ((status = DsMakeSpn(service_class_g, host_name_g, NULL, 0, NULL, &spn_size,
		                        NULL)) != ERROR_BUFFER_OVERFLOW)
		{
			goto done;
		}

		if ((service_principal_name = (LPTSTR) calloc(spn_size, sizeof(TCHAR))) == 0)
		{
			goto done;
		}

		if ((status = DsMakeSpn(service_class_g, host_name_g, 0, 0, 0, &spn_size,
		                        service_principal_name)) != ERROR_SUCCESS)
		{
			free(service_principal_name);
			service_principal_name = 0;
		}

	done:
		free(host_name_g);
		free(service_class_g);
		return service_principal_name;
	}
}


/**
 * Create new CredSSP state machine.
 * @param transport
 * @return new CredSSP state machine.
 */

rdpNla* nla_new(freerdp* instance, rdpTransport* transport, rdpSettings* settings)
{
	rdpNla* nla = (rdpNla*) calloc(1, sizeof(rdpNla));

	if (!nla)
		return NULL;

	nla->identity = calloc(1, sizeof(SEC_WINNT_AUTH_IDENTITY));

	if (!nla->identity)
	{
		free(nla);
		return NULL;
	}

	nla->instance = instance;
	nla->settings = settings;
	nla->server = settings->ServerMode;
	nla->transport = transport;
	nla->sendSeqNum = 0;
	nla->recvSeqNum = 0;
	nla->version = 3;

	if (settings->NtlmSamFile)
	{
		nla->SamFile = _strdup(settings->NtlmSamFile);

		if (!nla->SamFile)
		{
			free(nla->identity);
			free(nla);
			return NULL;
		}
	}

	ZeroMemory(&nla->negoToken, sizeof(SecBuffer));
	ZeroMemory(&nla->pubKeyAuth, sizeof(SecBuffer));
	ZeroMemory(&nla->authInfo, sizeof(SecBuffer));
	SecInvalidateHandle(&nla->context);

	if (nla->server)
	{
		LONG status;
		HKEY hKey;
		DWORD dwType;
		DWORD dwSize;
		status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, SERVER_KEY,
		                       0, KEY_READ | KEY_WOW64_64KEY, &hKey);

		if (status != ERROR_SUCCESS)
			return nla;

		status = RegQueryValueEx(hKey, _T("SspiModule"), NULL, &dwType, NULL, &dwSize);

		if (status != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return nla;
		}

		nla->SspiModule = (LPTSTR) malloc(dwSize + sizeof(TCHAR));

		if (!nla->SspiModule)
		{
			RegCloseKey(hKey);
			free(nla);
			return NULL;
		}

		status = RegQueryValueEx(hKey, _T("SspiModule"), NULL, &dwType,
		                         (BYTE*) nla->SspiModule, &dwSize);

		if (status == ERROR_SUCCESS)
			WLog_INFO(TAG, "Using SSPI Module: %s", nla->SspiModule);

		RegCloseKey(hKey);
	}

	return nla;
}

/**
 * Free CredSSP state machine.
 * @param credssp
 */

void nla_free(rdpNla* nla)
{
	if (!nla)
		return;

	nla_identity_free(nla->identity);

	if (nla->table)
	{
		SECURITY_STATUS status;

		if (SecIsValidHandle(&nla->credentials))
		{
			status = nla->table->FreeCredentialsHandle(&nla->credentials);

			if (status != SEC_E_OK)
			{
				WLog_WARN(TAG, "FreeCredentialsHandle status %s [0x%08"PRIX32"]",
				          GetSecurityStatusString(status), status);
			}

			SecInvalidateHandle(&nla->credentials);
		}

		status = nla->table->DeleteSecurityContext(&nla->context);

		if (status != SEC_E_OK)
		{
			WLog_WARN(TAG, "DeleteSecurityContext status %s [0x%08"PRIX32"]",
			          GetSecurityStatusString(status), status);
		}
	}

	free(nla->SamFile);
	nla->SamFile = NULL;
	sspi_SecBufferFree(&nla->PublicKey);
	sspi_SecBufferFree(&nla->tsCredentials);
	free(nla->ServicePrincipalName);
	free(nla);
}
