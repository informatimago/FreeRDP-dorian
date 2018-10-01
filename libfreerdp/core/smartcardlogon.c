/**
* FreeRDP: A Remote Desktop Protocol Implementation
* FreeRDP Smartcard logon
*
* Copyright 2017 Dorian Ducournau <dorian.ducournau@gmail.com>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
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

#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>

#include <winpr/sspi.h>

#include <freerdp/client.h>
#include <freerdp/error.h>
#include <freerdp/log.h>

#include "smartcardlogon.h"
#include "smartcardlogon_private.h"

#define TAG FREERDP_TAG("core.smartcardlogon")

/*
C_UnloadModule
Unload the library and free the pkcs11_module
*/
static CK_RV C_UnloadModule(pkcs11_module* module)
{
	if (!module || module->magic != PKCS11_MODULE_MAGIC)
	{
		return CKR_ARGUMENTS_BAD;
	}

	if (module->library != NULL && dlclose(module->library) < 0)
	{
		return CKR_FUNCTION_FAILED;
	}

	memset(module, 0, sizeof(*module));
	free(module);
	return CKR_OK;
}

/*
C_LoadModule
Allocate the pkcs11_module and load the library.
*/
static pkcs11_module* C_LoadModule(const char* mspec)
{
	pkcs11_module* module;
	CK_RV rv, (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);

	if (mspec == NULL)
	{
		goto failed;
	}

	module = calloc(1, sizeof(*module));

	module->magic = PKCS11_MODULE_MAGIC;

	module->library = dlopen(mspec, RTLD_LAZY);

	if (module->library == NULL)
	{
		WLog_ERR(TAG, "dlopen failed: %s\n", dlerror());
		free(module);
		goto failed;
	}

	/* Get the list of function pointers */
	c_get_function_list = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(module->library,
	                      "C_GetFunctionList");

	if (!c_get_function_list)
	{
		goto unload_and_failed;
	}

	rv = c_get_function_list(& module->p11);

	if (rv == CKR_OK)
	{
		WLog_DBG(TAG, "Load %s module with success !", mspec ? mspec : "NULL");
		return (void*) module;
	}

	WLog_ERR(TAG, "C_GetFunctionList failed %lx", rv);
unload_and_failed:
	C_UnloadModule(module);
failed:
	WLog_ERR(TAG, "Failed to load PKCS#11 module %s", mspec ? mspec : "NULL");
	return NULL;
}

#define DEFINE_ATTR_METHOD(ATTR, TYPE)								\
	static TYPE										\
	get##ATTR(pkcs11_module* module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj)	\
	{											\
		TYPE		type = 0;							\
		CK_ATTRIBUTE	attr = { CKA_##ATTR, &type, sizeof(type) };			\
		CK_RV		rv;								\
		\
		rv = module->p11->C_GetAttributeValue(session, obj, &attr, 1);			\
		if (rv != CKR_OK)								\
			WLog_DBG(TAG, "C_GetAttributeValue(" #ATTR ")", rv);			\
		return type;									\
	}

#define DEFINE_VARATTR_METHOD(ATTR, TYPE)										\
	static TYPE *													\
	get##ATTR(pkcs11_module* module, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount)	\
	{														\
		CK_ATTRIBUTE	attr = { CKA_##ATTR, NULL, 0 };								\
		CK_RV		rv;											\
		\
		rv = module->p11->C_GetAttributeValue(session, obj, &attr, 1);						\
		if (rv == CKR_OK) {											\
			if (!(attr.pValue = calloc(1, attr.ulValueLen + 1)))						\
				WLog_ERR(TAG, "out of memory in get" #ATTR ": %m");					\
			rv = module->p11->C_GetAttributeValue(session, obj, &attr, 1);					\
			if (pulCount)											\
				*pulCount = attr.ulValueLen / sizeof(TYPE);						\
		} else {												\
			WLog_DBG(TAG, "C_GetAttributeValue(" #ATTR ")", rv);						\
		}													\
		return (TYPE *) attr.pValue;										\
	}

DEFINE_VARATTR_METHOD(LABEL, char);
DEFINE_VARATTR_METHOD(ID, unsigned char);

static const char* p11_utf8_to_local(CK_UTF8CHAR* string, size_t len)
{
	static char	buffer[512];
	size_t		n, m;

	while (len && string[len - 1] == ' ')
		len--;

	/* For now, simply copy this thing */
	for (n = m = 0; n < sizeof(buffer) - 1; n++)
	{
		if (m >= len)
			break;

		buffer[n] = string[m++];
	}

	buffer[n] = '\0';
	return buffer;
}

static int find_object(pkcs11_module* module,
                       CK_SESSION_HANDLE session,
                       CK_OBJECT_CLASS cls,
                       CK_OBJECT_HANDLE_PTR ret,
                       const unsigned char* id, size_t id_len, int obj_index)
{
	CK_ATTRIBUTE attrs[2];
	unsigned int nattrs = 0;
	CK_ULONG count;
	CK_RV rv;
	int i;
	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &cls;
	attrs[0].ulValueLen = sizeof(cls);
	nattrs++;

	if (id)
	{
		attrs[nattrs].type = CKA_ID;
		attrs[nattrs].pValue = (void*) id;
		attrs[nattrs].ulValueLen = id_len;
		nattrs++;
	}

	rv = module->p11->C_FindObjectsInit(session, attrs, nattrs);

	if (rv != CKR_OK)
		WLog_ERR(TAG, "Error C_FindObjectsInit %lu\n", rv);

	for (i = 0; i < obj_index; i++)
	{
		rv = module->p11->C_FindObjects(session, ret, 1, &count);

		if (rv != CKR_OK)
			WLog_ERR(TAG, "Error C_FindObjects %lu\n", rv);

		if (count == 0)
			goto done;
	}

	rv = module->p11->C_FindObjects(session, ret, 1, &count);

	if (rv != CKR_OK)
		WLog_ERR(TAG, "Error C_FindObjects %lu\n", rv);

done:

	if (count == 0)
		*ret = CK_INVALID_HANDLE;

	module->p11->C_FindObjectsFinal(session);
	return count;
}

static pkcs11_module* cryptoki_load_and_initialize(const char* module_name)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	pkcs11_module* module = C_LoadModule(module_name);

	if (module == NULL)
	{
		return NULL;
	}

	rv = module->p11->C_Initialize(NULL);

	if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
	{
		WLog_ERR(TAG, "Cryptoki library (%s) has already been initialized", module_name);
		/* We still return the initialized module,  and go on. */
	}
	else if (rv != CKR_OK)
	{
		WLog_ERR(TAG, "Cryptoki library (%s) could not be initialized; C_Initialize returned %lu",
		         module_name, rv);
		C_UnloadModule(module);
		return NULL;
	}

	return module;
}

static void cryptoki_finalize_and_unload(pkcs11_module* module)
{
	module->p11->C_Finalize(NULL);
	C_UnloadModule(module);
}

static CK_SLOT_ID_PTR cryptoki_get_slot_list(pkcs11_module* module, CK_ULONG* slots_count)
{
	CK_SLOT_ID_PTR slot_ids = NULL;
	CK_RV rv = module->p11->C_GetSlotList(TRUE, NULL, slots_count); /* get the slot count */

	if (rv != CKR_OK)
	{
		WLog_ERR(TAG, "Error C_GetSlotList(NULL), %lu", rv);
		goto fail;
	}

	slot_ids = calloc(*slots_count, sizeof(* slot_ids));

	if (slot_ids == NULL)
	{
		WLog_ERR(TAG, "%s:%d: calloc failed", __FUNCTION__, __LINE__);
		goto fail;
	}

	rv = module->p11->C_GetSlotList(TRUE, slot_ids, slots_count);

	if (rv != CKR_OK)
	{
		WLog_ERR(TAG, "Error C_GetSlotList() %lu", rv);
		goto fail;
	}

	if (* slots_count == 0)
	{
		WLog_ERR(TAG, "No slots.");
		goto fail;
	}

	return slot_ids;
fail:
	(*slots_count) = 0;
	free(slot_ids);
	return NULL;
}

/* This is strnstr, but it exists only on BSD, not on MS-Windows */
static const char* search(const char* string, size_t max_string, const char* substring)
{
	size_t length = strlen(substring);
	size_t max_start = strnlen(string, max_string) - length;
	size_t i;
	const char* current = string;

	for (i = 0; i <= max_start; i ++, current ++)
	{
		if (strncmp(current, substring, length) == 0)
		{
			return current;
		}
	}

	return NULL;
}

static char* token_info_label(const CK_TOKEN_INFO*   tinfo)
{
	const size_t label_max_size = sizeof(tinfo->label) + 1;
	size_t label_length = 0;
	char* label = calloc(1, label_max_size);
	const char* end;

	if (label == NULL)
	{
		WLog_ERR(TAG, "Error allocation Token Label");
		return NULL;
	}

	/* two consecutive spaces mean the end of token label */
	end = search((const char*)tinfo->label, sizeof(tinfo->label), "  ");
	label_length = end
	               ? (end - (const char*)tinfo->label)
	               : strnlen((const char*)tinfo->label, sizeof(tinfo->label));
	strncpy(label, (const char*)tinfo->label, label_length);
	label[label_length] = '\0';
	WLog_DBG(TAG, "Token Label: %s", label);
	return label;
}

static CK_SLOT_ID find_usable_slot(rdpSettings* settings, pkcs11_module* module,
                                   char** token_label)
{
	CK_ULONG i;
	CK_ULONG slots_count = 0;
	CK_SLOT_ID_PTR slots = cryptoki_get_slot_list(module, &slots_count);

	for (i = 0; i < slots_count; i++)
	{
		CK_RV rv = CKR_GENERAL_ERROR;
		{
			CK_SLOT_INFO sinfo;
			WLog_DBG(TAG, "slot[%lu] = ID 0x%lx", i, slots[i]);
			rv = module->p11->C_GetSlotInfo(slots[i], &sinfo);

			if (rv != CKR_OK)
			{
				WLog_ERR(TAG, "slot[%lu] = ID 0x%lx; C_GetSlotInfo failed rv = %d", i, slots[i], rv);
				continue;
			}

			if (!(sinfo.flags & CKF_TOKEN_PRESENT))
			{
				WLog_ERR(TAG, "slot[%lu] = ID 0x%lx; token is not present", i, slots[i]);
				continue;
			}

			WLog_DBG(TAG, "slot[%lu] = ID 0x%lx; description: %s", i, slots[i],
			         p11_utf8_to_local(sinfo.slotDescription, sizeof(sinfo.slotDescription)));
		}
		{
			CK_TOKEN_INFO tinfo;
			memset(&tinfo, 0, sizeof(CK_TOKEN_INFO));
			rv = module->p11->C_GetTokenInfo(slots[i], &tinfo);

			if (rv != CKR_OK)
			{
				WLog_ERR(TAG, "slot[%lu] = ID 0x%lx; C_GetTokenInfo failed rv = %d", i, slots[i], rv);
				continue;
			}

			(*token_label) = token_info_label(&tinfo);

			if (!(*token_label))
			{
				return -1;
			}

			settings->PinPadIsPresent = ((tinfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0);
			settings->PinLoginRequired = ((tinfo.flags & CKF_LOGIN_REQUIRED) != 0);
			break;
		}
	}

	return (i < slots_count)
	       ? slots[i]
	       : CK_UNAVAILABLE_INFORMATION;
}

static CK_SESSION_HANDLE cryptoki_open_session(pkcs11_module* module, CK_SLOT_ID slot_id,
        CK_FLAGS flags, void* application, CK_NOTIFY notify)
{
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_RV rv = module->p11->C_OpenSession(slot_id, flags, application, notify,  &session);

	if (rv != CKR_OK)
	{
		WLog_ERR(TAG, "C_OpenSession() failed: 0x%08lX", rv);
		return CK_INVALID_HANDLE;
	}

	return session;
}

static CK_SESSION_HANDLE cryptoki_close_session(pkcs11_module* module, CK_SESSION_HANDLE session,
        CK_SLOT_ID slot_id)
{
	if (session != CK_INVALID_HANDLE)
	{
		CK_RV rv = module->p11->C_CloseSession(session);

		if ((rv != CKR_OK) && (rv != CKR_FUNCTION_NOT_SUPPORTED))
		{
			WLog_ERR(TAG, "C_CloseSession() failed: 0x%08lX", rv);

			if (slot_id != CK_UNAVAILABLE_INFORMATION)
			{
				rv = module->p11->C_CloseAllSessions(slot_id);

				if ((rv != CKR_OK) && (rv != CKR_FUNCTION_NOT_SUPPORTED))
				{
					WLog_ERR(TAG, "C_CloseAllSessions() failed: 0x%08lX", rv);
				}
			}
		}
	}

	return CK_INVALID_HANDLE;
}

static int unsigned_long_length_10(unsigned long value)
{
	if (value == 0)
	{
		return 1;
	}

	int length = 0;

	while (value > 0)
	{
		value /= 10;
		length ++;
	}

	return length;
}

static char* unsigned_long_to_string(unsigned long value)
{
	char*   buffer = malloc(1 + unsigned_long_length_10(value));

	if (buffer)
	{
		sprintf(buffer, "%lu", value);
	}

	return buffer;
}


/* perform PKCS#11 C_Login */
static CK_RV cryptoki_login(pkcs11_module* module, CK_SESSION_HANDLE session, char* pin)
{
	CK_RV rv;
	WLog_DBG(TAG, "login as user CKU_USER");

	if (pin)
	{
		WLog_DBG(TAG, "C_Login with PIN");
		rv = module->p11->C_Login(session, CKU_USER, (unsigned char*)pin, strlen(pin));
	}
	else
	{
		WLog_DBG(TAG, "C_Login without PIN");
		rv = module->p11->C_Login(session, CKU_USER, NULL, 0);
	}

	if ((rv != CKR_OK) && (rv != CKR_USER_ALREADY_LOGGED_IN))
	{
		WLog_ERR(TAG, "C_Login() failed: 0x%08lX", rv);
		return rv;
	}

	return CKR_OK;
}

/** pkcs11_do_login is used to do login by asking PIN code.
*  Function called only if pinpad is NOT used.
*  This function is actually called in init_authentication_pin()
*  @param session - valid PKCS#11 session handle
*  @param slod_id - slot id of present token
*  @param settings - pointer to rdpSettings structure that contains settings
*  @return CKR_OK if PKCS#11 login succeed.
*/
static CK_RV pkcs11_do_login(rdpSettings* settings, pkcs11_module* module,
                             CK_SESSION_HANDLE session, CK_SLOT_ID slot_id)
{
	CK_RV ret = 0, ret_token = 0;
	unsigned int try_left = NB_TRY_MAX_LOGIN_TOKEN;
	char* pin;
	BOOL retypePin = FALSE;
	ssize_t size_prompt_message = strlen(settings->TokenLabel) + strlen(" PIN :");
	char* prompt_message = calloc(size_prompt_message + 1, sizeof(char));

	if (prompt_message == NULL) return -1;

	strncpy(prompt_message, settings->TokenLabel, strlen(settings->TokenLabel));
	strncat(prompt_message, " PIN:", strlen(" PIN:"));
	prompt_message[size_prompt_message] = '\0';

	while (try_left > 0)
	{
		/* get PIN if not already given in command line argument */
		if (strncmp(settings->Pin, "NULL", 4) == 0)
		{
			pin = getpass(prompt_message);
			retypePin = FALSE;
		}
		else if (try_left == NB_TRY_MAX_LOGIN_TOKEN && !retypePin)
		{
			pin = calloc(PIN_LENGTH + 1, sizeof(char));

			if (!pin)
				return -1;
			else
			{
				strncpy(pin, settings->Pin, PIN_LENGTH);
				pin[PIN_LENGTH] = '\0';
			}
		}
		else
		{
			/* Login fail using PIN from getpass() or bad formatted PIN code
			* given in command line argument.
			* Reset PIN to "NULL" to get it again from getpass */
			strncpy(settings->Pin, "NULL", PIN_LENGTH + 1);
			continue;
		}

		if (NULL == pin || strlen(pin) > 4)
		{
			WLog_ERR(TAG, "Error encountered while reading PIN");
			continue;
		}

		/* check pin length */
		if (strlen(pin) == 0)
		{
			WLog_ERR(TAG, "Empty PIN are not allowed");
			continue;
		}

		/* check if pin characters are [0-9] to avoid keyboard num lock errors */
		int i;

		for (i = 0; i < strlen(pin); i++)
		{
			if (!isdigit(pin[i]))
			{
				retypePin = TRUE;
				break;
			}
		}

		if (retypePin)
		{
			WLog_ERR(TAG, "Bad format - Please retype PIN (4-digits)");
			continue;
		}

		CK_TOKEN_INFO tinfo;
		ret_token = module->p11->C_GetTokenInfo(slot_id, &tinfo);

		if (ret_token != CKR_OK)
		{
			WLog_ERR(TAG, "C_GetTokenInfo() failed: 0x%08lX", ret_token);
			return -1;
		}

		/* store token flags before login try */
		CK_FLAGS flags_before_login = tinfo.flags;

		/* check (if these token flags are set) how many PIN tries left before first login try */
		if ((flags_before_login & CKF_USER_PIN_COUNT_LOW) == CKF_USER_PIN_COUNT_LOW)
		{
			WLog_ERR(TAG,
			         "An incorrect user login PIN has been entered at least once since the last successful authentication /!\\ ");
		}

		if ((flags_before_login & CKF_USER_PIN_FINAL_TRY) == CKF_USER_PIN_FINAL_TRY)
		{
			WLog_ERR(TAG, "/!\\ Supplying an incorrect user PIN will cause it to become locked /!\\ ");
		}

		if ((flags_before_login & CKF_USER_PIN_LOCKED) == CKF_USER_PIN_LOCKED)
		{
			WLog_ERR(TAG,
			         "/!\\ /!\\ The user PIN has been locked. User login to the token is not possible /!\\ /!\\ ");
			return -1;
		}

		ret = cryptoki_login(module, session, pin); /* perform PKCS#11 login */
		ret_token = module->p11->C_GetTokenInfo(slot_id, &tinfo);

		if (ret_token != CKR_OK)
		{
			WLog_ERR(TAG, "C_GetTokenInfo() failed: 0x%08lX", ret_token);
			return -1;
		}

		CK_FLAGS flags_after_login = tinfo.flags;
		WLog_DBG(TAG, "flags after login : %d", flags_after_login);

		/* Some middlewares do not set standard token flags if PIN entry was wrong.
		* That's why we use here the C_Login return to check if the PIN was correct or not
		* rather than the token flags. In the case where flags are not set properly,
		* the C_Login return is the only (non middleware specific) way to check how many PIN try left us.
		* However, Kerberos PKINIT uses standard token flags to set responder callback questions.
		* Thus, for both middlewares (setting token flags or not) we store the state of token flags
		* to use it later in PKINIT.
		*/

		if (flags_before_login == flags_after_login)
		{
			if (ret == CKR_OK && try_left == NB_TRY_MAX_LOGIN_TOKEN)
				settings->TokenFlags |= FLAGS_TOKEN_USER_PIN_OK; /* means no error while logging to the token */

			if ((flags_after_login & CKF_USER_PIN_INITIALIZED) == CKF_USER_PIN_INITIALIZED)
				WLog_DBG(TAG, "CKF_USER_PIN_INITIALIZED set");

			if ((flags_after_login & CKF_LOGIN_REQUIRED) == CKF_LOGIN_REQUIRED)
				WLog_DBG(TAG, "CKF_LOGIN_REQUIRED set");

			if ((flags_after_login & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED)
				WLog_DBG(TAG, "CKF_TOKEN_INITIALIZED set");

			if ((flags_after_login & CKF_PROTECTED_AUTHENTICATION_PATH) == CKF_PROTECTED_AUTHENTICATION_PATH)
				WLog_DBG(TAG, "CKF_PROTECTED_AUTHENTICATION_PATH set");
		}
		else
		{
			/* We set the flags CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY and CKF_USER_PIN_LOCKED
			* only when the middleware set them itself.
			*/
			if ((flags_after_login & CKF_USER_PIN_COUNT_LOW) == CKF_USER_PIN_COUNT_LOW)
			{
				settings->TokenFlags |= FLAGS_TOKEN_USER_PIN_COUNT_LOW;
				WLog_ERR(TAG, "/!\\    WARNING    /!\\ 	  PIN INCORRECT (x1)	 /!\\	2 tries left  /!\\");
				try_left--;
				continue;
			}

			if ((flags_after_login & CKF_USER_PIN_FINAL_TRY) == CKF_USER_PIN_FINAL_TRY)
			{
				settings->TokenFlags |= FLAGS_TOKEN_USER_PIN_FINAL_TRY;
				WLog_ERR(TAG, "/!\\ 	DANGER   /!\\   PIN INCORRECT (x2)   /!\\	  Only 1 try left   /!\\");
				try_left--;
				continue;
			}

			if ((flags_after_login & CKF_USER_PIN_LOCKED) == CKF_USER_PIN_LOCKED)
			{
				settings->TokenFlags |= FLAGS_TOKEN_USER_PIN_LOCKED;
				WLog_ERR(TAG,
				         "/!\\ **** CRITICAL ERROR **** /!\\ **** PIN LOCKED **** /!\\ **** END OF PROGRAM **** /!\\");
				goto error_pin_entry;
			}
		}

		/* store PIN code in settings if C_Login() succeeded */
		if (ret == CKR_OK)
		{
			strncpy(settings->Pin, pin, PIN_LENGTH + 1);
			break;
		}
		else
		{
			try_left--; /* 3 C_Login() tries at maximum */

			if (ret & CKR_PIN_INCORRECT)
			{
				if (try_left == 2)
				{
					if (!(settings->TokenFlags & FLAGS_TOKEN_USER_PIN_COUNT_LOW))
					{
						/* It means that middleware does not set CKF_USER_PIN_COUNT_LOW token flag.
						*  If so, that would have already been done previously with the corresponding token flag.
						*  Thus, we set the token flag to FLAGS_TOKEN_USER_PIN_NOT_IMPLEMENTED.
						*/
						settings->TokenFlags |= FLAGS_TOKEN_USER_PIN_NOT_IMPLEMENTED;
					}

					WLog_ERR(TAG, "/!\\    WARNING    /!\\ 	  PIN INCORRECT (x1)	 /!\\	2 tries left  /!\\");
					continue;
				}

				if (try_left == 1)
				{
					if (((settings->TokenFlags & FLAGS_TOKEN_USER_PIN_FINAL_TRY) == FLAGS_TOKEN_USER_PIN_FINAL_TRY) ==
					    0)
					{
						/* means that middleware does not set CKF_USER_PIN_FINAL_TRY token flag */
						settings->TokenFlags |= FLAGS_TOKEN_USER_PIN_NOT_IMPLEMENTED;
					}

					WLog_ERR(TAG, "/!\\ 	DANGER   /!\\   PIN INCORRECT (x2)   /!\\	  Only 1 try left   /!\\");
					continue;
				}
			}

			if (ret & CKR_PIN_LOCKED)
			{
				if (((settings->TokenFlags & FLAGS_TOKEN_USER_PIN_LOCKED) == FLAGS_TOKEN_USER_PIN_LOCKED) == 0)
				{
					/* means that middleware does not set CKF_USER_PIN_LOCKED token flag */
					settings->TokenFlags |= FLAGS_TOKEN_USER_PIN_NOT_IMPLEMENTED;
				}

				WLog_ERR(TAG,
				         "/!\\ **** CRITICAL ERROR **** /!\\ **** PIN LOCKED **** /!\\ **** END OF PROGRAM **** /!\\");
				goto error_pin_entry;
			}
		}
	}

	WLog_DBG(TAG, "%s %d : tokenFlags=%"PRId32"", __FUNCTION__, __LINE__, settings->TokenFlags);
error_pin_entry:
	free(prompt_message);

	if (pin)
	{
		if (memset_s(pin, PIN_LENGTH, 0, PIN_LENGTH))
			memset(pin, 0, PIN_LENGTH);

		free(pin);
	}

	return ret;
}

static BOOL login(rdpSettings* settings, pkcs11_module* module, CK_SESSION_HANDLE session,
                  CK_SLOT_ID slot_id)
{
	CK_RV rv;

	/* Login token */
	/* call PKCS#11 login to ensure that the user is the real owner of the card,
	* but also because some tokens cannot read protected data until the PIN Global is unlocked */
	if ((settings->PinPadIsPresent && !settings->PinLoginRequired))
	{
		rv = module->p11->C_Login(session, CKU_USER, NULL_PTR,  0);
	}
	else if (!settings->PinPadIsPresent)
	{
		rv = pkcs11_do_login(settings, module,  session, slot_id);
	}
	else
	{
#ifndef HANDLE_PINPAD_WITH_LOGIN_REQUIRED
		/* Using a pinpad with the slot's setting 'login required' is not handled by default,
		* because it would require users to type two times their PIN code in a few seconds.
		* First, to unlock the token to be able to read protected data. And then, later in PKINIT,
		* to get Kerberos ticket (TGT) to authenticate against KDC.
		* Nevertheless, if you want to handle this case uncomment #define HANDLE_PINPAD_WITH_LOGIN_REQUIRED
		* in pkinit/pkinit.h */
		WLog_ERR(TAG, "Error configuration slot token");
		return FALSE;
#else
		rv = module->p11->C_Login(session, CKU_USER, NULL_PTR,  0);
#endif
	}

	if ((rv != CKR_OK) && (rv != CKR_USER_ALREADY_LOGGED_IN))
	{
		WLog_ERR(TAG, "C_Login() failed: 0x%08lX", rv);
		return FALSE;
	}

	WLog_DBG(TAG, "-------------- Login token OK --------------");
	return TRUE;
}

static void certificates_free(cert_object** certificates, int certificates_count)
{
	int i;

	for (i = 0; i < certificates_count; i++)
	{
		if (!certificates[i])
		{
			continue;
		}

		if (certificates[i]->x509 != NULL)
		{
			X509_free(certificates[i]->x509);
		}

		if (certificates[i]->id_cert != NULL)
		{
			free(certificates[i]->id_cert);
		}

		free(certificates[i]);
	}

	free(certificates);
}

static char* bytes_to_hexadecimal(CK_BYTE *  bytes, unsigned long count)
{
	char*   buffer = malloc(2 * count + 1);
	char *  current = buffer;

	if (!buffer)
	{
		WLog_ERR(TAG, "%s:%d: malloc() cannot allocate %lu bytes",
			__FUNCTION__, __LINE__, 2 *count + 1);
		return buffer;
	}

	while (count > 0)
	{
		sprintf(current, "%02x", * bytes);
		bytes ++ ;
		current += 2;
		count -- ;
	}
	* current = '\0';

	return buffer;
}

/** certificates_list find all certificates present on smartcard.
*  This function is actually called in get_valid_smartcard_cert().
*  @param context - pointer to the pkcs11_context structure that contains the variables
*  to manage PKCS#11 session
*  @param ncerts - number of certificates of the smartcard
*  @return list of certificates found
*/
static cert_object** certificates_list(pkcs11_context* context, int* ncerts)
{
	CK_BYTE* id_value = NULL;
	CK_BYTE* cert_value = NULL;
	CK_OBJECT_HANDLE object;
	CK_ULONG object_count;
	X509* x509 = NULL;
	int rv;
	CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
	CK_ATTRIBUTE cert_template[] =
	{
		{CKA_CLASS, &cert_class, sizeof(CK_OBJECT_CLASS)},
		{CKA_CERTIFICATE_TYPE, &cert_type, sizeof(CK_CERTIFICATE_TYPE)},
		{CKA_ID, NULL, 0},
		{CKA_VALUE, NULL, 0}
	};
	cert_object** certificates = NULL;
	int certificates_count = 0;

	if (context->certificates)
	{
		(*ncerts) = context->certificates_count;
		return context->certificates;
	}

	rv = context->module->p11->C_FindObjectsInit(context->session, cert_template, 2);

	if (rv != CKR_OK)
	{
		WLog_ERR(TAG, "C_FindObjectsInit() failed: 0x%08lX", rv);
		goto failure;
	}

	while (1)
	{
		/* look for certificates */
		rv = context->module->p11->C_FindObjects(context->session, &object, 1, &object_count);

		if (rv != CKR_OK)
		{
			WLog_ERR(TAG, "C_FindObjects() failed: 0x%08lX", rv);
			goto failure;
		}

		if (object_count == 0)
		{
			break; /* no more certs */
		}

		/* Pass 1: get cert id */
		/* retrieve cert object id length */
		cert_template[2].pValue = NULL;
		cert_template[2].ulValueLen = 0;
		rv = context->module->p11->C_GetAttributeValue(context->session, object, cert_template, 3);

		if (rv != CKR_OK)
		{
			WLog_ERR(TAG, "CertID length: C_GetAttributeValue() failed: 0x%08lX", rv);
			goto failure;
		}

		/* allocate enought space */
		id_value = malloc(cert_template[2].ulValueLen);

		if (id_value == NULL)
		{
			WLog_ERR(TAG, "Cert id malloc(%"PRIu32"): not enough free memory available",
			         cert_template[2].ulValueLen);
			goto failure;
		}

		/* read cert id into allocated space */
		cert_template[2].pValue = id_value;
		rv = context->module->p11->C_GetAttributeValue(context->session, object, cert_template, 3);

		if (rv != CKR_OK)
		{
			WLog_ERR(TAG, "CertID value: C_GetAttributeValue() failed: 0x%08lX", rv);
			goto failure;
		}

		/* Pass 2: get certificate */
		/* retrieve cert length */
		cert_template[3].pValue = NULL;
		rv = context->module->p11->C_GetAttributeValue(context->session, object, cert_template, 4);

		if (rv != CKR_OK)
		{
			WLog_ERR(TAG, "Cert Length: C_GetAttributeValue() failed: 0x%08lX", rv);
			goto failure;
		}

		/* allocate enough space */
		cert_value = malloc(cert_template[3].ulValueLen);

		if (cert_value == NULL)
		{
			WLog_ERR(TAG, "Cert value malloc(%"PRIu32"): not enough free memory available",
			         cert_template[3].ulValueLen);
			goto failure;
		}

		/* read certificate into allocated space */
		cert_template[3].pValue = cert_value;
		rv = context->module->p11->C_GetAttributeValue(context->session, object, cert_template, 4);

		if (rv != CKR_OK)
		{
			WLog_ERR(TAG, "Cert Value: C_GetAttributeValue() failed: 0x%08lX", rv);
			goto failure;
		}

		/* Pass 3: store certificate */
		/* convert to X509 data structure */
		x509 = d2i_X509(NULL, (const unsigned char**)&cert_template[3].pValue, cert_template[3].ulValueLen);

		if (x509 == NULL)
		{
			WLog_ERR(TAG, "d2i_x509() failed: %s", ERR_error_string(ERR_get_error(), NULL));
			goto failure;
		}

		/* finally add certificate to chain */
		certificates = realloc(certificates, (certificates_count + 1) * sizeof(cert_object*));

		if (!certificates)
		{
			WLog_ERR(TAG, "realloc() not space to re-size cert table");
			goto failure;
		}

		WLog_DBG(TAG, "Saving Certificate #%d", certificates_count + 1);
		certificates[certificates_count] = NULL;
		certificates[certificates_count] = (cert_object*) calloc(1, sizeof(cert_object));

		if (certificates[certificates_count] == NULL)
		{
			WLog_ERR(TAG, "calloc() not space to allocate cert object");
			goto failure;
		}

		certificates[certificates_count]->type = cert_type;
		certificates[certificates_count]->x509 = x509;
		certificates[certificates_count]->private_key = CK_INVALID_HANDLE;
		certificates[certificates_count]->key_type = 0;
		certificates[certificates_count]->id_cert = bytes_to_hexadecimal(cert_template[2].pValue, cert_template[2].ulValueLen);

		if (certificates[certificates_count]->id_cert == NULL)
		{
			goto failure;
		}


		/* Certificate found and save, increment the count */
		++certificates_count;
		free(id_value);
		free(cert_value);
	}

	/* release FindObject Session */
	rv = context->module->p11->C_FindObjectsFinal(context->session);

	if (rv != CKR_OK)
	{
		WLog_ERR(TAG, "C_FindObjectsFinal() failed: 0x%08lX", rv);
		goto fail_free;
	}

	/* arriving here means that's all right */
	WLog_DBG(TAG, "Found %d certificate(s) in token", certificates_count);
	(*ncerts) = certificates_count;
	return certificates;
failure:
	rv = context->module->p11->C_FindObjectsFinal(context->session);

	if (rv != CKR_OK)
	{
		WLog_ERR(TAG, "C_FindObjectsFinal() failed: 0x%08lX", rv);
	}

fail_free:
	free(id_value);
	id_value = NULL;
	free(cert_value);
	cert_value = NULL;
	certificates_free(certificates, certificates_count);
	(*ncerts) = 0;
	return NULL;
}

static pkcs11_context* pkcs11_context_new(pkcs11_module* module, CK_SESSION_HANDLE session,
        CK_SLOT_ID slot_id, CK_OBJECT_HANDLE private_key)
{
	pkcs11_context* context = calloc(1, sizeof(*context));

	if (!context)
	{
		WLog_ERR(TAG, "%s:%d: cannot allocate a pkcs11_context", __FUNCTION__, __LINE__);
		return NULL;
	}

	context->module = module;
	context->session = session;
	context->slot_id = slot_id;
	context->private_key = private_key;
	return context;
}

static void pkcs11_context_free(pkcs11_context* context)
{
	context->session = cryptoki_close_session(context->module, context->session, context->slot_id);

	if (context->module)
	{
		C_UnloadModule(context->module);
		context->module = NULL;
	}

	certificates_free(context->certificates, context->certificates_count);
	memset(context, 0, sizeof(*context));
	free(context);
}

static CK_OBJECT_HANDLE find_signature_private_key(pkcs11_module* module, CK_SESSION_HANDLE session,
        char** certificate_id)
{
	CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;
	CK_ULONG j;
	CK_BYTE* certificate_id_bytes = NULL;
	CK_ULONG certificate_id_length;
	char* label = NULL;
	char* certificate_id_string;

	for (j = 0; find_object(module, session, CKO_PRIVATE_KEY, &private_key, NULL, 0, j); j++)
	{
		if ((label = getLABEL(module, session, private_key, NULL)) != NULL)
		{
			WLog_DBG(TAG, "label = (%s)", label);
		}

		certificate_id_bytes = getID(module, session, private_key, &certificate_id_length);

		if (certificate_id_bytes == NULL)
		{
			WLog_ERR(TAG, "private key has no ID : can't find corresponding certificate without it");
			continue;
		}

		certificate_id_string = bytes_to_hexadecimal(certificate_id_bytes, certificate_id_length);
		free(certificate_id_bytes);
		free(label);

		if (!certificate_id_string)
		{
			WLog_ERR(TAG, "Error allocating memory for IdCertificate");
			return CK_INVALID_HANDLE;
		}

		break;
	}

	if (private_key == CK_INVALID_HANDLE)
	{
		WLog_ERR(TAG, "Signature: no private key found in this slot");
	}

	(*certificate_id) = certificate_id_string;
	return private_key;
}

/** init_authentication_pin is used to login to the token
* 	and to get PKCS#11 session informations, then use
* 	to retrieve valid certificate and UPN.
*  This function is actually called in get_valid_smartcard_cert()
*  @return CKR_OK if all PKCS#11 functions succeed.
*/
static CK_RV init_authentication_pin(freerdp* instance, pkcs11_context** context)
{
	CK_SLOT_ID        slot_id        = 0;
	CK_SESSION_HANDLE session        = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE  private_key    = CK_INVALID_HANDLE;
	CK_FLAGS          flags          = CKF_SERIAL_SESSION;
	pkcs11_module*    module         = cryptoki_load_and_initialize(instance->settings->Pkcs11Module);
	char*             certificate_id = NULL;
	(*context) = NULL;

	if (!module)
	{
		return CKR_GENERAL_ERROR;
	}

	slot_id = find_usable_slot(instance->settings, module, &instance->settings->TokenLabel);

	if (slot_id == CK_UNAVAILABLE_INFORMATION)
	{
		return CKR_GENERAL_ERROR;
	}

	instance->settings->SlotID = unsigned_long_to_string(slot_id);

	if (instance->settings->SlotID == NULL)
	{
		goto finalize_and_unload;
	}

	if (instance->settings->Pin == NULL)
	{
		/* set PIN settings to string "NULL" for further credentials delegation */
		instance->settings->Pin = strdup("NULL");

		if (instance->settings->Pin == NULL)
		{
			WLog_ERR(TAG, "Error allocating memory for PIN");
			goto finalize_and_unload;
		}
	}

	session = cryptoki_open_session(module, slot_id, flags, NULL, NULL);

	if (session == CK_INVALID_HANDLE)
	{
		goto finalize_and_unload;
	}

	if (!login(instance->settings, module, session, slot_id))
	{
		goto close_session_finalize_and_unload;
	}

	private_key = find_signature_private_key(module, session, &certificate_id);

	if (private_key == CK_INVALID_HANDLE)
	{
		WLog_ERR(TAG, "Signatures: no private key for signature found in this slot.");
		goto close_session_finalize_and_unload;
	}

	(*context) = pkcs11_context_new(module, session, slot_id, private_key);

	if (*context)
	{
		instance->settings->IdCertificate = certificate_id;        /* ! */
		instance->settings->IdCertificateLength = strlen(certificate_id) / 2; /* ! */
		return CKR_OK;
	}

close_session_finalize_and_unload:
	free(certificate_id);
	session = cryptoki_close_session(module, session, slot_id);
finalize_and_unload:
	cryptoki_finalize_and_unload(module);
	return CKR_GENERAL_ERROR;
}


static CK_OBJECT_HANDLE private_key_handle_with_id(pkcs11_context* context, char*  certificate_id)
{
	CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_BBOOL key_sign = CK_TRUE;
	CK_ATTRIBUTE key_template[] =
	{
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_SIGN, &key_sign, sizeof(key_sign)},
		{CKA_ID, NULL, 0}
	};
	CK_OBJECT_HANDLE object;
	CK_ULONG object_count;
	int rv;

	/* search for a specific ID is any */
	if (certificate_id)
	{
		key_template[2].pValue = certificate_id;
		key_template[2].ulValueLen = strlen(certificate_id);
		rv = context->module->p11->C_FindObjectsInit(context->session, key_template, 3);
	}
	else
	{
		rv = context->module->p11->C_FindObjectsInit(context->session, key_template, 2);
	}

	if (rv != CKR_OK)
	{
		WLog_ERR(TAG, "C_FindObjectsInit() failed: 0x%08lX", rv);
		return CK_INVALID_HANDLE;
	}

	rv = context->module->p11->C_FindObjects(context->session, &object, /* max object count: */ 1,
	        &object_count);

	if (rv != CKR_OK)
	{
		WLog_ERR(TAG, "C_FindObjects() failed: 0x%08lX", rv);
		object = CK_INVALID_HANDLE;
		goto done;
	}

	if (object_count <= 0)
	{
		/* cert without private key: perhaps CA or CA-chain cert */
		WLog_ERR(TAG, "No private key found for certificate id %s: 0x%08lX",
		         certificate_id ? certificate_id : "any", rv);
		object = CK_INVALID_HANDLE;
	}

done:
	/* and finally release Find session */
	rv = context->module->p11->C_FindObjectsFinal(context->session);

	if (rv != CKR_OK)
	{
		WLog_ERR(TAG, "C_FindObjectsFinal() failed: 0x%08lX", rv);
		return CK_INVALID_HANDLE;
	}

	return object;
}

/* retrieve the private key handle associated with a given certificate */
static int certificate_update_private_key_handle(pkcs11_context* context, cert_object* cert)
{
	if (context->private_key != CK_INVALID_HANDLE)
	{
		/* we've already found the private key for this certificate */
		return 0;
	}

	cert->private_key = private_key_handle_with_id(context, cert->id_cert);
	cert->key_type = CKK_RSA;
	return (cert->private_key == CK_INVALID_HANDLE) ? -1 : 0;
}



static const X509* get_X509_certificate(cert_object* cert)
{
	return cert->x509;
}

/** match_id compare id's certificate.
*  This function is actually called in find_valid_matching_cert().
*  @param settings - pointer to the rdpSettings structure that contains the settings
*  @param cert - pointer to the cert_handle structure that contains a certificate
*  @return 1 if match occurred; 0 or -1 otherwise
*/
static int match_id(rdpSettings* settings, cert_object* cert)
{
	/* if no cert provided, call  */
	if (!cert->id_cert)
	{
		return 0;
	}

	if (strcmp(settings->IdCertificate, cert->id_cert) != 0)
	{
		return -1;
	}

	return 1;
}

/** find_valid_matching_cert find a valid certificate that matches requirements.
*  This function is actually called in get_valid_smartcard_cert().
*  @param settings - pointer to the rdpSettings structure that contains the settings
*  @param context - pointer to the pkcs11_context structure that contains smartcard data
*  @return 0 if a valid certificate matches requirements (<0 otherwise)
*/
static int find_valid_matching_cert(rdpSettings* settings, pkcs11_context* context)
{
	int i, rv = 0;
	X509* x509 = NULL;
	WLog_DBG(TAG, "settings : ID Authentication Certificate (%s)", settings->IdCertificate);
	context->valid_cert = NULL;

	/* find a valid and matching certificate */
	for (i = 0; i < context->certificates_count; i++)
	{
		x509 = (X509*)get_X509_certificate(context->certificates[i]);

		if (!x509)
		{
			continue;
		}

		/* ensure we extract the right certificate from the list by checking
		* whether ID matches the one previously stored in settings */
		rv = match_id(settings, context->certificates[i]);

		if (rv == 1)   /* match success */
		{
			context->valid_cert = context->certificates[i];
			break;
		}

		WLog_DBG(TAG, "ID not matching (%s vs. %s). Try next cert...",
		         settings->IdCertificate, context->certificates[i]->id_cert);
	}

	/* now valid_cert points to our found certificate or null if none found */
 	if (!context->valid_cert)
	{
		free(context->valid_cert);
		WLog_ERR(TAG, "Error: No matching certificate found");
		return -1;
	}

	return 0;
}

static int crypto_init()
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	return 0;
}

static void debug_log_certificate(int i, X509* cert)
{
	char* name;
	WLog_DBG(TAG, "certificate[%d]:", i);
	name = x509_cert_info_string(cert, CERT_CN);
	WLog_DBG(TAG, "    Common Name: %s", name);
	free(name);
	name = x509_cert_info_string(cert, CERT_SUBJECT);
	WLog_DBG(TAG, "    Subject:     %s", name);
	free(name);
	name = x509_cert_info_string(cert, CERT_ISSUER);
	WLog_DBG(TAG, "    Issuer:      %s", name);
	free(name);
}

/** get_valid_smartcard_cert find and verify the authentication certificate.
*  This function is actually called in get_info_smartcard().
*  @param instance -  freerdp instance.
*  @return 0 if the certificate was successfully retrieved; -1 otherwise
*/
static int get_valid_smartcard_cert(freerdp* instance, pkcs11_context** context)
{
	int i;
	int ret;
	CK_RV ck_rv;
	/* init openssl */
	ret  = crypto_init();

	if (ret != 0)
	{
		WLog_ERR(TAG, "Could not initialize openssl.");
		return -1;
	}

	ck_rv = init_authentication_pin(instance, context);

	if (ck_rv != CKR_OK)
	{
		WLog_ERR(TAG, "Error initialization PKCS#11 session : 0x%08lX", ck_rv);
		return -1;
	}

	(*context)->certificates = certificates_list((*context), &((*context)->certificates_count));

	if ((*context)->certificates == NULL)
	{
		goto get_error;
	}

	for (i = 0; i < (*context)->certificates_count; i++)
	{
		X509* cert = (X509*) get_X509_certificate((*context)->certificates[i]);
		debug_log_certificate(i, cert);

		if (certificate_update_private_key_handle((*context), (*context)->certificates[i]) < 0)
		{
			WLog_ERR(TAG, "%s %d : Certificate[%d] does not have associated private key",
			         __FUNCTION__, __LINE__, i);
			continue;
		}

		if (find_valid_matching_cert(instance->settings, (*context)) == 0)
		{
			WLog_INFO(TAG, "Found 1 valid authentication certificate");
			return 0;
		}

		WLog_ERR(TAG, "None valid and matching requirements certificate found");
	}

get_error:
	cryptoki_close_session((*context)->module, (*context)->session, CK_UNAVAILABLE_INFORMATION);
	pkcs11_context_free((*context));
	(*context) = NULL;
	return -1;
}


/** get_valid_smartcard_UPN is used to get valid UPN and KPN from the smartcard.
*  This function is actually called in init_authentication_pin().
*  @param settings - pointer to stucture rdpSettings
*  @param x509 - pointer to X509 certificate
*  @return 0 if UPN was successfully retrieved
*/
static int get_valid_smartcard_UPN(rdpSettings* settings, X509* x509)
{
	char* entries_upn = NULL;

	if (x509 == NULL)
	{
		WLog_ERR(TAG, "Null certificate provided");
		return -1;
	}

	if (settings->UserPrincipalName)
	{
		WLog_DBG(TAG, "Reset UserPrincipalName");
		free(settings->UserPrincipalName);
		settings->UserPrincipalName = NULL;
	}

	/* retrieve UPN */
	entries_upn = x509_cert_info_string(x509, CERT_UPN);

	if (!entries_upn || (entries_upn && !strlen(entries_upn)))
	{
		WLog_ERR(TAG, "cert_info() failed");
		return -1;
	}

	/* set UPN in rdp settings */
	settings->UserPrincipalName = calloc(strlen(entries_upn) + 1, sizeof(char));

	if (settings->UserPrincipalName == NULL)
	{
		WLog_ERR(TAG, "Error allocation UserPrincipalName");
		return -1;
	}

	strncpy(settings->UserPrincipalName, entries_upn, strlen(entries_upn) + 1);
	return 0;
}

/** get_info_smartcard is used to retrieve a valid authentication certificate.
*  This function is actually called in nla_client_init().
*  @param nla : rdpNla structure that contains nla settings
*  @return CKR_OK if successful, CKR_GENERAL_ERROR if error occurred
*/
int get_info_smartcard(freerdp* instance)
{
	int ret = 0;
	CK_RV rv;
	pkcs11_context* context;

	/* retrieve a valid authentication certificate */
	ret = get_valid_smartcard_cert(instance, & context);

	if ((ret != 0) || (!context))
	{
		return -1;
	}

	/* retrieve UPN from smartcard */
	ret = get_valid_smartcard_UPN(instance->settings, context->valid_cert->x509);

	if (ret < 0)
	{
		WLog_ERR(TAG, "Fail to get valid UPN %s", instance->settings->UserPrincipalName);
		goto auth_failed;
	}
	else
	{
		WLog_DBG(TAG, "Valid UPN retrieved (%s)", instance->settings->UserPrincipalName);
	}

	/* close PKCS#11 session */
	rv = cryptoki_close_session(context->module, context->session, CK_UNAVAILABLE_INFORMATION);

	if (rv != 0)
	{
		pkcs11_context_free(context);
		WLog_ERR(TAG, "close_pkcs11_session() failed: %d", rv);
		return -1;
	}

	/* release PKCS#11 module */
	WLog_DBG(TAG, "releasing PKCS#11 module...");
	pkcs11_context_free(context);
	WLog_DBG(TAG, "UPN retrieving process completed");
	return 0;
auth_failed:
	cryptoki_close_session(context->module, context->session, CK_UNAVAILABLE_INFORMATION);
	pkcs11_context_free(context);
	return -1;
}
