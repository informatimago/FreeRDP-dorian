/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Smartcard Device Service Virtual Channel
 *
 * Copyright (C) Alexi Volkov <alexi@myrealbox.com> 2006
 * Copyright 2011 O.S. Systems Software Ltda.
 * Copyright 2011 Anthony Tong <atong@trustedcs.com>
 * Copyright 2015 Thincast Technologies GmbH
 * Copyright 2015 DI (FH) Martin Haimberger <martin.haimberger@thincast.com>
 * Copyright 2017 Armin Novak <armin.novak@thincast.com>
 * Copyright 2017 Thincast Technologies GmbH
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

#include <assert.h>

#include <winpr/crt.h>
#include <winpr/print.h>
#include <winpr/stream.h>
#include <winpr/smartcard.h>

#include <freerdp/freerdp.h>
#include <freerdp/channels/rdpdr.h>

#include "smartcard_main.h"

const char* smartcard_get_ioctl_string(UINT32 ioControlCode, BOOL funcName)
{
	switch (ioControlCode)
	{
		case SCARD_IOCTL_ESTABLISHCONTEXT:
			return funcName ? "SCardEstablishContext" : "SCARD_IOCTL_ESTABLISHCONTEXT";

		case SCARD_IOCTL_RELEASECONTEXT:
			return funcName ? "SCardReleaseContext" : "SCARD_IOCTL_RELEASECONTEXT";

		case SCARD_IOCTL_ISVALIDCONTEXT:
			return funcName ? "SCardIsValidContext" : "SCARD_IOCTL_ISVALIDCONTEXT";

		case SCARD_IOCTL_LISTREADERGROUPSA:
			return funcName ? "SCardListReaderGroupsA" : "SCARD_IOCTL_LISTREADERGROUPSA";

		case SCARD_IOCTL_LISTREADERGROUPSW:
			return funcName ? "SCardListReaderGroupsW" : "SCARD_IOCTL_LISTREADERGROUPSW";

		case SCARD_IOCTL_LISTREADERSA:
			return funcName ? "SCardListReadersA" : "SCARD_IOCTL_LISTREADERSA";

		case SCARD_IOCTL_LISTREADERSW:
			return funcName ? "SCardListReadersW" : "SCARD_IOCTL_LISTREADERSW";

		case SCARD_IOCTL_INTRODUCEREADERGROUPA:
			return funcName ? "SCardIntroduceReaderGroupA" : "SCARD_IOCTL_INTRODUCEREADERGROUPA";

		case SCARD_IOCTL_INTRODUCEREADERGROUPW:
			return funcName ? "SCardIntroduceReaderGroupW" : "SCARD_IOCTL_INTRODUCEREADERGROUPW";

		case SCARD_IOCTL_FORGETREADERGROUPA:
			return funcName ? "SCardForgetReaderGroupA" : "SCARD_IOCTL_FORGETREADERGROUPA";

		case SCARD_IOCTL_FORGETREADERGROUPW:
			return funcName ? "SCardForgetReaderGroupW" : "SCARD_IOCTL_FORGETREADERGROUPW";

		case SCARD_IOCTL_INTRODUCEREADERA:
			return funcName ? "SCardIntroduceReaderA" : "SCARD_IOCTL_INTRODUCEREADERA";

		case SCARD_IOCTL_INTRODUCEREADERW:
			return funcName ? "SCardIntroduceReaderW" : "SCARD_IOCTL_INTRODUCEREADERW";

		case SCARD_IOCTL_FORGETREADERA:
			return funcName ? "SCardForgetReaderA" : "SCARD_IOCTL_FORGETREADERA";

		case SCARD_IOCTL_FORGETREADERW:
			return funcName ? "SCardForgetReaderW" : "SCARD_IOCTL_FORGETREADERW";

		case SCARD_IOCTL_ADDREADERTOGROUPA:
			return funcName ? "SCardAddReaderToGroupA" : "SCARD_IOCTL_ADDREADERTOGROUPA";

		case SCARD_IOCTL_ADDREADERTOGROUPW:
			return funcName ? "SCardAddReaderToGroupW" : "SCARD_IOCTL_ADDREADERTOGROUPW";

		case SCARD_IOCTL_REMOVEREADERFROMGROUPA:
			return funcName ? "SCardRemoveReaderFromGroupA" : "SCARD_IOCTL_REMOVEREADERFROMGROUPA";

		case SCARD_IOCTL_REMOVEREADERFROMGROUPW:
			return funcName ? "SCardRemoveReaderFromGroupW" : "SCARD_IOCTL_REMOVEREADERFROMGROUPW";

		case SCARD_IOCTL_LOCATECARDSA:
			return funcName ? "SCardLocateCardsA" : "SCARD_IOCTL_LOCATECARDSA";

		case SCARD_IOCTL_LOCATECARDSW:
			return funcName ? "SCardLocateCardsW" : "SCARD_IOCTL_LOCATECARDSW";

		case SCARD_IOCTL_GETSTATUSCHANGEA:
			return funcName ? "SCardGetStatusChangeA" : "SCARD_IOCTL_GETSTATUSCHANGEA";

		case SCARD_IOCTL_GETSTATUSCHANGEW:
			return funcName ? "SCardGetStatusChangeW" : "SCARD_IOCTL_GETSTATUSCHANGEW";

		case SCARD_IOCTL_CANCEL:
			return funcName ? "SCardCancel" : "SCARD_IOCTL_CANCEL";

		case SCARD_IOCTL_CONNECTA:
			return funcName ? "SCardConnectA" : "SCARD_IOCTL_CONNECTA";

		case SCARD_IOCTL_CONNECTW:
			return funcName ? "SCardConnectW" : "SCARD_IOCTL_CONNECTW";

		case SCARD_IOCTL_RECONNECT:
			return funcName ? "SCardReconnect" : "SCARD_IOCTL_RECONNECT";

		case SCARD_IOCTL_DISCONNECT:
			return funcName ? "SCardDisconnect" : "SCARD_IOCTL_DISCONNECT";

		case SCARD_IOCTL_BEGINTRANSACTION:
			return funcName ? "SCardBeginTransaction" : "SCARD_IOCTL_BEGINTRANSACTION";

		case SCARD_IOCTL_ENDTRANSACTION:
			return funcName ? "SCardEndTransaction" : "SCARD_IOCTL_ENDTRANSACTION";

		case SCARD_IOCTL_STATE:
			return funcName ? "SCardState" : "SCARD_IOCTL_STATE";

		case SCARD_IOCTL_STATUSA:
			return funcName ? "SCardStatusA" : "SCARD_IOCTL_STATUSA";

		case SCARD_IOCTL_STATUSW:
			return funcName ? "SCardStatusW" : "SCARD_IOCTL_STATUSW";

		case SCARD_IOCTL_TRANSMIT:
			return funcName ? "SCardTransmit" : "SCARD_IOCTL_TRANSMIT";

		case SCARD_IOCTL_CONTROL:
			return funcName ? "SCardControl" : "SCARD_IOCTL_CONTROL";

		case SCARD_IOCTL_GETATTRIB:
			return funcName ? "SCardGetAttrib" : "SCARD_IOCTL_GETATTRIB";

		case SCARD_IOCTL_SETATTRIB:
			return funcName ? "SCardSetAttrib" : "SCARD_IOCTL_SETATTRIB";

		case SCARD_IOCTL_ACCESSSTARTEDEVENT:
			return funcName ? "SCardAccessStartedEvent" : "SCARD_IOCTL_ACCESSSTARTEDEVENT";

		case SCARD_IOCTL_LOCATECARDSBYATRA:
			return funcName ? "SCardLocateCardsByATRA" : "SCARD_IOCTL_LOCATECARDSBYATRA";

		case SCARD_IOCTL_LOCATECARDSBYATRW:
			return funcName ? "SCardLocateCardsByATRB" : "SCARD_IOCTL_LOCATECARDSBYATRW";

		case SCARD_IOCTL_READCACHEA:
			return funcName ? "SCardReadCacheA" : "SCARD_IOCTL_READCACHEA";

		case SCARD_IOCTL_READCACHEW:
			return funcName ? "SCardReadCacheW" : "SCARD_IOCTL_READCACHEW";

		case SCARD_IOCTL_WRITECACHEA:
			return funcName ? "SCardWriteCacheA" : "SCARD_IOCTL_WRITECACHEA";

		case SCARD_IOCTL_WRITECACHEW:
			return funcName ? "SCardWriteCacheW" : "SCARD_IOCTL_WRITECACHEW";

		case SCARD_IOCTL_GETTRANSMITCOUNT:
			return funcName ? "SCardGetTransmitCount" : "SCARD_IOCTL_GETTRANSMITCOUNT";

		case SCARD_IOCTL_RELEASESTARTEDEVENT:
			return funcName ? "SCardReleaseStartedEvent" : "SCARD_IOCTL_RELEASESTARTEDEVENT";

		case SCARD_IOCTL_GETREADERICON:
			return funcName ? "SCardGetReaderIcon" : "SCARD_IOCTL_GETREADERICON";

		case SCARD_IOCTL_GETDEVICETYPEID:
			return funcName ? "SCardGetDeviceTypeId" : "SCARD_IOCTL_GETDEVICETYPEID";

		default:
			return funcName ? "SCardUnknown" : "SCARD_IOCTL_UNKNOWN";
	}

	return funcName ? "SCardUnknown" : "SCARD_IOCTL_UNKNOWN";
}

static LONG smartcard_EstablishContext_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	EstablishContext_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(EstablishContext_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_establish_context_call(smartcard, irp->input, call)))
	{
		WLog_ERR(TAG, "smartcard_unpack_establish_context_call failed with error %"PRId32"", status);
		return status;
	}

	smartcard_trace_establish_context_call(smartcard, call);
	return SCARD_S_SUCCESS;
}

static LONG smartcard_EstablishContext_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	SCARDCONTEXT hContext = -1;
	EstablishContext_Return ret;
	IRP* irp = operation->irp;
	EstablishContext_Call* call = operation->call;
	status = ret.ReturnCode = SCardEstablishContext(call->dwScope, NULL, NULL, &hContext);

	if (ret.ReturnCode == SCARD_S_SUCCESS)
	{
		SMARTCARD_CONTEXT* pContext;
		void* key = (void*)(size_t) hContext;
		// TODO: handle return values
		pContext = smartcard_context_new(smartcard, hContext);

		if (!pContext)
		{
			WLog_ERR(TAG, "smartcard_context_new failed!");
			return STATUS_NO_MEMORY;
		}

		if (!ListDictionary_Add(smartcard->rgSCardContextList, key, (void*) pContext))
		{
			WLog_ERR(TAG, "ListDictionary_Add failed!");
			return STATUS_INTERNAL_ERROR;
		}
	}
	else
	{
		WLog_ERR(TAG, "SCardEstablishContext failed with error %"PRId32"", status);
		return status;
	}

	smartcard_scard_context_native_to_redir(smartcard, &(ret.hContext), hContext);
	smartcard_trace_establish_context_return(smartcard, &ret);

	if ((status = smartcard_pack_establish_context_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_establish_context_return failed with error %"PRId32"", status);
		return status;
	}

	return ret.ReturnCode;
}

static LONG smartcard_ReleaseContext_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	Context_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(Context_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_context_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_context_call failed with error %"PRId32"", status);

	smartcard_trace_context_call(smartcard, call, "ReleaseContext");
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	return status;
}

static LONG smartcard_ReleaseContext_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	Long_Return ret;
	status = ret.ReturnCode = SCardReleaseContext(operation->hContext);

	if (ret.ReturnCode == SCARD_S_SUCCESS)
	{
		SMARTCARD_CONTEXT* pContext;
		void* key = (void*)(size_t) operation->hContext;
		pContext = (SMARTCARD_CONTEXT*) ListDictionary_Remove(smartcard->rgSCardContextList, key);
		smartcard_context_free(pContext);
	}
	else
	{
		WLog_ERR(TAG, "SCardReleaseContext failed with error %"PRId32"", status);
		return status;
	}

	smartcard_trace_long_return(smartcard, &ret, "ReleaseContext");
	return ret.ReturnCode;
}

static LONG smartcard_IsValidContext_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	Context_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(Context_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_context_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_context_call failed with error %"PRId32"", status);

	smartcard_trace_context_call(smartcard, call, "IsValidContext");
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	return status;
}

static LONG smartcard_IsValidContext_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	Long_Return ret;

	if ((status = ret.ReturnCode = SCardIsValidContext(operation->hContext)))
	{
		WLog_ERR(TAG, "SCardIsValidContext failed with error %"PRId32"", status);
		return status;
	}

	smartcard_trace_long_return(smartcard, &ret, "IsValidContext");
	return ret.ReturnCode;
}

static LONG smartcard_ListReaderGroupsA_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	ListReaderGroups_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(ListReaderGroups_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	status = smartcard_unpack_list_reader_groups_call(smartcard, irp->input, call);
	smartcard_trace_list_reader_groups_call(smartcard, call, FALSE);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	return status;
}

static LONG smartcard_ListReaderGroupsA_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	ListReaderGroups_Return ret;
	LPSTR mszGroups = NULL;
	DWORD cchGroups = 0;
	IRP* irp = operation->irp;
	cchGroups = SCARD_AUTOALLOCATE;
	status = ret.ReturnCode = SCardListReaderGroupsA(operation->hContext, (LPSTR) &mszGroups,
	                          &cchGroups);
	ret.msz = (BYTE*) mszGroups;
	ret.cBytes = cchGroups;

	if (status != SCARD_S_SUCCESS)
		return status;

	smartcard_trace_list_reader_groups_return(smartcard, &ret, FALSE);
	status = smartcard_pack_list_reader_groups_return(smartcard, irp->output, &ret);

	if (status != SCARD_S_SUCCESS)
		return status;

	if (mszGroups)
		SCardFreeMemory(operation->hContext, mszGroups);

	return ret.ReturnCode;
}

static LONG smartcard_ListReaderGroupsW_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	ListReaderGroups_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(ListReaderGroups_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	status = smartcard_unpack_list_reader_groups_call(smartcard, irp->input, call);
	smartcard_trace_list_reader_groups_call(smartcard, call, TRUE);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	return status;
}

static LONG smartcard_ListReaderGroupsW_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	ListReaderGroups_Return ret;
	LPWSTR mszGroups = NULL;
	DWORD cchGroups = 0;
	IRP* irp = operation->irp;
	cchGroups = SCARD_AUTOALLOCATE;
	status = ret.ReturnCode = SCardListReaderGroupsW(operation->hContext, (LPWSTR) &mszGroups,
	                          &cchGroups);
	ret.msz = (BYTE*) mszGroups;
	ret.cBytes = cchGroups;

	if (status != SCARD_S_SUCCESS)
		return status;

	smartcard_trace_list_reader_groups_return(smartcard, &ret, TRUE);
	status = smartcard_pack_list_reader_groups_return(smartcard, irp->output, &ret);

	if (status != SCARD_S_SUCCESS)
		return status;

	if (mszGroups)
		SCardFreeMemory(operation->hContext, mszGroups);

	return ret.ReturnCode;
}

static LONG smartcard_ListReadersA_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	ListReaders_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(ListReaders_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_list_readers_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_list_readers_call failed with error %"PRId32"", status);

	smartcard_trace_list_readers_call(smartcard, call, FALSE);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	return status;
}

static LONG smartcard_ListReadersA_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	ListReaders_Return ret;
	LPSTR mszReaders = NULL;
	DWORD cchReaders = 0;
	IRP* irp = operation->irp;
	ListReaders_Call* call = operation->call;
	cchReaders = SCARD_AUTOALLOCATE;
	status = ret.ReturnCode = SCardListReadersA(operation->hContext, (LPCSTR) call->mszGroups,
	                          (LPSTR) &mszReaders, &cchReaders);
	ret.msz = (BYTE*) mszReaders;
	ret.cBytes = cchReaders;

	if (call->mszGroups)
	{
		free(call->mszGroups);
		call->mszGroups = NULL;
	}

	if (status)
	{
		WLog_ERR(TAG, "SCardListReadersA failed with error %"PRId32"", status);
		return status;
	}

	smartcard_trace_list_readers_return(smartcard, &ret, FALSE);

	if ((status = smartcard_pack_list_readers_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_list_readers_return failed with error %"PRId32"", status);
		return status;
	}

	if (mszReaders)
		SCardFreeMemory(operation->hContext, mszReaders);

	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_ListReadersW_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	ListReaders_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(ListReaders_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_list_readers_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_list_readers_call failed with error %"PRId32"", status);

	smartcard_trace_list_readers_call(smartcard, call, TRUE);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	return status;
}

static LONG smartcard_ListReadersW_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	ListReaders_Return ret;
	LPWSTR mszReaders = NULL;
	DWORD cchReaders = 0;
	IRP* irp = operation->irp;
	ListReaders_Call* call = operation->call;
	cchReaders = SCARD_AUTOALLOCATE;
	status = ret.ReturnCode = SCardListReadersW(operation->hContext,
	                          (LPCWSTR) call->mszGroups, (LPWSTR) &mszReaders, &cchReaders);
	ret.msz = (BYTE*) mszReaders;
	ret.cBytes = cchReaders * 2;

	if (call->mszGroups)
	{
		free(call->mszGroups);
		call->mszGroups = NULL;
	}

	if (status != SCARD_S_SUCCESS)
	{
		WLog_ERR(TAG, "SCardListReadersW failed with error %"PRId32"", status);
		return status;
	}

	smartcard_trace_list_readers_return(smartcard, &ret, TRUE);

	if ((status = smartcard_pack_list_readers_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_list_readers_return failed with error %"PRId32"", status);
		return status;
	}

	if (mszReaders)
		SCardFreeMemory(operation->hContext, mszReaders);

	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_GetStatusChangeA_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	GetStatusChangeA_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(GetStatusChangeA_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_get_status_change_a_call(smartcard, irp->input, call)))
	{
		WLog_ERR(TAG, "smartcard_unpack_get_status_change_a_call failed with error %"PRId32"", status);
		return status;
	}

	smartcard_trace_get_status_change_a_call(smartcard, call);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	return status;
}

static LONG smartcard_GetStatusChangeA_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	UINT32 index;
	GetStatusChange_Return ret;
	LPSCARD_READERSTATEA rgReaderState = NULL;
	IRP* irp = operation->irp;
	GetStatusChangeA_Call* call = operation->call;
	status = ret.ReturnCode = SCardGetStatusChangeA(operation->hContext,
	                          call->dwTimeOut, call->rgReaderStates, call->cReaders);

	if (status && (status != SCARD_E_TIMEOUT) && (status != SCARD_E_CANCELLED))
	{
		call->cReaders = 0;
	}

	ret.cReaders = call->cReaders;
	ret.rgReaderStates = NULL;

	if (ret.cReaders > 0)
		ret.rgReaderStates = (ReaderState_Return*) calloc(ret.cReaders, sizeof(ReaderState_Return));

	if (!ret.rgReaderStates)
		return STATUS_NO_MEMORY;

	for (index = 0; index < ret.cReaders; index++)
	{
		ret.rgReaderStates[index].dwCurrentState = call->rgReaderStates[index].dwCurrentState;
		ret.rgReaderStates[index].dwEventState = call->rgReaderStates[index].dwEventState;
		ret.rgReaderStates[index].cbAtr = call->rgReaderStates[index].cbAtr;
		CopyMemory(&(ret.rgReaderStates[index].rgbAtr), &(call->rgReaderStates[index].rgbAtr), 32);
	}

	smartcard_trace_get_status_change_return(smartcard, &ret, FALSE);

	if ((status = smartcard_pack_get_status_change_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_get_status_change_return failed with error %"PRId32"", status);
		return status;
	}

	if (call->rgReaderStates)
	{
		for (index = 0; index < call->cReaders; index++)
		{
			rgReaderState = &call->rgReaderStates[index];
			free((void*)rgReaderState->szReader);
		}

		free(call->rgReaderStates);
	}

	free(ret.rgReaderStates);
	return ret.ReturnCode;
}

static LONG smartcard_GetStatusChangeW_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	GetStatusChangeW_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(GetStatusChangeW_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_get_status_change_w_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_get_status_change_w_call failed with error %"PRId32"", status);

	smartcard_trace_get_status_change_w_call(smartcard, call);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	return status;
}

static LONG smartcard_GetStatusChangeW_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	UINT32 index;
	GetStatusChange_Return ret;
	LPSCARD_READERSTATEW rgReaderState = NULL;
	IRP* irp = operation->irp;
	GetStatusChangeW_Call* call = operation->call;
	status = ret.ReturnCode = SCardGetStatusChangeW(operation->hContext, call->dwTimeOut,
	                          call->rgReaderStates, call->cReaders);

	if (status && (status != SCARD_E_TIMEOUT) && (status != SCARD_E_CANCELLED))
	{
		call->cReaders = 0;
	}

	ret.cReaders = call->cReaders;
	ret.rgReaderStates = NULL;

	if (ret.cReaders > 0)
		ret.rgReaderStates = (ReaderState_Return*) calloc(ret.cReaders, sizeof(ReaderState_Return));

	if (!ret.rgReaderStates)
		return STATUS_NO_MEMORY;

	for (index = 0; index < ret.cReaders; index++)
	{
		ret.rgReaderStates[index].dwCurrentState = call->rgReaderStates[index].dwCurrentState;
		ret.rgReaderStates[index].dwEventState = call->rgReaderStates[index].dwEventState;
		ret.rgReaderStates[index].cbAtr = call->rgReaderStates[index].cbAtr;
		CopyMemory(&(ret.rgReaderStates[index].rgbAtr), &(call->rgReaderStates[index].rgbAtr), 32);
	}

	smartcard_trace_get_status_change_return(smartcard, &ret, TRUE);

	if ((status = smartcard_pack_get_status_change_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_get_status_change_return failed with error %"PRId32"", status);
		return status;
	}

	if (call->rgReaderStates)
	{
		for (index = 0; index < call->cReaders; index++)
		{
			rgReaderState = &call->rgReaderStates[index];
			free((void*)rgReaderState->szReader);
		}

		free(call->rgReaderStates);
	}

	free(ret.rgReaderStates);
	return ret.ReturnCode;
}

static LONG smartcard_Cancel_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Context_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(Context_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_context_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_context_call failed with error %"PRId32"", status);

	smartcard_trace_context_call(smartcard, call, "Cancel");
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	return status;
}

static LONG smartcard_Cancel_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Long_Return ret;

	if ((status = ret.ReturnCode = SCardCancel(operation->hContext)))
	{
		WLog_ERR(TAG, "SCardCancel failed with error %"PRId32"", status);
		return status;
	}

	smartcard_trace_long_return(smartcard, &ret, "Cancel");
	return ret.ReturnCode;
}

static LONG smartcard_ConnectA_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	ConnectA_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(ConnectA_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_connect_a_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_connect_a_call failed with error %"PRId32"", status);

	smartcard_trace_connect_a_call(smartcard, call);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard,
	                      &(call->Common.hContext));
	return status;
}

static LONG smartcard_ConnectA_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	SCARDHANDLE hCard = 0;
	Connect_Return ret = { 0 };
	IRP* irp = operation->irp;
	ConnectA_Call* call = operation->call;

	if ((call->Common.dwPreferredProtocols == SCARD_PROTOCOL_UNDEFINED) &&
	    (call->Common.dwShareMode != SCARD_SHARE_DIRECT))
	{
		call->Common.dwPreferredProtocols = SCARD_PROTOCOL_Tx;
	}

	status = ret.ReturnCode = SCardConnectA(operation->hContext, (char*) call->szReader,
	                                        call->Common.dwShareMode,
	                                        call->Common.dwPreferredProtocols, &hCard, &ret.dwActiveProtocol);
	smartcard_scard_context_native_to_redir(smartcard, &(ret.hContext), operation->hContext);
	smartcard_scard_handle_native_to_redir(smartcard, &(ret.hCard), hCard);
	smartcard_trace_connect_return(smartcard, &ret);

	if (status)
	{
		WLog_ERR(TAG, "SCardConnectA failed with error %"PRId32"", status);
		return status;
	}

	if ((status = smartcard_pack_connect_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_connect_return failed with error %"PRId32"", status);
		return status;
	}

	free(call->szReader);
	return ret.ReturnCode;
}

static LONG smartcard_ConnectW_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	ConnectW_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(ConnectW_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_connect_w_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_connect_w_call failed with error %"PRId32"", status);

	smartcard_trace_connect_w_call(smartcard, call);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard,
	                      &(call->Common.hContext));
	return status;
}

static LONG smartcard_ConnectW_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	SCARDHANDLE hCard = 0;
	Connect_Return ret = { 0 };
	IRP* irp = operation->irp;
	ConnectW_Call* call = operation->call;

	if ((call->Common.dwPreferredProtocols == SCARD_PROTOCOL_UNDEFINED) &&
	    (call->Common.dwShareMode != SCARD_SHARE_DIRECT))
	{
		call->Common.dwPreferredProtocols = SCARD_PROTOCOL_Tx;
	}

	status = ret.ReturnCode = SCardConnectW(operation->hContext, (WCHAR*) call->szReader,
	                                        call->Common.dwShareMode,
	                                        call->Common.dwPreferredProtocols, &hCard, &ret.dwActiveProtocol);
	smartcard_scard_context_native_to_redir(smartcard, &(ret.hContext), operation->hContext);
	smartcard_scard_handle_native_to_redir(smartcard, &(ret.hCard), hCard);
	smartcard_trace_connect_return(smartcard, &ret);

	if (status)
	{
		WLog_ERR(TAG, "SCardConnectW failed with error %"PRId32"", status);
		return status;
	}

	if ((status = smartcard_pack_connect_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_connect_return failed with error %"PRId32"", status);
		return status;
	}

	free(call->szReader);
	return ret.ReturnCode;
}

static LONG smartcard_Reconnect_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Reconnect_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(Reconnect_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_reconnect_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_reconnect_call failed with error %"PRId32"", status);

	smartcard_trace_reconnect_call(smartcard, call);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	operation->hCard = smartcard_scard_handle_native_from_redir(smartcard, &(call->hCard));
	return status;
}

static LONG smartcard_Reconnect_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Reconnect_Return ret;
	IRP* irp = operation->irp;
	Reconnect_Call* call = operation->call;
	status = ret.ReturnCode = SCardReconnect(operation->hCard, call->dwShareMode,
	                          call->dwPreferredProtocols, call->dwInitialization, &ret.dwActiveProtocol);
	smartcard_trace_reconnect_return(smartcard, &ret);

	if ((status = smartcard_pack_reconnect_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_reconnect_return failed with error %"PRId32"", status);
		return status;
	}

	return ret.ReturnCode;
}

static LONG smartcard_Disconnect_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	HCardAndDisposition_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(HCardAndDisposition_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_hcard_and_disposition_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_hcard_and_disposition_call failed with error %"PRId32"", status);

	smartcard_trace_hcard_and_disposition_call(smartcard, call, "Disconnect");
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	operation->hCard = smartcard_scard_handle_native_from_redir(smartcard, &(call->hCard));
	return status;
}

static LONG smartcard_Disconnect_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Long_Return ret;
	HCardAndDisposition_Call* call = operation->call;

	if ((status = ret.ReturnCode = SCardDisconnect(operation->hCard, call->dwDisposition)))
	{
		WLog_ERR(TAG, "SCardDisconnect failed with error %"PRId32"", status);
		return status;
	}

	smartcard_trace_long_return(smartcard, &ret, "Disconnect");

	if (status != SCARD_S_SUCCESS)
		return status;

	return ret.ReturnCode;
}

static LONG smartcard_BeginTransaction_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	HCardAndDisposition_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(HCardAndDisposition_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_hcard_and_disposition_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_hcard_and_disposition_call failed with error %"PRId32"", status);

	smartcard_trace_hcard_and_disposition_call(smartcard, call, "BeginTransaction");
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	operation->hCard = smartcard_scard_handle_native_from_redir(smartcard, &(call->hCard));
	return status;
}

static LONG smartcard_BeginTransaction_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	Long_Return ret;

	if ((ret.ReturnCode = SCardBeginTransaction(operation->hCard)))
	{
		WLog_ERR(TAG, "SCardBeginTransaction failed with error %"PRId32"", ret.ReturnCode);
		return ret.ReturnCode;
	}

	smartcard_trace_long_return(smartcard, &ret, "BeginTransaction");
	return ret.ReturnCode;
}

static LONG smartcard_EndTransaction_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	HCardAndDisposition_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(HCardAndDisposition_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_hcard_and_disposition_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_hcard_and_disposition_call failed with error %"PRId32"", status);

	smartcard_trace_hcard_and_disposition_call(smartcard, call, "EndTransaction");
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	operation->hCard = smartcard_scard_handle_native_from_redir(smartcard, &(call->hCard));
	return status;
}

static LONG smartcard_EndTransaction_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	Long_Return ret;
	HCardAndDisposition_Call* call = operation->call;

	if ((ret.ReturnCode = SCardEndTransaction(operation->hCard, call->dwDisposition)))
	{
		WLog_ERR(TAG, "SCardEndTransaction failed with error %"PRId32"", ret.ReturnCode);
		return ret.ReturnCode;
	}

	smartcard_trace_long_return(smartcard, &ret, "EndTransaction");
	return ret.ReturnCode;
}

static LONG smartcard_State_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	State_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(State_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_state_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_state_call failed with error %"PRId32"", status);

	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	operation->hCard = smartcard_scard_handle_native_from_redir(smartcard, &(call->hCard));
	return status;
}

static LONG smartcard_State_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	State_Return ret;
	IRP* irp = operation->irp;
	ret.cbAtrLen = SCARD_ATR_LENGTH;
	ret.ReturnCode = SCardState(operation->hCard, &ret.dwState, &ret.dwProtocol, (BYTE*) &ret.rgAtr,
	                            &ret.cbAtrLen);

	if ((status = smartcard_pack_state_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_state_return failed with error %"PRId32"", status);
		return status;
	}

	return ret.ReturnCode;
}

static LONG smartcard_StatusA_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Status_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(Status_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_status_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_status_call failed with error %"PRId32"", status);

	smartcard_trace_status_call(smartcard, call, FALSE);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	operation->hCard = smartcard_scard_handle_native_from_redir(smartcard, &(call->hCard));
	return status;
}

static LONG smartcard_StatusA_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Status_Return ret = { 0 };
	DWORD cchReaderLen = 0;
	LPSTR mszReaderNames = NULL;
	IRP* irp = operation->irp;
	Status_Call* call = operation->call;

	if (call->cbAtrLen > 32)
		call->cbAtrLen = 32;

	ret.cbAtrLen = call->cbAtrLen;
	ZeroMemory(ret.pbAtr, 32);
	cchReaderLen = SCARD_AUTOALLOCATE;
	status = ret.ReturnCode = SCardStatusA(operation->hCard, (LPSTR) &mszReaderNames, &cchReaderLen,
	                                       &ret.dwState, &ret.dwProtocol, (BYTE*) &ret.pbAtr, &ret.cbAtrLen);

	if (status == SCARD_S_SUCCESS)
	{
		ret.mszReaderNames = (BYTE*) mszReaderNames;
		ret.cBytes = cchReaderLen;
	}

	smartcard_trace_status_return(smartcard, &ret, FALSE);

	if ((status = smartcard_pack_status_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_status_return failed with error %"PRId32"", status);
		return status;
	}

	if (mszReaderNames)
		SCardFreeMemory(operation->hContext, mszReaderNames);

	return ret.ReturnCode;
}

static LONG smartcard_StatusW_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Status_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(Status_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_status_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_status_call failed with error %"PRId32"", status);

	smartcard_trace_status_call(smartcard, call, TRUE);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	operation->hCard = smartcard_scard_handle_native_from_redir(smartcard, &(call->hCard));
	return status;
}

static LONG smartcard_StatusW_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Status_Return ret;
	DWORD cchReaderLen = 0;
	LPWSTR mszReaderNames = NULL;
	IRP* irp = operation->irp;
	Status_Call* call = operation->call;

	if (call->cbAtrLen > 32)
		call->cbAtrLen = 32;

	ret.cbAtrLen = call->cbAtrLen;
	ZeroMemory(ret.pbAtr, 32);
	cchReaderLen = SCARD_AUTOALLOCATE;
	status = ret.ReturnCode = SCardStatusW(operation->hCard, (LPWSTR) &mszReaderNames, &cchReaderLen,
	                                       &ret.dwState, &ret.dwProtocol, (BYTE*) &ret.pbAtr, &ret.cbAtrLen);
	ret.mszReaderNames = (BYTE*) mszReaderNames;
	ret.cBytes = cchReaderLen * 2;
	smartcard_trace_status_return(smartcard, &ret, TRUE);

	if ((status = smartcard_pack_status_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_status_return failed with error %"PRId32"", status);
		return status;
	}

	if (mszReaderNames)
		SCardFreeMemory(operation->hContext, mszReaderNames);

	return ret.ReturnCode;
}

static LONG smartcard_Transmit_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Transmit_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(Transmit_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_transmit_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_transmit_call failed with error %"PRId32"", status);

	smartcard_trace_transmit_call(smartcard, call);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	operation->hCard = smartcard_scard_handle_native_from_redir(smartcard, &(call->hCard));
	return status;
}

static LONG smartcard_Transmit_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Transmit_Return ret;
	IRP* irp = operation->irp;
	Transmit_Call* call = operation->call;
	ret.cbRecvLength = 0;
	ret.pbRecvBuffer = NULL;

	if (call->cbRecvLength && !call->fpbRecvBufferIsNULL)
	{
		if (call->cbRecvLength >= 66560)
			call->cbRecvLength = 66560;

		ret.cbRecvLength = call->cbRecvLength;
		ret.pbRecvBuffer = (BYTE*) malloc(ret.cbRecvLength);

		if (!ret.pbRecvBuffer)
			return STATUS_NO_MEMORY;
	}

	ret.pioRecvPci = call->pioRecvPci;
	status = ret.ReturnCode = SCardTransmit(operation->hCard, call->pioSendPci, call->pbSendBuffer,
	                                        call->cbSendLength, ret.pioRecvPci, ret.pbRecvBuffer, &(ret.cbRecvLength));
	smartcard_trace_transmit_return(smartcard, &ret);

	if ((status = smartcard_pack_transmit_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_transmit_return failed with error %"PRId32"", status);
		return status;
	}

	free(call->pbSendBuffer);
	free(ret.pbRecvBuffer);
	free(call->pioSendPci);
	free(call->pioRecvPci);
	return ret.ReturnCode;
}

static LONG smartcard_Control_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Control_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(Control_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_control_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_control_call failed with error %"PRId32"", status);

	smartcard_trace_control_call(smartcard, call);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	operation->hCard = smartcard_scard_handle_native_from_redir(smartcard, &(call->hCard));
	return status;
}

static LONG smartcard_Control_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	Control_Return ret;
	IRP* irp = operation->irp;
	Control_Call* call = operation->call;
	ret.cbOutBufferSize = call->cbOutBufferSize;
	ret.pvOutBuffer = (BYTE*) malloc(call->cbOutBufferSize);

	if (!ret.pvOutBuffer)
		return SCARD_E_NO_MEMORY;

	status = ret.ReturnCode = SCardControl(operation->hCard,
	                                       call->dwControlCode, call->pvInBuffer, call->cbInBufferSize,
	                                       ret.pvOutBuffer, call->cbOutBufferSize, &ret.cbOutBufferSize);
	smartcard_trace_control_return(smartcard, &ret);

	if ((status = smartcard_pack_control_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_control_return failed with error %"PRId32"", status);
		return status;
	}

	free(call->pvInBuffer);
	free(ret.pvOutBuffer);
	return ret.ReturnCode;
}

static LONG smartcard_GetAttrib_Decode(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	GetAttrib_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(GetAttrib_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_get_attrib_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_get_attrib_call failed with error %"PRId32"", status);

	smartcard_trace_get_attrib_call(smartcard, call);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	operation->hCard = smartcard_scard_handle_native_from_redir(smartcard, &(call->hCard));
	return status;
}

static LONG smartcard_GetAttrib_Call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	LONG status;
	DWORD cbAttrLen;
	BOOL autoAllocate;
	GetAttrib_Return ret;
	IRP* irp = operation->irp;
	GetAttrib_Call* call = operation->call;
	ret.pbAttr = NULL;

	if (call->fpbAttrIsNULL)
		call->cbAttrLen = 0;

	autoAllocate = (call->cbAttrLen == SCARD_AUTOALLOCATE) ? TRUE : FALSE;

	if (call->cbAttrLen && !autoAllocate)
	{
		ret.pbAttr = (BYTE*) malloc(call->cbAttrLen);

		if (!ret.pbAttr)
			return SCARD_E_NO_MEMORY;
	}

	cbAttrLen = call->cbAttrLen;
	status = ret.ReturnCode = SCardGetAttrib(operation->hCard, call->dwAttrId,
	                          autoAllocate ? (LPBYTE) & (ret.pbAttr) : ret.pbAttr, &cbAttrLen);
	ret.cbAttrLen = cbAttrLen;
	smartcard_trace_get_attrib_return(smartcard, &ret, call->dwAttrId);

	if (ret.ReturnCode)
	{
		WLog_WARN(TAG, "SCardGetAttrib: %s (0x%08"PRIX32") cbAttrLen: %"PRIu32"",
		          SCardGetAttributeString(call->dwAttrId), call->dwAttrId, call->cbAttrLen);
		Stream_Zero(irp->output, 256);
		free(ret.pbAttr);
		return ret.ReturnCode;
	}

	if ((status = smartcard_pack_get_attrib_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_get_attrib_return failed with error %"PRId32"", status);
		return status;
	}

	free(ret.pbAttr);
	return ret.ReturnCode;
}

static LONG smartcard_AccessStartedEvent_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	Long_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(Long_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		WLog_WARN(TAG, "AccessStartedEvent is too short: %"PRIuz"",
		          Stream_GetRemainingLength(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(irp->input, call->LongValue); /* Unused (4 bytes) */
	return SCARD_S_SUCCESS;
}

static LONG smartcard_AccessStartedEvent_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status = SCARD_S_SUCCESS;

	if (!smartcard->StartedEvent)
		smartcard->StartedEvent = SCardAccessStartedEvent();

	if (!smartcard->StartedEvent)
		status = SCARD_E_NO_SERVICE;

	return status;
}

static LONG smartcard_LocateCardsByATRA_Decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	LocateCardsByATRA_Call* call;
	IRP* irp = operation->irp;
	operation->call = call = calloc(1, sizeof(LocateCardsByATRA_Call));

	if (!call)
		return STATUS_NO_MEMORY;

	if ((status = smartcard_unpack_locate_cards_by_atr_a_call(smartcard, irp->input, call)))
		WLog_ERR(TAG, "smartcard_unpack_locate_cards_by_atr_a_call failed with error %"PRId32"", status);

	smartcard_trace_locate_cards_by_atr_a_call(smartcard, call);
	operation->hContext = smartcard_scard_context_native_from_redir(smartcard, &(call->hContext));
	return status;
}

static LONG smartcard_LocateCardsByATRA_Call(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	BOOL equal;
	DWORD i, j, k;
	GetStatusChange_Return ret;
	LPSCARD_READERSTATEA state = NULL;
	LPSCARD_READERSTATEA states = NULL;
	IRP* irp = operation->irp;
	LocateCardsByATRA_Call* call = operation->call;
	states = (LPSCARD_READERSTATEA) calloc(call->cReaders, sizeof(SCARD_READERSTATEA));

	if (!states)
		return STATUS_NO_MEMORY;

	for (i = 0; i < call->cReaders; i++)
	{
		states[i].szReader = (LPCSTR) call->rgReaderStates[i].szReader;
		states[i].dwCurrentState = call->rgReaderStates[i].Common.dwCurrentState;
		states[i].dwEventState = call->rgReaderStates[i].Common.dwEventState;
		states[i].cbAtr = call->rgReaderStates[i].Common.cbAtr;
		CopyMemory(&(states[i].rgbAtr), &(call->rgReaderStates[i].Common.rgbAtr), 35);
	}

	status = ret.ReturnCode = SCardGetStatusChangeA(operation->hContext, 0x000001F4, states,
	                          call->cReaders);

	if (status && (status != SCARD_E_TIMEOUT) && (status != SCARD_E_CANCELLED))
	{
		call->cReaders = 0;
	}

	for (i = 0; i < call->cAtrs; i++)
	{
		for (j = 0; j < call->cReaders; j++)
		{
			equal = TRUE;

			for (k = 0; k < call->rgAtrMasks[i].cbAtr; k++)
			{
				if ((call->rgAtrMasks[i].rgbAtr[k] & call->rgAtrMasks[i].rgbMask[k]) !=
				    (states[j].rgbAtr[k] & call->rgAtrMasks[i].rgbMask[k]))
				{
					equal = FALSE;
					break;
				}

				if (equal)
				{
					states[j].dwEventState |= SCARD_STATE_ATRMATCH;
				}
			}
		}
	}

	ret.cReaders = call->cReaders;
	ret.rgReaderStates = NULL;

	if (ret.cReaders > 0)
		ret.rgReaderStates = (ReaderState_Return*) calloc(ret.cReaders, sizeof(ReaderState_Return));

	if (!ret.rgReaderStates)
		return STATUS_NO_MEMORY;

	for (i = 0; i < ret.cReaders; i++)
	{
		state = &states[i];
		ret.rgReaderStates[i].dwCurrentState = state->dwCurrentState;
		ret.rgReaderStates[i].dwEventState = state->dwEventState;
		ret.rgReaderStates[i].cbAtr = state->cbAtr;
		CopyMemory(&(ret.rgReaderStates[i].rgbAtr), &(state->rgbAtr), 32);
	}

	free(states);
	smartcard_trace_get_status_change_return(smartcard, &ret, FALSE);

	if ((status = smartcard_pack_get_status_change_return(smartcard, irp->output, &ret)))
	{
		WLog_ERR(TAG, "smartcard_pack_get_status_change_return failed with error %"PRId32"", status);
		return status;
	}

	if (call->rgReaderStates)
	{
		for (i = 0; i < call->cReaders; i++)
		{
			state = (LPSCARD_READERSTATEA) &call->rgReaderStates[i];

			if (state->szReader)
			{
				free((void*) state->szReader);
				state->szReader = NULL;
			}
		}

		free(call->rgReaderStates);
		call->rgReaderStates = NULL;
	}

	free(ret.rgReaderStates);
	return ret.ReturnCode;
}

LONG smartcard_irp_device_control_decode(SMARTCARD_DEVICE* smartcard,
        SMARTCARD_OPERATION* operation)
{
	LONG status;
	UINT32 offset;
	UINT32 ioControlCode;
	UINT32 outputBufferLength;
	UINT32 inputBufferLength;
	IRP* irp = operation->irp;

	/* Device Control Request */

	if (Stream_GetRemainingLength(irp->input) < 32)
	{
		WLog_WARN(TAG, "Device Control Request is too short: %"PRIuz"",
		          Stream_GetRemainingLength(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(irp->input, outputBufferLength); /* OutputBufferLength (4 bytes) */
	Stream_Read_UINT32(irp->input, inputBufferLength); /* InputBufferLength (4 bytes) */
	Stream_Read_UINT32(irp->input, ioControlCode); /* IoControlCode (4 bytes) */
	Stream_Seek(irp->input, 20); /* Padding (20 bytes) */
	operation->ioControlCode = ioControlCode;

	if (Stream_Length(irp->input) != (Stream_GetPosition(irp->input) + inputBufferLength))
	{
		WLog_WARN(TAG, "InputBufferLength mismatch: Actual: %"PRIuz" Expected: %"PRIuz"",
		          Stream_Length(irp->input),
		          Stream_GetPosition(irp->input) + inputBufferLength);
		return SCARD_F_INTERNAL_ERROR;
	}

	WLog_DBG(TAG, "%s (0x%08"PRIX32") FileId: %"PRIu32" CompletionId: %"PRIu32"",
	         smartcard_get_ioctl_string(ioControlCode, TRUE),
	         ioControlCode, irp->FileId, irp->CompletionId);

	if ((ioControlCode != SCARD_IOCTL_ACCESSSTARTEDEVENT) &&
	    (ioControlCode != SCARD_IOCTL_RELEASESTARTEDEVENT))
	{
		if ((status = smartcard_unpack_common_type_header(smartcard, irp->input)))
		{
			WLog_ERR(TAG, "smartcard_unpack_common_type_header failed with error %"PRId32"", status);
			return SCARD_F_INTERNAL_ERROR;
		}

		if ((status = smartcard_unpack_private_type_header(smartcard, irp->input)))
		{
			WLog_ERR(TAG, "smartcard_unpack_common_type_header failed with error %"PRId32"", status);
			return SCARD_F_INTERNAL_ERROR;
		}
	}

	/* Decode */
	operation->call = NULL;

	switch (ioControlCode)
	{
		case SCARD_IOCTL_ESTABLISHCONTEXT:
			status = smartcard_EstablishContext_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_RELEASECONTEXT:
			status = smartcard_ReleaseContext_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_ISVALIDCONTEXT:
			status = smartcard_IsValidContext_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_LISTREADERGROUPSA:
			status = smartcard_ListReaderGroupsA_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_LISTREADERGROUPSW:
			status = smartcard_ListReaderGroupsW_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_LISTREADERSA:
			status = smartcard_ListReadersA_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_LISTREADERSW:
			status = smartcard_ListReadersW_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_INTRODUCEREADERGROUPA:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_INTRODUCEREADERGROUPW:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_FORGETREADERGROUPA:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_FORGETREADERGROUPW:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_INTRODUCEREADERA:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_INTRODUCEREADERW:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_FORGETREADERA:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_FORGETREADERW:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_ADDREADERTOGROUPA:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_ADDREADERTOGROUPW:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_REMOVEREADERFROMGROUPA:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_REMOVEREADERFROMGROUPW:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_LOCATECARDSA:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_LOCATECARDSW:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_GETSTATUSCHANGEA:
			status = smartcard_GetStatusChangeA_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_GETSTATUSCHANGEW:
			status = smartcard_GetStatusChangeW_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_CANCEL:
			status = smartcard_Cancel_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_CONNECTA:
			status = smartcard_ConnectA_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_CONNECTW:
			status = smartcard_ConnectW_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_RECONNECT:
			status = smartcard_Reconnect_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_DISCONNECT:
			status = smartcard_Disconnect_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_BEGINTRANSACTION:
			status = smartcard_BeginTransaction_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_ENDTRANSACTION:
			status = smartcard_EndTransaction_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_STATE:
			status = smartcard_State_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_STATUSA:
			status = smartcard_StatusA_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_STATUSW:
			status = smartcard_StatusW_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_TRANSMIT:
			status = smartcard_Transmit_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_CONTROL:
			status = smartcard_Control_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_GETATTRIB:
			status = smartcard_GetAttrib_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_SETATTRIB:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_ACCESSSTARTEDEVENT:
			status = smartcard_AccessStartedEvent_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_LOCATECARDSBYATRA:
			status = smartcard_LocateCardsByATRA_Decode(smartcard, operation);
			break;

		case SCARD_IOCTL_LOCATECARDSBYATRW:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_READCACHEA:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_READCACHEW:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_WRITECACHEA:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_WRITECACHEW:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_GETTRANSMITCOUNT:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_RELEASESTARTEDEVENT:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_GETREADERICON:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_GETDEVICETYPEID:
			status = SCARD_F_INTERNAL_ERROR;
			break;

		default:
			status = SCARD_F_INTERNAL_ERROR;
			break;
	}

	if ((ioControlCode != SCARD_IOCTL_ACCESSSTARTEDEVENT) &&
	    (ioControlCode != SCARD_IOCTL_RELEASESTARTEDEVENT))
	{
		offset = (RDPDR_DEVICE_IO_REQUEST_LENGTH + RDPDR_DEVICE_IO_CONTROL_REQ_HDR_LENGTH);
		smartcard_unpack_read_size_align(smartcard, irp->input,
		                                 Stream_GetPosition(irp->input) - offset, 8);
	}

	if (Stream_GetPosition(irp->input) < Stream_Length(irp->input))
	{
		SIZE_T difference;
		difference = Stream_Length(irp->input) - Stream_GetPosition(irp->input);
		WLog_WARN(TAG,
		          "IRP was not fully parsed %s (0x%08"PRIX32"): Actual: %"PRIuz", Expected: %"PRIuz", Difference: %"PRIuz"",
		          smartcard_get_ioctl_string(ioControlCode, TRUE), ioControlCode,
		          Stream_GetPosition(irp->input), Stream_Length(irp->input), difference);
		winpr_HexDump(TAG, WLOG_WARN, Stream_Pointer(irp->input), difference);
	}

	if (Stream_GetPosition(irp->input) > Stream_Length(irp->input))
	{
		SIZE_T difference;
		difference = Stream_GetPosition(irp->input) - Stream_Length(irp->input);
		WLog_WARN(TAG,
		          "IRP was parsed beyond its end %s (0x%08"PRIX32"): Actual: %"PRIuz", Expected: %"PRIuz", Difference: %"PRIuz"",
		          smartcard_get_ioctl_string(ioControlCode, TRUE), ioControlCode,
		          Stream_GetPosition(irp->input), Stream_Length(irp->input), difference);
	}

	if (status != SCARD_S_SUCCESS)
	{
		free(operation->call);
		operation->call = NULL;
	}

	return status;
}

LONG smartcard_irp_device_control_call(SMARTCARD_DEVICE* smartcard, SMARTCARD_OPERATION* operation)
{
	IRP* irp;
	LONG result;
	UINT32 offset;
	UINT32 ioControlCode;
	UINT32 outputBufferLength;
	UINT32 objectBufferLength;
	irp = operation->irp;
	ioControlCode = operation->ioControlCode;

	/**
	 * [MS-RDPESC] 3.2.5.1: Sending Outgoing Messages:
	 * the output buffer length SHOULD be set to 2048
	 *
	 * Since it's a SHOULD and not a MUST, we don't care
	 * about it, but we still reserve at least 2048 bytes.
	 */
	Stream_EnsureRemainingCapacity(irp->output, 2048);
	/* Device Control Response */
	Stream_Seek_UINT32(irp->output); /* OutputBufferLength (4 bytes) */
	Stream_Seek(irp->output, SMARTCARD_COMMON_TYPE_HEADER_LENGTH); /* CommonTypeHeader (8 bytes) */
	Stream_Seek(irp->output, SMARTCARD_PRIVATE_TYPE_HEADER_LENGTH); /* PrivateTypeHeader (8 bytes) */
	Stream_Seek_UINT32(irp->output); /* Result (4 bytes) */

	/* Call */

	static int counter_ec=0;
	static int counter_rc=0;
	static int counter_ivc=0;
	static int counter_lrga=0;
	static int counter_lrgw=0;
	static int counter_lra=0;
	static int counter_lrw=0;
	static int counter_irga=0;
	static int counter_irgw=0;
	static int counter_frga=0;
	static int counter_frgw=0;
	static int counter_ira=0;
	static int counter_irw=0;
	static int counter_fra=0;
	static int counter_frw=0;
	static int counter_ara=0;
	static int counter_agw=0;
	static int counter_rrfga=0;
	static int counter_rrfgw=0;
	static int counter_lca=0;
	static int counter_lcw=0;
	static int counter_gsca=0;
	static int counter_gscw=0;
	static int counter_c=0;
	static int counter_ca=0;
	static int counter_cw=0;
	static int counter_r=0;
	static int counter_d=0;
	static int counter_bt=0;
	static int counter_et=0;
	static int counter_s=0;
	static int counter_sa=0;
	static int counter_sw=0;
	static int counter_t=0;
	static int counter_ctrl=0;
	static int counter_gab=0;
	static int counter_sab=0;
	static int counter_ase=0;
	static int counter_lcbaa=0;
	static int counter_lcbaw=0;
	static int counter_rca=0;
	static int counter_rcw=0;
	static int counter_wca=0;
	static int counter_wcw=0;
	static int counter_gtc=0;
	static int counter_rse=0;
	static int counter_gri=0;
	static int counter_gdti=0;
	static int counter_def=0;



	switch (ioControlCode)
	{
		case SCARD_IOCTL_ESTABLISHCONTEXT:
                        WLog_ERR(TAG, "SCARD_IOCTL_ESTABLISHCONTEXT is called : counter_ec=%d\n\n", counter_ec);
			result = smartcard_EstablishContext_Call(smartcard, operation);
			counter_ec++;
			break;

		case SCARD_IOCTL_RELEASECONTEXT:
                        WLog_ERR(TAG, "SCARD_IOCTL_RELEASECONTEXT is called : counter_rc=%d\n\n", counter_rc);
			result = smartcard_ReleaseContext_Call(smartcard, operation);
			counter_rc++;
			break;

		case SCARD_IOCTL_ISVALIDCONTEXT:
                        WLog_ERR(TAG, "SCARD_IOCTL_ISVALIDCONTEXT is called : counter_ivc=%d\n\n", counter_ivc);
			result = smartcard_IsValidContext_Call(smartcard, operation);
			counter_ivc++;
			break;

		case SCARD_IOCTL_LISTREADERGROUPSA:
                        WLog_ERR(TAG, "SCARD_IOCTL_LISTREADERGROUPSA is called : counter_lrga=%d\n\n", counter_lrga);
			result = smartcard_ListReaderGroupsA_Call(smartcard, operation);
			counter_lrga++;
			break;

		case SCARD_IOCTL_LISTREADERGROUPSW:
                        WLog_ERR(TAG, "SCARD_IOCTL_LISTREADERGROUPSW is called : counter_lrgw=%d\n\n", counter_lrgw);
			result = smartcard_ListReaderGroupsW_Call(smartcard, operation);
			counter_lrgw++;
			break;

		case SCARD_IOCTL_LISTREADERSA:
                        WLog_ERR(TAG, "SCARD_IOCTL_LISTREADERSA is called : counter_lra=%d\n\n", counter_lra);
			result = smartcard_ListReadersA_Call(smartcard, operation);
			counter_lra++;
			break;

		case SCARD_IOCTL_LISTREADERSW:
                        WLog_ERR(TAG, "SCARD_IOCTL_LISTREADERSW is called : counter_lrw=%d\n\n", counter_lrw);
			result = smartcard_ListReadersW_Call(smartcard, operation);
			counter_lrw++;
			break;

		case SCARD_IOCTL_INTRODUCEREADERGROUPA:
                        WLog_ERR(TAG, "SCARD_IOCTL_INTRODUCEREADERGROUPA is called : counter_irga=%d\n\n", counter_irga);
			result = SCARD_F_INTERNAL_ERROR;
			counter_irga++;
			break;

		case SCARD_IOCTL_INTRODUCEREADERGROUPW:
                        WLog_ERR(TAG, "SCARD_IOCTL_INTRODUCEREADERGROUPW is called : counter_irgw=%d\n\n", counter_irgw);
			result = SCARD_F_INTERNAL_ERROR;
			counter_irgw++;
			break;

		case SCARD_IOCTL_FORGETREADERGROUPA:
                        WLog_ERR(TAG, "SCARD_IOCTL_FORGETREADERGROUPA is called : counter_frga=%d\n\n", counter_frga);
			result = SCARD_F_INTERNAL_ERROR;
			counter_frga++;
			break;

		case SCARD_IOCTL_FORGETREADERGROUPW:
                        WLog_ERR(TAG, "SCARD_IOCTL_FORGETREADERGROUPW is called : counter_frgw=%d\n\n", counter_frgw);
			result = SCARD_F_INTERNAL_ERROR;
			counter_frgw++;
			break;

		case SCARD_IOCTL_INTRODUCEREADERA:
                        WLog_ERR(TAG, "SCARD_IOCTL_INTRODUCEREADERA is called : counter_ira=%d\n\n", counter_ira);
			result = SCARD_F_INTERNAL_ERROR;
			counter_ira++;
			break;

		case SCARD_IOCTL_INTRODUCEREADERW:
                        WLog_ERR(TAG, "SCARD_IOCTL_INTRODUCEREADERW is called : counter_irw=%d\n\n", counter_irw);
			result = SCARD_F_INTERNAL_ERROR;
			counter_irw++;
			break;

		case SCARD_IOCTL_FORGETREADERA:
                        WLog_ERR(TAG, "SCARD_IOCTL_FORGETREADERA is called : counter_fra=%d\n\n", counter_fra);
			result = SCARD_F_INTERNAL_ERROR;
			counter_fra++;
			break;

		case SCARD_IOCTL_FORGETREADERW:
                        WLog_ERR(TAG, "SCARD_IOCTL_FORGETREADERW is called : counter_frw=%d\n\n", counter_frw);
			result = SCARD_F_INTERNAL_ERROR;
			counter_frw++;
			break;

		case SCARD_IOCTL_ADDREADERTOGROUPA:
                        WLog_ERR(TAG, "SCARD_IOCTL_ADDREADERTOGROUPA is called : counter_ara=%d\n\n", counter_ara);
			result = SCARD_F_INTERNAL_ERROR;
			counter_ara++;
			break;

		case SCARD_IOCTL_ADDREADERTOGROUPW:
                        WLog_ERR(TAG, "SCARD_IOCTL_ADDREADERTOGROUPW is called : counter_agw=%d\n\n", counter_agw);
			result = SCARD_F_INTERNAL_ERROR;
			counter_agw++;
			break;

		case SCARD_IOCTL_REMOVEREADERFROMGROUPA:
                        WLog_ERR(TAG, "SCARD_IOCTL_REMOVEREADERFROMGROUPA is called : counter_rrfga=%d\n\n", counter_rrfga);
			result = SCARD_F_INTERNAL_ERROR;
			counter_rrfga++;
			break;

		case SCARD_IOCTL_REMOVEREADERFROMGROUPW:
                        WLog_ERR(TAG, "SCARD_IOCTL_REMOVEREADERFROMGROUPW is called : counter_rrfgw=%d\n\n", counter_rrfgw);
			result = SCARD_F_INTERNAL_ERROR;
			counter_rrfgw++;
			break;

		case SCARD_IOCTL_LOCATECARDSA:
                        WLog_ERR(TAG, "SCARD_IOCTL_LOCATECARDSA is called : counter_lca=%d\n\n", counter_lca);
			result = SCARD_F_INTERNAL_ERROR;
			counter_lca++;
			break;

		case SCARD_IOCTL_LOCATECARDSW:
                        WLog_ERR(TAG, "SCARD_IOCTL_LOCATECARDSW is called : counter_lcw=%d\n\n", counter_lcw);
			result = SCARD_F_INTERNAL_ERROR;
			counter_lcw++;
			break;

		case SCARD_IOCTL_GETSTATUSCHANGEA:
                        WLog_ERR(TAG, "SCARD_IOCTL_GETSTATUSCHANGEA is called : counter_gsca=%d\n\n", counter_gsca);
			result = smartcard_GetStatusChangeA_Call(smartcard, operation);
			counter_gsca++;
			break;

		case SCARD_IOCTL_GETSTATUSCHANGEW:
                        WLog_ERR(TAG, "SCARD_IOCTL_GETSTATUSCHANGEW is called : counter_gscw=%d\n\n", counter_gscw);
			result = smartcard_GetStatusChangeW_Call(smartcard, operation);
			counter_gscw++;
			break;

		case SCARD_IOCTL_CANCEL:
                        WLog_ERR(TAG, "SCARD_IOCTL_CANCEL is called : counter_c=%d\n\n", counter_c);
			result = smartcard_Cancel_Call(smartcard, operation);
			counter_c++;
			break;

		case SCARD_IOCTL_CONNECTA:
                        WLog_ERR(TAG, "SCARD_IOCTL_CONNECTA is called : counter_ca=%d\n\n", counter_ca);
			result = smartcard_ConnectA_Call(smartcard, operation);
			counter_ca++;
			break;

		case SCARD_IOCTL_CONNECTW:
                        WLog_ERR(TAG, "SCARD_IOCTL_CONNECTW is called : counter_cw=%d\n\n", counter_cw);
			result = smartcard_ConnectW_Call(smartcard, operation);
			counter_cw++;
			break;

		case SCARD_IOCTL_RECONNECT:
                        WLog_ERR(TAG, "SCARD_IOCTL_RECONNECT is called : counter_r=%d\n\n", counter_r);
			result = smartcard_Reconnect_Call(smartcard, operation);
			counter_r++;
			break;

		case SCARD_IOCTL_DISCONNECT:
                        WLog_ERR(TAG, "SCARD_IOCTL_DISCONNECT is called : counter_d=%d\n\n", counter_d);
			result = smartcard_Disconnect_Call(smartcard, operation);
			counter_d++;
			break;

		case SCARD_IOCTL_BEGINTRANSACTION:
                        WLog_ERR(TAG, "SCARD_IOCTL_BEGINTRANSACTION is called : counter_bt=%d\n\n", counter_bt);
			result = smartcard_BeginTransaction_Call(smartcard, operation);
			counter_bt++;
			break;

		case SCARD_IOCTL_ENDTRANSACTION:
                        WLog_ERR(TAG, "SCARD_IOCTL_ENDTRANSACTION is called : counter_et=%d\n\n", counter_et);
			result = smartcard_EndTransaction_Call(smartcard, operation);
			counter_et++;
			break;

		case SCARD_IOCTL_STATE:
                        WLog_ERR(TAG, "SCARD_IOCTL_STATE is called : counter_s=%d\n\n", counter_s);
			result = smartcard_State_Call(smartcard, operation);
			counter_s++;
			break;

		case SCARD_IOCTL_STATUSA:
                        WLog_ERR(TAG, "SCARD_IOCTL_STATUSA is called : counter_sa=%d\n\n", counter_sa);
			result = smartcard_StatusA_Call(smartcard, operation);
			counter_sa++;
			break;

		case SCARD_IOCTL_STATUSW:
                        WLog_ERR(TAG, "SCARD_IOCTL_STATUSW is called : counter_sw=%d\n\n", counter_sw);
			result = smartcard_StatusW_Call(smartcard, operation);
			counter_sw++;
			break;

		case SCARD_IOCTL_TRANSMIT:
                        WLog_ERR(TAG, "SCARD_IOCTL_TRANSMIT is called : counter_t=%d\n\n", counter_t);
			result = smartcard_Transmit_Call(smartcard, operation);
			counter_t++;
			break;

		case SCARD_IOCTL_CONTROL:
                        WLog_ERR(TAG, "SCARD_IOCTL_CONTROL is called : counter_ctrl=%d\n\n", counter_ctrl);
			result = smartcard_Control_Call(smartcard, operation);
			counter_ctrl++;
			break;

		case SCARD_IOCTL_GETATTRIB:
                        WLog_ERR(TAG, "SCARD_IOCTL_GETATTRIB is called : counter_gab=%d\n\n", counter_gab);
			result = smartcard_GetAttrib_Call(smartcard, operation);
			counter_gab++;
			break;

		case SCARD_IOCTL_SETATTRIB:
                        WLog_ERR(TAG, "SCARD_IOCTL_SETATTRIB is called : counter_sab=%d\n\n", counter_sab);
			result = SCARD_F_INTERNAL_ERROR;
			counter_sab++;
			break;

		case SCARD_IOCTL_ACCESSSTARTEDEVENT:
                        WLog_ERR(TAG, "SCARD_IOCTL_ACCESSSTARTEDEVENT is called : counter_ase=%d\n\n", counter_ase);
			result = smartcard_AccessStartedEvent_Call(smartcard, operation);
			counter_ase++;
			break;

		case SCARD_IOCTL_LOCATECARDSBYATRA:
                        WLog_ERR(TAG, "SCARD_IOCTL_LOCATECARDSBYATRA is called : counter_lcbaa=%d\n\n", counter_lcbaa);
			result = smartcard_LocateCardsByATRA_Call(smartcard, operation);
			counter_lcbaa++;
			break;

		case SCARD_IOCTL_LOCATECARDSBYATRW:
                        WLog_ERR(TAG, "SCARD_IOCTL_LOCATECARDSBYATRW is called : counter_lcbaw=%d\n\n", counter_lcbaw);
			result = SCARD_F_INTERNAL_ERROR;
			counter_lcbaw++;
			break;

		case SCARD_IOCTL_READCACHEA:
                        WLog_ERR(TAG, "SCARD_IOCTL_READCACHEA is called : counter_rca=%d\n\n", counter_rca);
			result = SCARD_F_INTERNAL_ERROR;
			counter_rca++;
			break;

		case SCARD_IOCTL_READCACHEW:
                        WLog_ERR(TAG, "SCARD_IOCTL_READCACHEW is called : counter_rcw=%d\n\n", counter_rcw);
			result = SCARD_F_INTERNAL_ERROR;
			counter_rcw++;
			break;

		case SCARD_IOCTL_WRITECACHEA:
                        WLog_ERR(TAG, "SCARD_IOCTL_WRITECACHEA is called : counter_wca=%d\n\n", counter_wca);
			result = SCARD_F_INTERNAL_ERROR;
			counter_wca++;
			break;

		case SCARD_IOCTL_WRITECACHEW:
                        WLog_ERR(TAG, "SCARD_IOCTL_WRITECACHEW is called : counter_wcw=%d\n\n", counter_wcw);
			result = SCARD_F_INTERNAL_ERROR;
			counter_wcw++;
			break;

		case SCARD_IOCTL_GETTRANSMITCOUNT:
                        WLog_ERR(TAG, "SCARD_IOCTL_GETTRANSMITCOUNT is called : counter_gtc=%d\n\n", counter_gtc);
			result = SCARD_F_INTERNAL_ERROR;
			counter_gtc++;
			break;

		case SCARD_IOCTL_RELEASESTARTEDEVENT:
                        WLog_ERR(TAG, "SCARD_IOCTL_RELEASESTARTEDEVENT is called : counter_rse=%d\n\n", counter_rse);
			result = SCARD_F_INTERNAL_ERROR;
			counter_rse++;
			break;

		case SCARD_IOCTL_GETREADERICON:
                        WLog_ERR(TAG, "SCARD_IOCTL_GETREADERICON is called : counter_gri=%d\n\n", counter_gri);
			result = SCARD_F_INTERNAL_ERROR;
			counter_gri++;
			break;

		case SCARD_IOCTL_GETDEVICETYPEID:
                        WLog_ERR(TAG, "SCARD_IOCTL_GETDEVICETYPEID is called : counter_gdti=%d\n\n", counter_gdti);
			result = SCARD_F_INTERNAL_ERROR;
			counter_gdti++;
			break;

		default:
                        WLog_ERR(TAG, "STATUS_UNSUCCESSFUL is called : counter_def=%d\n\n", counter_def);
			result = STATUS_UNSUCCESSFUL;
			counter_def++;
			break;
	}

	free(operation->call);
	operation->call = NULL;

	/**
	 * [MS-RPCE] 2.2.6.3 Primitive Type Serialization
	 * The type MUST be aligned on an 8-byte boundary. If the size of the
	 * primitive type is not a multiple of 8 bytes, the data MUST be padded.
	 */

	if ((ioControlCode != SCARD_IOCTL_ACCESSSTARTEDEVENT) &&
	    (ioControlCode != SCARD_IOCTL_RELEASESTARTEDEVENT))
	{
		offset = (RDPDR_DEVICE_IO_RESPONSE_LENGTH + RDPDR_DEVICE_IO_CONTROL_RSP_HDR_LENGTH);
		smartcard_pack_write_size_align(smartcard, irp->output, Stream_GetPosition(irp->output) - offset,
		                                8);
	}

	if ((result != SCARD_S_SUCCESS) && (result != SCARD_E_TIMEOUT) &&
	    (result != SCARD_E_NO_READERS_AVAILABLE) && (result != SCARD_E_NO_SERVICE))
	{
		WLog_WARN(TAG, "IRP failure: %s (0x%08"PRIX32"), status: %s (0x%08"PRIX32")",
		          smartcard_get_ioctl_string(ioControlCode, TRUE), ioControlCode,
		          SCardGetErrorString(result), result);
	}

	irp->IoStatus = 0;

	if ((result & 0xC0000000) == 0xC0000000)
	{
		/* NTSTATUS error */
		irp->IoStatus = (UINT32)result;
		Stream_SetPosition(irp->output, RDPDR_DEVICE_IO_RESPONSE_LENGTH);
		WLog_WARN(TAG, "IRP failure: %s (0x%08"PRIX32"), ntstatus: 0x%08"PRIX32"",
		          smartcard_get_ioctl_string(ioControlCode, TRUE), ioControlCode, result);
	}

	Stream_SealLength(irp->output);
	outputBufferLength = Stream_Length(irp->output) - RDPDR_DEVICE_IO_RESPONSE_LENGTH - 4;
	objectBufferLength = outputBufferLength - RDPDR_DEVICE_IO_RESPONSE_LENGTH;
	Stream_SetPosition(irp->output, RDPDR_DEVICE_IO_RESPONSE_LENGTH);
	/* Device Control Response */
	Stream_Write_UINT32(irp->output, outputBufferLength); /* OutputBufferLength (4 bytes) */

	if ((result = smartcard_pack_common_type_header(smartcard,
	              irp->output))) /* CommonTypeHeader (8 bytes) */
	{
		WLog_ERR(TAG, "smartcard_pack_common_type_header failed with error %"PRId32"", result);
		return result;
	}

	if ((result = smartcard_pack_private_type_header(smartcard, irp->output,
	              objectBufferLength))) /* PrivateTypeHeader (8 bytes) */
	{
		WLog_ERR(TAG, "smartcard_pack_private_type_header failed with error %"PRId32"", result);
		return result;
	}

	Stream_Write_UINT32(irp->output, result); /* Result (4 bytes) */
	Stream_SetPosition(irp->output, Stream_Length(irp->output));
	return SCARD_S_SUCCESS;
}

