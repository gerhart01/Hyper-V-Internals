#include "hv.h"

int SignalEvent()
{
	HV_STATUS hvStatus;
	HV_CONNECTION_ID ConnectionID;
	UINT16 FlagNumber = 1;
	UINT32 i;
	for (i = 0; i < 0x1000000; i++)
	{
		ConnectionID.Id = i;
		hvStatus = WinHvSignalEvent(ConnectionID, FlagNumber);
		if (hvStatus != 5) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "i = %x, hvstatus = %x", i, hvStatus);
		}
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "SignalEvent finished");
	return 0;
}

int PostMessage()
{
	HV_STATUS hvStatus;
	HV_CONNECTION_ID ConnectionID;
	HV_MESSAGE_TYPE MessageType = 1;
	UINT32 PayloadSize = 0x28;
	UINT16 FlagNumber = 1;
	//UINT32 i;
	PUINT32 pMessage;
	ConnectionID.Reserved = 0;
	ConnectionID.AsUint32 = 0;

	ConnectionID.Id = 1;
	pMessage = ExAllocatePoolWithTag(NonPagedPoolNx, PayloadSize, 0xAAAA);
	if (pMessage != NULL) {
		*pMessage = 0x15;
		//*(pMessage + 6) = 0xb1d00d3e;
		//*(pMessage + 7) = 0x4570fe10;
		//*(pMessage + 8) = 0x487662ad;
		//*(pMessage + 9) = 0x1b7a9d77;

		*(pMessage + 6) = 0x999e53d4;
		*(pMessage + 7) = 0x4c3e3d5c;
		*(pMessage + 8) = 0xd0be7987;
		*(pMessage + 9) = 0xe156c06e;
		//for (i = 0; i < 0xFFFFFFF; i++)
		//{	
		hvStatus = WinHvPostMessage(ConnectionID, MessageType, pMessage, PayloadSize);
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "i = %x, hvstatus = %x", i, hvStatus);
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "hvstatus = %x\n", hvStatus);
	//}
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "PostMessage finished \n");
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "ExAllocatePoolWithTag failed \n");
	}

	return 0;
}