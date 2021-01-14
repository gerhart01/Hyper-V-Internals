#include "hv.h"
#include "distorm\src\decoder.h"

PVOID pWinHVOnInterruptOrig = NULL;
PVOID pHvlpInterruptCallbackOrig = NULL;
PVOID pSIMP[MAX_PROCESSOR_COUNT];
PVOID pSIEFP[MAX_PROCESSOR_COUNT];
PHV_MESSAGE hvMessage = NULL;

#ifndef IS_GUEST

int EnumActivePartitionID()
{
	HV_STATUS hvStatus;
	HV_PARTITION_ID PartID = 0xFF, NextPartID;
	HV_PARTITION_PROPERTY HvProp = 0;
	DbgPrintString("EnumActivePartitionID: ");
	hvStatus = WinHvGetPartitionId(&PartID);
	DbgLog("First PartID", PartID);
	hvStatus = WinHvGetNextChildPartition(PartID, HV_PARTITION_ID_INVALID, &NextPartID);
	DbgLog16("NextPartID", NextPartID);
	while ((NextPartID != HV_PARTITION_ID_INVALID) && (hvStatus == 0)) {
		//hvStatus = WinHvGetPartitionProperty(NextPartID,HvPartitionPropertyPrivilegeFlags,&HvProp);
		hvStatus = WinHvGetNextChildPartition(PartID, NextPartID, &NextPartID);
		if (NextPartID != 0) {
			DbgLog16("NextPartID", NextPartID);
		}
	}
	return 0;
}

int InitWinHV()
{
	//ULONG GPI;
	HV_PARTITION_ID PartID = 0xFF, NextPartID;
	HV_STATUS hvStatus;
	HV_NANO100_TIME	GlobalTime = 0, LocalRunTime = 0, HypervisorTime = 0, SomethingTime = 0;
	HV_PARTITION_PROPERTY HvProp = 0;
	hvStatus = WinHvGetPartitionId(&PartID);
	//GPI = (ULONG) KernelGetProcAddress(KernelGetModuleBase("winhv.sys"),"WinHvGetPartitionId");
	//DbgLog("WinHvGetPartitionId address",PartID);
	DbgLog("hvStatus", hvStatus);
	hvStatus = 0;
	//hvStatus = WinHvGetLogicalProcessorRunTime(&GlobalTime,&LocalRunTime,&HypervisorTime,&SomethingTime);
	//DbgLog16("GlobalTime",GlobalTime);
	//DbgLog16("LocalRunTime",LocalRunTime);
	//DbgLog16("HypervisorTime",HypervisorTime);
	//DbgLog16("SomethingTime",SomethingTime);
	//DbgLog("WinHvGetLogicalProcessorRunTime hvStatus",hvStatus);
	hvStatus = WinHvGetPartitionId(&PartID);
	DbgLog("PartID", PartID);
	hvStatus = WinHvGetPartitionProperty(PartID, HvPartitionPropertyPrivilegeFlags, &HvProp);
	DbgLog16("HvProp", HvProp);
	hvStatus = WinHvGetNextChildPartition(PartID, HV_PARTITION_ID_INVALID, &NextPartID);
	DbgLog("first WinHvGetNextChildPartition hvstatus", hvStatus);
	DbgLog16("NextPartID", NextPartID);
	while ((NextPartID != HV_PARTITION_ID_INVALID) && (hvStatus == 0)) {
		hvStatus = WinHvGetPartitionProperty(NextPartID, HvPartitionPropertyPrivilegeFlags, &HvProp);
		DbgLog16("HvProp", HvProp);
		hvStatus = WinHvGetNextChildPartition(PartID, NextPartID, &NextPartID);
		DbgLog("WinHvGetNextChildPartition hvstatus", hvStatus);
		DbgLog16("NextPartID", NextPartID);
	}
	//DbgLog("WinHvGetPartitionId hvStatus",hvStatus);
	//hvStatus = WinHvGetPartitionProperty(PartID,HvPartitionPropertyPrivilegeFlags,&HvProp);
	//DbgLog16("HvProp",HvProp);
	//DbgLog("WinHvGetPartitionProperty",hvStatus);
	//hvStatus = WinHvGetPartitionProperty(0x2,HvPartitionPropertyPrivilegeFlags,&HvProp);
	//DbgLog16("HvProp",HvProp);
	//DbgLog("WinHvGetPartitionProperty",hvStatus);
	//hvStatus = WinHvSetPartitionProperty(0x2,HvPartitionPropertyPrivilegeFlags,0x000008B000000EF0);
	//DbgLog("WinHvSetPartitionProperty",hvStatus);
	//hvStatus = WinHvGetPartitionProperty(0x2,HvPartitionPropertyPrivilegeFlags,&HvProp);
	//DbgLog16("HvProp",HvProp);
	//DbgLog("WinHvGetPartitionProperty",hvStatus);
	return 0;
}

int GetActivePartitionsId()
{
	UINT32 i, res = 0;
	for (i = 0x2; i <= 0x100; i++)
	{
		if (ARCH_VMCALL_REG_MOD(i) == 6)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "PartitionID %x \n", i, ARCH_VMCALL_REG_MOD(i));
			res = i;
		}
	}
	return res;
}

#endif // IS_GUEST



#ifndef IS_GUEST

int ConnectPort()
{
	//	HV_STATUS hvStatus;
	HV_CONNECTION_ID ConnectionID;
	HV_CONNECTION_INFO ConnectionInfo;
	HV_PORT_ID PortId;
	UINT32 i, j, param6 = 0;
	int cPID = GetActivePartitionsId(); //only for 1 active guest partition
	ConnectionID.Reserved = 0;
	ConnectionID.AsUint32 = 0;
	PortId.AsUint32 = 0;
	PortId.Reserved = 0;
	ConnectionInfo.MonitorConnectionInfo.MonitorAddress = 0xff;
	for (i = 0; i < 0x10; i++)
	{
		for (j = 0; j < 0x10; j++)
		{
			ConnectionID.Id = i;
			PortId.Id = j;
			//hvStatus = WinHvConnectPort(1, ConnectionID, cPID,PortId,(PHV_CONNECTION_INFO)&ConnectionInfo);
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"i = %x, j = %x, hvstatus = %x \n",i,j,hvStatus);
			//if (hvStatus != 0xd){
			//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"i = %x, hvstatus = %x",i,hvStatus);
			//}
		}
	}
	return 0;
}

int SetupInterception()
{
	HV_INTERCEPT_DESCRIPTOR Descriptor;
	HV_INTERCEPT_PARAMETERS Parameters = { 0 };
	HV_STATUS hvStatus = 0;
	Parameters.CpuidIndex = 0x11114444;
	Descriptor.Type = HvInterceptTypeX64Cpuid;
	Descriptor.Parameters = Parameters;
	hvStatus = WinHvInstallIntercept(0x3, HV_INTERCEPT_ACCESS_MASK_EXECUTE, &Descriptor);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "hvstatus of WinHvInstallIntercept = %x\n", hvStatus);
	hvStatus = WinHvInstallIntercept(0x2, HV_INTERCEPT_ACCESS_MASK_EXECUTE, &Descriptor);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "hvstatus of WinHvInstallIntercept = %x\n", hvStatus);
	hvStatus = WinHvInstallIntercept(0x4, HV_INTERCEPT_ACCESS_MASK_EXECUTE, &Descriptor);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "hvstatus of WinHvInstallIntercept = %x\n", hvStatus);
	hvStatus = WinHvInstallIntercept(0x5, HV_INTERCEPT_ACCESS_MASK_EXECUTE, &Descriptor);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "hvstatus of WinHvInstallIntercept = %x\n", hvStatus);
	return 0;
}

int FindHvlpInterruptCallback(unsigned char* buf)
{
	_DecodeResult res;
	_DInst adv_res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0, i, next;
	_DecodeType dt = Decode64Bits;
	const char* sMnemonicName = "LEA";
	const char* sOperandName = "R10";
	_CodeInfo ci;

	_OffsetType offset = 0;
	char* errch = NULL;

	int len = 100;
	for (;;) {
		res = distorm_decode64(offset, (const unsigned char*)buf, len, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
		if (res == DECRES_INPUTERR) {
			DbgPrint(("NULL Buffer?!\n"));
			break;
		}
		for (i = 0; i < decodedInstructionsCount; i++) {
			if (strstr((char*)decodedInstructions[i].mnemonic.p, (char*)sMnemonicName) && strstr((char*)decodedInstructions[i].operands.p, (char*)sOperandName)) {
				DbgPrint("%08I64x (%02d) %s %s %s\n", decodedInstructions[i].offset, decodedInstructions[i].size,
					(char*)decodedInstructions[i].instructionHex.p,
					(char*)decodedInstructions[i].mnemonic.p,
					(char*)decodedInstructions[i].operands.p);
				ci.codeOffset = offset;
				ci.code = (const unsigned char*)buf;
				ci.codeLen = len;
				ci.dt = dt;
				ci.features = DF_NONE;
				res = decode_internal(&ci, FALSE, &adv_res, MAX_INSTRUCTIONS, &decodedInstructionsCount);
				DbgLog("RIP-relative offset", adv_res.disp);
				//pHvlpInterruptCallbackOrig = (PVOID)((UINT64)buf+adv_res.disp+adv_res.size); //C4305
				pHvlpInterruptCallbackOrig = (PVOID)((size_t)(buf + adv_res.disp + adv_res.size));
				DbgLog16("pHvlpInterruptCallbackOrig address:", pHvlpInterruptCallbackOrig);
				//pWinHVOnInterruptOrig = (PVOID)*(PUINT64)pHvlpInterruptCallbackOrig;
				pWinHVOnInterruptOrig = (PVOID) * (PULONG_PTR)pHvlpInterruptCallbackOrig;
				DbgLog16("WinHvOnInterrupt address:", pWinHVOnInterruptOrig);
				return 0;
			}
		}

		if (res == DECRES_SUCCESS || decodedInstructionsCount == 0) {
			break; // All instructions were decoded.
		}

		// Synchronize:
		next = (unsigned int)(decodedInstructions[decodedInstructionsCount - 1].offset - offset);
		next += decodedInstructions[decodedInstructionsCount - 1].size;

		// Advance ptr and recalc offset.
		buf += next;
		len -= next;
		offset += next;
	}
	DbgPrintString("LEA R10 mnemonic not found!");
	return 1;
}

int FindWinHvOnInterrupt()
{
	ULONG i, ModuleCount;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;
	ULONG Len = 0;
	PVOID pBuffer;
	PVOID pWinHVModuleBase = NULL;
	const char* sDriverName = "winhv.sys";
	ZwQuerySystemInformation(SystemModuleInformation, &pSystemModuleInformation, 0, &Len);
	DbgLog("Length ", Len);
	pBuffer = MmAllocateNonCachedMemory(Len);
	DbgLog16("pBuffer ", pBuffer);
	if (!pBuffer)
	{
		DbgPrintString("WindowsGetDriverCodeSection. pBuffer allocation failed");
		return 1;
	}

	if (ZwQuerySystemInformation(SystemModuleInformation, pBuffer, Len, &Len)) {
		DbgPrintString("WindowsGetDriverCodeSection. ZwQuerySystemInformation failed");
		MmFreeNonCachedMemory(pBuffer, Len);
		return 1;
	}

	ModuleCount = *(UINT32*)pBuffer;
	DbgLog("ModuleCount ", ModuleCount);
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)((unsigned char*)pBuffer + sizeof(size_t));
	for (i = 0; i < ModuleCount; i++) {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"pSystemModuleInformation->ImageName = %s\n",pSystemModuleInformation->Module->ImageName);
		if (strstr(pSystemModuleInformation->Module->ImageName, sDriverName)) //driver name is case-sensitive
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "Driver found = %s\n", pSystemModuleInformation->Module->ImageName);
			pWinHVModuleBase = pSystemModuleInformation->Module->Base;
			pWinHVOnInterruptOrig = (unsigned char*)pWinHVModuleBase + WIN_HV_ON_INTERRUPT_OFFSET;
			DbgLog16("Base address is ", pWinHVOnInterruptOrig);
		}
		pSystemModuleInformation++;
	}
	MmFreeNonCachedMemory(pBuffer, Len);
	return 0;
}

int RegisterInterrupt()
{
	UNICODE_STRING     uniName;
	PVOID pvHvlRegisterAddress = NULL;
	PHYSICAL_ADDRESS pAdr = { 0 };
	ULONG i, ProcessorCount;
	ProcessorCount = KeQueryActiveProcessorCount(NULL);
	//DbgLog("Current processor number",KeGetCurrentProcessorNumberEx(NULL));
	DbgLog("Active processor count", ProcessorCount);
	//NTSTATUS nResult = STATUS_SUCCESS;
	RtlInitUnicodeString(&uniName, L"HvlRegisterInterruptCallback");
	pvHvlRegisterAddress = MmGetSystemRoutineAddress(&uniName);
	//FindWinHvOnInterrupt();
	if (pvHvlRegisterAddress == NULL) {
		DbgPrintString("Cannot find HvlRegisterInterruptCallback!");
		return 0;
	}
	DbgLog16("HvlRegisterInterruptCallback address ", pvHvlRegisterAddress);
	FindHvlpInterruptCallback((unsigned char*)pvHvlRegisterAddress);
	//__debugbreak();
	//nResult = HvlRegisterInterruptCallback(0,(UINT_PTR)&mWinHvOnInterrupt,0);
	ArchmHvlRegisterInterruptCallback((UINT64)&ArchmWinHvOnInterrupt, (UINT64)pHvlpInterruptCallbackOrig, 0);
	for (i = 0; i < ProcessorCount; i++) {
		KeSetSystemAffinityThreadEx(1i64 << i);
		DbgLog("Current processor number", KeGetCurrentProcessorNumberEx(NULL));
		pAdr.QuadPart = ArchReadMsr(HV_X64_MSR_SIMP) & 0xFFFFFFFFFFFFF000;
		pSIMP[i] = MmMapIoSpace(pAdr, PAGE_SIZE, MmCached);
		if (pSIMP[i] == NULL) {
			DbgPrintString("Error during pSIMP MmMapIoSpace");
			return 1;
		}
		DbgLog16("pSIMP[i] address", pSIMP[i]);
		pAdr.QuadPart = ArchReadMsr(HV_X64_MSR_SIEFP) & 0xFFFFFFFFFFFFF000;
		pSIEFP[i] = MmMapIoSpace(pAdr, PAGE_SIZE, MmCached);
		if (pSIMP[i] == NULL) {
			DbgPrintString("Error during pSIEFP MmMapIoSpace");
			return 1;
		}
		DbgLog16("pSIEFP  address", pSIEFP[i]);
	}
	return 0;
}

#endif // !IS_GUEST

void PrintIO_PORT_INTERCEPT_MESSAGE()
{
	PHV_X64_IO_PORT_INTERCEPT_MESSAGE phvIOPORT = (PHV_X64_IO_PORT_INTERCEPT_MESSAGE)hvMessage->Payload;
	//DbgLog("	phvIOPORT->Rax",phvIOPORT->Rax);
	//DbgLog16("phvIOPORT->InstructionBytes[0]",phvIOPORT->InstructionBytes0);
	//DbgLog16("phvIOPORT->InstructionBytes[1]",phvIOPORT->InstructionBytes1);
	//DbgLog("	phvIOPORT->PortNumber",phvIOPORT->PortNumber);
	//DbgLog("	phvIOPORT->Header.VpIndex",phvIOPORT->Header.VpIndex);
	//DbgLog16("	phvIOPORT->Header.Rip",phvIOPORT->Header.Rip);
	//DbgLog16("phvIOPORT->Header.Rflags",phvIOPORT->Header.Rflags);
	//DbgLog("	phvIOPORT->Header.ExecutionState.EferLma",phvIOPORT->Header.ExecutionState.EferLma);
	//DbgLog("	phvIOPORT->Header.InstructionLength",phvIOPORT->Header.InstructionLength);
	//DbgLog("	phvIOPORT->Header.InterceptAccessType",phvIOPORT->Header.InterceptAccessType);
	//DbgLog("	phvIOPORT->InstructionByteCount",phvIOPORT->InstructionByteCount);
}

void PrintCPUID_INTERCEPT_MESSAGE()
{
	PHV_X64_CPUID_INTERCEPT_MESSAGE phvCPUID = (PHV_X64_CPUID_INTERCEPT_MESSAGE)hvMessage->Payload;
	//for (i=0;i<0x1000000;i++){
//		j = phvCPUID->DefaultResultRdx ^ i;
//	}
//	if (phvCPUID->Rax == 0x11114444){
//		phvCPUID->DefaultResultRdx = 0x12345678;
//		DbgLog("Interception was made",j);
//	}
//	DbgLog("	phvCPUID->Rax",phvCPUID->Rax);
//	DbgLog("	phvCPUID->DefaultResultRax",phvCPUID->DefaultResultRax);
//	DbgLog("	phvCPUID->DefaultResultRbx",phvCPUID->DefaultResultRbx);
//	DbgLog("	phvCPUID->DefaultResultRcx",phvCPUID->DefaultResultRcx);
//	DbgLog("	phvCPUID->DefaultResultRdx",phvCPUID->DefaultResultRdx);
	if (phvCPUID->Rax == 0x11114444) {
		phvCPUID->DefaultResultRdx = 0x12345678;
		DbgLog("	phvCPUID->Header.Rip", phvCPUID->Header.Rip);
		DbgPrintString("Interception was made");
	}
}

void PrintMSR_INTERCEPT_MESSAGE()
{
	PHV_X64_MSR_INTERCEPT_MESSAGE phvMSR = (PHV_X64_MSR_INTERCEPT_MESSAGE)hvMessage->Payload;
	//DbgLog("	phvMSR->MsrNumber",phvMSR->MsrNumber);
}

void PrintEXCEPTION_INTERCEPT_MESSAGE()
{
	PHV_X64_EXCEPTION_INTERCEPT_MESSAGE phvExc = (PHV_X64_EXCEPTION_INTERCEPT_MESSAGE)hvMessage->Payload;
	//DbgLog("	phvExc->ErrorCode",phvExc->ErrorCode);
}

void ParseHvMessage()
{
	ULONG uCurProcNum = KeGetCurrentProcessorNumberEx(NULL);
	if (pSIMP[uCurProcNum] != NULL) {
		hvMessage = (PHV_MESSAGE)pSIMP[uCurProcNum];
	}
	else {
		DbgPrintString("pSIMP is NULL");
		return;
	}
	//DbgLog("hvMessage->Header.Port",hvMessage->Header.Port.Id);
	//DbgLog("hvMessage->Header.MessageType",hvMessage->Header.MessageType);
	//DbgLog("ParseHvMessage. Current processor number",uCurProcNum);
	switch (hvMessage->Header.MessageType)
	{
		case HvMessageTypeX64IoPortIntercept:
			PrintIO_PORT_INTERCEPT_MESSAGE();
			break;
		case HvMessageTypeNone:
			break;
		case HvMessageTypeUnmappedGpa:
			break;
		case HvMessageTypeGpaIntercept:
			break;
		case HvMessageTimerExpired:
			break;
		case HvMessageTypeInvalidVpRegisterValue:
			break;
		case HvMessageTypeUnrecoverableException:
			break;
		case HvMessageTypeUnsupportedFeature:
			break;
		case HvMessageTypeEventLogBufferComplete:
			break;
		case HvMessageTypeX64MsrIntercept:
			PrintMSR_INTERCEPT_MESSAGE();
			break;
		case HvMessageTypeX64CpuidIntercept:
			PrintCPUID_INTERCEPT_MESSAGE();
			break;
		case HvMessageTypeX64ExceptionIntercept:
			PrintEXCEPTION_INTERCEPT_MESSAGE();
			break;
		case HvMessageTypeX64ApicEoi:
			break;
		case HvMessageTypeX64LegacyFpError:
			break;
		default:
			DbgPrintString("Unknown MessageType");
			break;
	}
}