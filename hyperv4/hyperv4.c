#include "hyperv4.h"
#include "trace.h"
#include "hyperv4.tmh"


extern PVOID pvHvlpInterruptCallbackOrig;
extern PVOID pvWinHVOnInterruptOrig;
extern PVOID pvXPartEnlightenedIsrOrig;
extern BOOLEAN IsActivated;

NTSTATUS DeviceControlRoutine( IN PDEVICE_OBJECT fdo, IN PIRP Irp );
NTSTATUS Create_File_IRPprocessing(IN PDEVICE_OBJECT fdo, IN PIRP Irp);
NTSTATUS Close_HandleIRPprocessing(IN PDEVICE_OBJECT fdo, IN PIRP Irp);
NTSTATUS ReadWrite_IRPhandler(IN PDEVICE_OBJECT fdo, IN PIRP Irp);
VOID     UnloadRoutine(IN PDRIVER_OBJECT DriverObject);

KSPIN_LOCK MySpinLock;

NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject,
                      IN PUNICODE_STRING RegistryPath  )
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT  fdo;
	UNICODE_STRING  devName;
	PMY_DEVICE_EXTENSION dx;
	UNICODE_STRING symLinkName;

	DriverObject->DriverUnload = UnloadRoutine;
	DriverObject->MajorFunction[IRP_MJ_CREATE]= Create_File_IRPprocessing;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close_HandleIRPprocessing;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]= DeviceControlRoutine;
	DriverObject->MajorFunction[IRP_MJ_READ] = ReadWrite_IRPhandler;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = ReadWrite_IRPhandler;

	RtlInitUnicodeString( &devName, L"\\Device\\hyperv4" );

	status = IoCreateDevice(DriverObject,
                            sizeof(MY_DEVICE_EXTENSION),
                            &devName, 
                            FILE_DEVICE_UNKNOWN,
                            0,
                            FALSE, 
                            &fdo);
	if(!NT_SUCCESS(status)) return status;

	dx = (PMY_DEVICE_EXTENSION)fdo->DeviceExtension;
	dx->fdo = fdo;  

	#define   SYM_LINK_NAME   L"\\??\\hyperv4"

	RtlInitUnicodeString( &symLinkName, SYM_LINK_NAME );
	dx->ustrSymLinkName = symLinkName;
	
	status = IoCreateSymbolicLink( &symLinkName, &devName );
	if (!NT_SUCCESS(status))
	{ 
		IoDeleteDevice( fdo );
		return status;
    } 
	//WPP_INIT_TRACING(DriverObject, RegistryPath);
    return status;
}

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG info)
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	return status;
}

NTSTATUS ReadWrite_IRPhandler( IN PDEVICE_OBJECT fdo, IN PIRP Irp )
{
	ULONG BytesTxd = 0;
	NTSTATUS status = STATUS_SUCCESS; 
	return CompleteIrp(Irp,status,BytesTxd);
}

NTSTATUS Create_File_IRPprocessing(IN PDEVICE_OBJECT fdo,IN PIRP Irp)
{
	return CompleteIrp(Irp,STATUS_SUCCESS,0); 
}

NTSTATUS Close_HandleIRPprocessing(IN PDEVICE_OBJECT fdo,IN PIRP Irp)
{
	return CompleteIrp(Irp,STATUS_SUCCESS,0);
}

NTSTATUS DeviceControlRoutine( IN PDEVICE_OBJECT fdo, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG BytesTxd =0; 
	PIO_STACK_LOCATION IrpStack=IoGetCurrentIrpStackLocation(Irp);
	ULONG ControlCode =	IrpStack->Parameters.DeviceIoControl.IoControlCode;
	ULONG counter = 0;
	PVOID pHyperCallIn = NULL, pHyperCallOut = NULL;
	PHYSICAL_ADDRESS pHyperCallInPA, pHyperCallOutPA;

	DbgLog("IOCTL", ControlCode);
	switch(ControlCode) {	
	case INTERRUPT_CODE:
	{
		RegisterInterrupt();
		break;
	}
	case INTERCEPTION_CODE:
	{
		SetupIntercept();
		break;
	}
	case IOCTL_VMCALL:
	{     
		DbgLog("IOCTL_VMCALL",ControlCode);
		pHyperCallIn = MmAllocateNonCachedMemory(0x1000);
		if (pHyperCallIn == NULL) 
		{
			DbgPrintString("pHyperCallIn MmAllocateNonCachedMemory failed!");
			break;
		}
		pHyperCallOut = MmAllocateNonCachedMemory(0x1000);
		if (pHyperCallOut == NULL)
		{
			DbgPrintString("pHyperCallOut MmAllocateNonCachedMemory failed!");
			MmFreeNonCachedMemory(pHyperCallIn,0x1000);
			break;
		}
		pHyperCallInPA =  MmGetPhysicalAddress(pHyperCallIn);
		pHyperCallOutPA =  MmGetPhysicalAddress(pHyperCallOut);
		DbgLog16("pHyperCallInPA",pHyperCallInPA);
		DbgLog16("pHyperCallOutPA",pHyperCallOutPA);
		MmFreeNonCachedMemory(pHyperCallIn,0x1000);
		MmFreeNonCachedMemory(pHyperCallOut,0x1000);
		break;
	}
	default: status = STATUS_INVALID_DEVICE_REQUEST;
	}

return CompleteIrp(Irp,status,BytesTxd); 
}


VOID UnloadRoutine(IN PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT	pNextDevObj;
	int i;
	//WPP_CLEANUP(NULL);
	pNextDevObj = pDriverObject->DeviceObject;
	if ((pvWinHVOnInterruptOrig!= NULL) & (pvHvlpInterruptCallbackOrig!=NULL)){
		ArchmHvlRegisterInterruptCallback((uintptr_t)pvWinHVOnInterruptOrig, (uintptr_t)pvHvlpInterruptCallbackOrig, WIN_HV_ON_INTERRUPT_INDEX);
	}
	if ((pvXPartEnlightenedIsrOrig != NULL) & (pvHvlpInterruptCallbackOrig != NULL)){
		ArchmHvlRegisterInterruptCallback((uintptr_t)pvXPartEnlightenedIsrOrig, (uintptr_t)pvHvlpInterruptCallbackOrig, XPART_ENLIGHTENED_ISR0_INDEX);
		ArchmHvlRegisterInterruptCallback((uintptr_t)pvXPartEnlightenedIsrOrig, (uintptr_t)pvHvlpInterruptCallbackOrig, XPART_ENLIGHTENED_ISR1_INDEX);
		ArchmHvlRegisterInterruptCallback((uintptr_t)pvXPartEnlightenedIsrOrig, (uintptr_t)pvHvlpInterruptCallbackOrig, XPART_ENLIGHTENED_ISR2_INDEX);
		ArchmHvlRegisterInterruptCallback((uintptr_t)pvXPartEnlightenedIsrOrig, (uintptr_t)pvHvlpInterruptCallbackOrig, XPART_ENLIGHTENED_ISR3_INDEX);
	}
	IsActivated = FALSE;
	for(i=0; pNextDevObj!=NULL; i++)
	{
		PMY_DEVICE_EXTENSION dx =
				(PMY_DEVICE_EXTENSION)pNextDevObj->DeviceExtension;
		UNICODE_STRING *pLinkName = & (dx->ustrSymLinkName);
		pNextDevObj = pNextDevObj->NextDevice;
		IoDeleteSymbolicLink(pLinkName);
		IoDeleteDevice(dx->fdo);
	}
}