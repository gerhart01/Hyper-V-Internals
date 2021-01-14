
//#define DBG 0

#include "ntddk.h"
#include "ioctl.h"

#define DBG_PRINT_LEVEL DPFLTR_ERROR_LEVEL
#define DbgLog(format, value) { DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"%-50s [%08X]\n", format, value ); } 
#define DbgLog16(format, value) { DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"%-50s [%016I64X]\n", format, value ); } 
#define DbgTraceLog(value) { DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"%08X:\n", value ); } 
#define DbgPrintString(value)  { DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"%s \n", value ); } 

typedef struct _EXAMPLE_DEVICE_EXTENSION
{
	PDEVICE_OBJECT	fdo;
	UNICODE_STRING	ustrSymLinkName; 
} EXAMPLE_DEVICE_EXTENSION, *PEXAMPLE_DEVICE_EXTENSION;




