#include "hv.h"

#ifndef IS_GUEST

int fHvConnectPort()
{
    //HV_STATUS hvStatus;
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
            //hvStatus = WinHvConnectPort(1, ConnectionID, cPID, PortId, (PHV_CONNECTION_INFO)&ConnectionInfo, param6);
            //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL, "i = %x, j = %x, hvstatus = %x \n", i, j, hvStatus);
            //if (hvStatus != 0xd){
            //	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DBG_PRINT_LEVEL,"i = %x, hvstatus = %x",i,hvStatus);
            //}
        }
    } 
    return 0;
}
#endif // !IS_GUEST