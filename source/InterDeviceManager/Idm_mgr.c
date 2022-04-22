/*------------------Include file---------------------------*/
#include "inter_device_manager_global.h"
#include "Idm_rbus.h"

/*-------------------declarations--------------------*/

/*-------------------Extern declarations--------------------*/

ANSC_STATUS Idm_Init()
{
    if(ANSC_STATUS_FAILURE == IdmMgr_Data_Init())
    {
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - IDM data initialisation success\n", __FUNCTION__, __LINE__));

    if(ANSC_STATUS_FAILURE == Idm_Rbus_Init())
    {
        return ANSC_STATUS_FAILURE;
    }       
    CcspTraceInfo(("%s %d - IDM Rbus initialisation success\n", __FUNCTION__, __LINE__)); 

    //TODO: Wait for mesh network
    if(IDMMgr_UpdateLocalDeviceData()== ANSC_STATUS_FAILURE)
    {
       CcspTraceInfo(("%s %d - IDM UpdateLocalDeviceData initialisation Failed\n", __FUNCTION__, __LINE__));
    }
    
    CcspTraceInfo(("%s %d - IDM UpdateLocalDeviceData success\n", __FUNCTION__, __LINE__));

    if(IDM_Start_Device_Discovery() == ANSC_STATUS_FAILURE)
    {
       CcspTraceInfo(("%s %d - IDM Device_Discovery initialisation Failed\n", __FUNCTION__, __LINE__));
    }
    CcspTraceInfo(("%s %d - IDM Device_Discovery initialisation success\n", __FUNCTION__, __LINE__));
    CcspTraceInfo(("%s %d - IDM initialisation success\n", __FUNCTION__, __LINE__)); 

    return ANSC_STATUS_SUCCESS;

}
