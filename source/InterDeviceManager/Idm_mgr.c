/*------------------Include file---------------------------*/
#include "inter_device_manager_global.h"
#include "Idm_rbus.h"

/*-------------------declarations--------------------*/

/*-------------------Extern declarations--------------------*/

ANSC_STATUS Idm_Init()
{

    if(ANSC_STATUS_FAILURE == Idm_Rbus_Init())
    {
        return ANSC_STATUS_FAILURE;
    }       
    CcspTraceInfo(("%s %d - IDM Rbus initialisation success\n", __FUNCTION__, __LINE__)); 

    if(IDMMgr_Start_HeartBeat_Thread() == ANSC_STATUS_FAILURE)
    {
       CcspTraceInfo(("%s %d - IDM HeartBeat_Thread initialisation Failed\n", __FUNCTION__, __LINE__));
    }
    CcspTraceInfo(("%s %d - IDM HeartBeat_Thread initialisation success\n", __FUNCTION__, __LINE__));
    CcspTraceInfo(("%s %d - IDM initialisation success\n", __FUNCTION__, __LINE__)); 

    return ANSC_STATUS_SUCCESS;

}
