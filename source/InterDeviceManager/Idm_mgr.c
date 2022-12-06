/*------------------Include file---------------------------*/
#include "inter_device_manager_global.h"
#include "Idm_rbus.h"
#include "Idm_utils.h"
/*-------------------declarations--------------------*/

/*-------------------Extern declarations--------------------*/
#ifdef _HUB4_PRODUCT_REQ_
typedef struct
{
    char binaryLocation[64];
    char rbusName[64];
}Rbus_Module;

static void waitUntilSystemReady()
{
    int wait_time = 0;
    char pModule[1024] = {0};
    Rbus_Module pModuleNames[] = {{"/usr/bin/PsmSsp",    "rbusPsmSsp"}};

    int elementCnt = ARRAY_SZ(pModuleNames);
    for(int i=0; i<elementCnt;i++)
    {
        if (IsFileExists(pModuleNames[i].binaryLocation) == 0)
        {
            strcat(pModule,pModuleNames[i].rbusName);
            strcat(pModule," ");
        }
    }

    /* Check RBUS is ready. This needs to be continued upto 3 mins (180s) */
    while(wait_time <= 90)
    {
        if(Idm_Rbus_discover_components(pModule)){
            break;
        }

        wait_time++;
        sleep(2);
    }
}
#endif //_HUB4_PRODUCT_REQ_
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

#ifdef _HUB4_PRODUCT_REQ_
    waitUntilSystemReady();
#endif //_HUB4_PRODUCT_REQ_

    if(ANSC_STATUS_FAILURE == IDM_SyseventInit())
    {
        IDM_SyseventClose();
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - IDM sysevent initialisation success\n", __FUNCTION__, __LINE__));


    if(IDM_Start_Device_Discovery() == ANSC_STATUS_FAILURE)
    {
       CcspTraceInfo(("%s %d - IDM Device_Discovery initialisation Failed\n", __FUNCTION__, __LINE__));
    }
    CcspTraceInfo(("%s %d - IDM Device_Discovery initialisation success\n", __FUNCTION__, __LINE__));
    CcspTraceInfo(("%s %d - IDM initialisation success\n", __FUNCTION__, __LINE__)); 

    return ANSC_STATUS_SUCCESS;

}
