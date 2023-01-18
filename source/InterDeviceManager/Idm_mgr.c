/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2022 Sky
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
    if(ANSC_STATUS_FAILURE == Idm_Rbus_Init())
    {
        return ANSC_STATUS_FAILURE;
    }       
    CcspTraceInfo(("%s %d - IDM Rbus initialisation success\n", __FUNCTION__, __LINE__)); 

    if(ANSC_STATUS_FAILURE == IdmMgr_Data_Init())
    {
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - IDM data initialisation success\n", __FUNCTION__, __LINE__));

    if(ANSC_STATUS_FAILURE == Idm_Rbus_DM_Init())
    {
        return ANSC_STATUS_FAILURE;
    }       
    CcspTraceInfo(("%s %d - IDM DM Registration success\n", __FUNCTION__, __LINE__)); 

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
