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
#include "Idm_data.h"
#include "Idm_call_back_apis.h"
/*-------------------declarations--------------------*/

/*-------------------Extern declarations--------------------*/
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
