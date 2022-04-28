/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2021 RDK Management
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
/*
 * Copyright [2014] [Cisco Systems, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     LICENSE-2.0" target="_blank" rel="nofollow">http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Idm_data.h"

#define DEFAULT_SUBNET_LIST "255.255.255.0"
#define DEFAULT_HELLO_INTERVAL 10000 /* 10000 msec */
#define DEFAULT_DETECTION_WINDOW 30000 /* 30000 msec */
#define DEFAULT_BC_PORT 1234
#define DEFAULT_BC_INTF "br403"
#define DEFAULT_RM_PORT 4321

IDMMGR_CONFIG_DATA gpidmDmlInfo;

static int IdmMgr_get_IDM_ParametersFromPSM()
{
    int retPsmGet = CCSP_SUCCESS;
    char param_value[256];
    char param_name[512];

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_DEVICE_CAPABILITIES);

    retPsmGet = IDM_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    if (retPsmGet == CCSP_SUCCESS)
    {
        AnscCopyString(pidmDmlInfo->stConnectionInfo.Capabilities, param_value);
    }

    _ansc_memset(param_name, 0, sizeof(param_name));
    _ansc_memset(param_value, 0, sizeof(param_value));
    _ansc_sprintf(param_name, PSM_BROADCAST_INTERFACE_NAME);

    retPsmGet = IDM_RdkBus_GetParamValuesFromDB(param_name,param_value,sizeof(param_value));

    if (retPsmGet == CCSP_SUCCESS)
    {
        AnscCopyString(pidmDmlInfo->stConnectionInfo.Interface, param_value);
    }

    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    return retPsmGet;
}

PIDM_DML_INFO IdmMgr_GetConfigData_locked(void)
{
    //lock
    if(pthread_mutex_lock(&(gpidmDmlInfo.mDataMutex)) == 0)
    {
        return gpidmDmlInfo.pidmDmlInfo;
    }

    return NULL;
}

void IdmMgrDml_GetConfigData_release(PIDM_DML_INFO pidmDmlInfo)
{

    if(pidmDmlInfo != NULL)
    {
        pthread_mutex_unlock (&(gpidmDmlInfo.mDataMutex));
    }
}

void IdmMgr_SetConfigData_Default()
{
    PIDM_DML_INFO pidmDmlInfo = gpidmDmlInfo.pidmDmlInfo;

    if(pidmDmlInfo != NULL)
    { 
        CcspTraceInfo(("%s %d - Setting default value\n", __FUNCTION__, __LINE__ ));
        AnscZeroMemory(pidmDmlInfo, (sizeof(IDM_DML_INFO)));
        pidmDmlInfo->stConnectionInfo.HelloInterval = DEFAULT_HELLO_INTERVAL;

        strncpy(pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList, DEFAULT_SUBNET_LIST, sizeof(pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList));
        strncpy(pidmDmlInfo->stConnectionInfo.Interface, DEFAULT_BC_INTF, sizeof(pidmDmlInfo->stConnectionInfo.Interface));
        pidmDmlInfo->stConnectionInfo.DetectionWindow = DEFAULT_DETECTION_WINDOW;
        pidmDmlInfo->stConnectionInfo.Port = DEFAULT_BC_PORT;
        // Initially the remote table will have a single entry with local device info
        pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries = 0;
	pidmDmlInfo->stRemoteInfo.Port = DEFAULT_RM_PORT;
    }

}

ANSC_STATUS IdmMgr_Data_Init(void)
{
    pthread_mutexattr_t     muttex_attr;

    //Initialise mutex attributes
    pthread_mutexattr_init(&muttex_attr);
    pthread_mutexattr_settype(&muttex_attr, PTHREAD_MUTEX_RECURSIVE);

    /*** IDMMGR_CONFIG_DATA ***/
    gpidmDmlInfo.pidmDmlInfo = NULL;
    gpidmDmlInfo.pidmDmlInfo = (PIDM_DML_INFO)AnscAllocateMemory(sizeof(IDM_DML_INFO));

    IdmMgr_SetConfigData_Default();
    IdmMgr_get_IDM_ParametersFromPSM();
    pthread_mutex_init(&(gpidmDmlInfo.mDataMutex), &(muttex_attr));
    return ANSC_STATUS_SUCCESS;
}

