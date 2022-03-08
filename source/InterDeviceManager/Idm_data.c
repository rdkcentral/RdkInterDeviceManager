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

IDMMGR_CONFIG_DATA gpidmDmlInfo;

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

        pidmDmlInfo->stConnectionInfo.DetectionWindow = DEFAULT_DETECTION_WINDOW;

        // Initially the remote table will have a single entry with local device info
        pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries = 0;
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
    pthread_mutex_init(&(gpidmDmlInfo.mDataMutex), &(muttex_attr));
    return ANSC_STATUS_SUCCESS;
}

