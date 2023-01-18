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
/*
 * Copyright 2021 RDK Management
 * Licensed under the Apache License, Version 2.0
 */
#ifndef _IDM_DATA_H_
#define _IDM_DATA_H_

#include "Idm_rbus.h"

#define PSM_BROADCAST_INTERFACE_NAME      "dmsb.interdevicemanager.BroadcastInterface"
#define PSM_DEVICE_CAPABILITIES           "dmsb.interdevicemanager.Capabilities"
#define PSM_DEVICE_HELLO_INTERVAL         "dmsb.interdevicemanager.HelloInterval"
#define PSM_DEVICE_DETECION_WINDOW        "dmsb.interdevicemanager.DetectionWindow"
#define PSM_DEVICE_PORT                   "dmsb.interdevicemanager.BroadcastPort"
#define PSM_DEVICE_REMOTE_PORT            "dmsb.interdevicemanager.MessagingPort"


typedef struct _WANMGR_CONFIG_DATA_
{
    PIDM_DML_INFO           pidmDmlInfo;
    pthread_mutex_t         mDataMutex;
} IDMMGR_CONFIG_DATA;

PIDM_DML_INFO IdmMgr_GetConfigData_locked(void);

void IdmMgrDml_GetConfigData_release(PIDM_DML_INFO pidmDmlInfo);

void IdmMgr_SetConfigData_Default();

ANSC_STATUS IdmMgr_Data_Init(void);

int IdmMgr_write_IDM_ParametersToPSM();

ANSC_STATUS IdmMgr_GetFactoryDefaultValue(const char * param_name,char * param_value);
#endif
