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


#ifndef  _IDM_INTERNAL_H_
#define  _IDM_INTERNAL_H_

#include "inter_device_manager_plugin_main_apis.h"

#define  RDK_COMPONENT_ID_INTER_DEVICE_MANAGER                             "com.cisco.spvtg.ccsp.interdevicemanager"
#define  RDK_COMPONENT_NAME_INTER_DEVICE_MANAGER                           "com.cisco.spvtg.ccsp.interdevicemanager"
#define  RDK_COMPONENT_VERSION_INTER_DEVICE_MANAGER                        1
#define  RDK_COMPONENT_PATH_INTER_DEVICE_MANAGER                           "/com/cisco/spvtg/ccsp/interdevicemanager"

#define  RDK_COMMON_COMPONENT_HEALTH_Red                   1
#define  RDK_COMMON_COMPONENT_HEALTH_Yellow                2
#define  RDK_COMMON_COMPONENT_HEALTH_Green                 3

#define  RDK_COMMON_COMPONENT_STATE_Initializing           1
#define  RDK_COMMON_COMPONENT_STATE_Running                2
#define  RDK_COMMON_COMPONENT_STATE_Blocked                3
#define  RDK_COMMON_COMPONENT_STATE_Paused                 3

typedef  struct
_COMPONENT_COMMON_INTER_DEVICE_MANAGER
{
    char*                           Name;
    ULONG                           Version;
    char*                           Author;
    ULONG                           Health;
    ULONG                           State;

    BOOL                            LogEnable;
    ULONG                           LogLevel;

    ULONG                           MemMaxUsage;
    ULONG                           MemMinUsage;
    ULONG                           MemConsumed;

}
COMPONENT_COMMON_INTER_DEVICE_MANAGER, *PCOMPONENT_COMMON_INTER_DEVICE_MANAGER;

#define ComponentCommonDmInit(component_com_interdevicemanager)                                          \
        {                                                                                             \
            AnscZeroMemory(component_com_interdevicemanager, sizeof(COMPONENT_COMMON_INTER_DEVICE_MANAGER)); \
            component_com_interdevicemanager->Name        = NULL;                                        \
            component_com_interdevicemanager->Version     = 1;                                           \
            component_com_interdevicemanager->Author      = "SKY";                                        \
            component_com_interdevicemanager->Health      = RDK_COMMON_COMPONENT_HEALTH_Red;            \
            component_com_interdevicemanager->State       = RDK_COMMON_COMPONENT_STATE_Running;         \
            if(g_iTraceLevel >= CCSP_TRACE_LEVEL_EMERGENCY)                                           \
                component_com_interdevicemanager->LogLevel = (ULONG) g_iTraceLevel;                      \
            component_com_interdevicemanager->LogEnable   = TRUE;                                        \
            component_com_interdevicemanager->MemMaxUsage = 0;                                           \
            component_com_interdevicemanager->MemMinUsage = 0;                                           \
            component_com_interdevicemanager->MemConsumed = 0;                                           \
        }

ANSC_STATUS
InterDeviceManager_Init
(
);

ANSC_STATUS
InterDeviceManager_RegisterComponent
(
);

ANSC_STATUS
InterDeviceManager_Term
(
);


char*
InterDeviceManager_GetComponentName
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
InterDeviceManager_GetComponentVersion
    (
        ANSC_HANDLE                     hThisObject
    );

char*
InterDeviceManager_GetComponentAuthor
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
InterDeviceManager_GetComponentHealth
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
InterDeviceManager_GetComponentState
    (
        ANSC_HANDLE                     hThisObject
    );

BOOL
InterDeviceManager_GetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
InterDeviceManager_SetLoggingEnabled
    (
        ANSC_HANDLE                     hThisObject,
        BOOL                            bEnabled
    );

ULONG
InterDeviceManager_GetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
InterDeviceManager_SetLoggingLevel
    (
        ANSC_HANDLE                     hThisObject,
        ULONG                           LogLevel
    );

ULONG
InterDeviceManager_GetMemMaxUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
InterDeviceManager_GetMemMinUsage
    (
        ANSC_HANDLE                     hThisObject
    );

ULONG
InterDeviceManager_GetMemConsumed
    (
        ANSC_HANDLE                     hThisObject
    );

ANSC_STATUS
InterDeviceManager_ApplyChanges
    (
        ANSC_HANDLE                     hThisObject
    );

int
InterDeviceManager_DMLInit
(
    ULONG                       uMaxVersionSupported,
    void*                       hCosaPlugInfo
);
#endif
