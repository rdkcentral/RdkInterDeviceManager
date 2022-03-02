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
#ifndef  _IDM_UTILS_H_
#define  _IDM_UTILS_H_

#include "Idm_rbus.h"

#define PSM_BROADCAST_INTERFACE_NAME      "dmsb.interdevicemanager.BroadcastInterface"
#define PSM_DEVICE_CAPABILITIES           "dmsb.interdevicemanager.Capabilities"

typedef enum _EVENT_DATA_TYPES
{
    EV_BOOLEAN = 1,
    EV_INTEGER,
    EV_STRING

}EVENT_DATA_TYPES;

ANSC_STATUS addDevice(IDM_REMOTE_DEVICE_LINK_INFO *newNode, IDM_DML_LINK_LIST *sidmDmlListInfo);

ANSC_STATUS updateDeviceStatus(IDM_DML_LINK_LIST *sidmDmlListInfo, uint32_t index, uint32_t newStatus);

EVENT_DATA_TYPES getEventType(char *event);

IDM_REMOTE_DEVICE_LINK_INFO* getRmDeviceNode(const IDM_DML_LINK_LIST sidmDmlListInfo, uint32_t index);

ANSC_STATUS updteSubscriptionStatus(char *event, IDM_RBUS_SUBS_STATUS *sidmRmSubStatus);

int IDMMgr_RdkBus_SetParamValuesToDB( char *pParamName, char *pParamVal );

int IDMMgr_RdkBus_GetParamValuesFromDB( char *pParamName, char *pReturnVal, int returnValLength );

ANSC_STATUS IDMMgr_UpdateLocalDeviceData(char *IP, char *mac);

#endif
