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

#ifndef _IDM_RBUS_H_
#define _IDM_RBUS_H_

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <rbus.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pthread.h>
#include "ansc_platform.h"
#include "inter_device_manager_internal.h"
#include "Idm_utils.h"
#include "ccsp_base_api.h"
#include "safec_lib_common.h"

#define RM_NUM_ENTRIES "Device.X_RDK_Remote.DeviceNumberOfEntries"

//Publish Parameters
#define DM_PUBLISH_REMOTE_DEVICE_STATUS "Device.X_RDK_Remote.Device.%d.Status"
#define DM_PUBLISH_REMOTE_DEVICE_CAP "Device.X_RDK_Remote.Device.%d.Capabilities"
#define DM_PUBLISH_REMOTE_DEVICE_MAC "Device.X_RDK_Remote.Device.%d.MAC"

//file transfer status
#define FT_STATUS_SIZE 24
#define FT_ERROR "FT_ERROR"
#define FT_SUCCESS "FT_SUCCESS"
#define FT_INVALID_SRC_PATH "FT_INVALID_SRC_PATH"
#define FT_INVALID_DST_PATH "FT_INVALID_DST_PATH"
#define FT_NOT_WRITABLE_PATH "FT_NOT_WRITABLE_PATH"
#define FT_INVALID_DST_MAC "FT_INVALID_DST_MAC"
#define FT_INVALID_FILE_SIZE "FT_INVALID_FILE_SIZE"
#define FT_NOT_FOUND "not found"
#define FT_INVALID_FILE_NAME "invalid file name"
#define FT_FILE_SIZE_EXCEED "file size exceed"
#define FT_START "start"
#define FT_INVALID_DST "invalid_dst"
#define FT_NVRAM "nvram"
#define FT_TMP "tmp"

typedef struct _DeviceChangeEvent {
    uint32_t     deviceIndex;
    char*        capability;
    char*        mac_addr;
    bool                       available;
} IDM_DeviceChangeEvent;

ANSC_STATUS Idm_Rbus_Init();
ANSC_STATUS Idm_Rbus_DM_Init();
ANSC_STATUS Idm_Rbus_Exit();

rbusError_t eventSubHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish);

rbusError_t X_RDK_Connection_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);

ANSC_STATUS Idm_PublishDmEvent(char *dm_event, void *dm_value);

ANSC_STATUS Idm_PublishDeviceChangeEvent(IDM_DeviceChangeEvent * pDeviceChangeEvent);

rbusError_t X_RDK_Remote_MethodHandler(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle);

rbusError_t idmDmPublishEventHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish);

rbusError_t X_RDK_Connection_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);

rbusError_t X_RDK_Connection_SetHandler(rbusHandle_t handle, rbusProperty_t prop, rbusSetHandlerOptions_t* opts);

rbusError_t X_RDK_Remote_Device_Status_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);
rbusError_t X_RDK_Remote_Device_Mac_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);

rbusError_t X_RDK_Remote_Device_Hello_Interval_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);

rbusError_t X_RDK_Remote_Device_Ipv4_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);

rbusError_t X_RDK_Remote_Device_Ipv6_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);

rbusError_t X_RDK_Remote_Device_Capabilities_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);

rbusError_t X_RDK_Remote_Device_Model_Number_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);

ANSC_STATUS Idm_Create_Rbus_Obj();

rbusError_t X_RDK_Connection_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);

rbusError_t X_RDK_Remote_Device_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts);

rbusError_t X_RDK_Remote_Device_SetHandler(rbusHandle_t handle, rbusProperty_t prop, rbusSetHandlerOptions_t* opts);
#ifdef _HUB4_PRODUCT_REQ_
BOOL Idm_Rbus_discover_components(char const *pModuleList);
#endif
#endif 


