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

#include "Idm_rbus.h"
#include "Idm_msg_process.h"

#define CONN_HC_ELEMENTS   4
#define CONN_METHOD_ELEMENTS   3
#define RM_NEW_DEVICE_FOUND "Device.X_RDK_Remote.DeviceChange"
#define  ARRAY_SZ(x) (sizeof(x) / sizeof((x)[0]))

#define DM_CONN_HELLO_INTERVAL "Device.X_RDK_Connection.HelloInterval"
#define DM_CONN_HELLO_IPV4SUBNET_LIST "Device.X_RDK_Connection.HelloIPv4SubnetList"
#define DM_CONN_HELLO_IPV6SUBNET_LIST "Device.X_RDK_Connection.HelloIPv6SubnetList"
#define DM_CONN_DETECTION_WINDOW "Device.X_RDK_Connection.DetectionWindow"
#define DM_CONN_INTF "Device.X_RDK_Connection.Interface"
#define DM_CONN_PORT "Device.X_RDK_Connection.Port"

// table parameters
#define DM_REMOTE_DEVICE_TABLE "Device.X_RDK_Remote.Device" 
#define DM_REMOTE_DEVICE "Device.X_RDK_Remote.Device.{i}."
#define DM_REMOTE_DEVICE_STATUS "Device.X_RDK_Remote.Device.{i}.Status"
#define DM_REMOTE_DEVICE_MAC "Device.X_RDK_Remote.Device.{i}.MAC"
#define DM_REMOTE_DEVICE_HELLO_INTERVAL "Device.X_RDK_Remote.Device.{i}.HelloInterval"
#define DM_REMOTE_DEVICE_IPV4 "Device.X_RDK_Remote.Device.{i}.IPv4"
#define DM_REMOTE_DEVICE_IPV6 "Device.X_RDK_Remote.Device.{i}.IPv6"
#define DM_REMOTE_DEVICE_CAP "Device.X_RDK_Remote.Device.{i}.Capabilities"
#define DM_REMOTE_DEVICE_MODEL_NUM "Device.X_RDK_Remote.Device.{i}.ModelNumber"

#define DM_REMOTE_DEVICE_ADD_CAP "Device.X_RDK_Remote.AddDeviceCapabilities()"
#define DM_REMOTE_DEVICE_REM_CAP "Device.X_RDK_Remote.RemoveDeviceCapabilities()"
#define DM_REMOTE_DEVICE_RESET_CAP "Device.X_RDK_Remote.ResetDeviceCapabilities()"
#define DM_REMOTE_DEVICE_INVOKE "Device.X_RDK_Remote.Invoke()"

#define RM_NUM_ENTRIES "Device.X_RDK_Remote.DeviceNumberOfEntries"
#define RM_PORT "Device.X_RDK_Remote.Port"

rbusHandle_t        rbusHandle;
char                idmComponentName[32] = "IDM_RBUS";

// Instance for the global structure. This will be allocated and initialised by rbus
IDM_RBUS_SUBS_STATUS sidmRmSubStatus;

/**************************Array declarations for RBUS registrations************************/
rbusDataElement_t idmRmPublishElements[] = {
    {DM_REMOTE_DEVICE, RBUS_ELEMENT_TYPE_TABLE, {NULL, NULL, NULL, NULL, NULL, NULL}},
    {DM_REMOTE_DEVICE_STATUS, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_MAC, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_HELLO_INTERVAL, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_IPV4, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_IPV6, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_CAP, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {DM_REMOTE_DEVICE_MODEL_NUM, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {RM_NEW_DEVICE_FOUND, RBUS_ELEMENT_TYPE_EVENT, { NULL, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {RM_NUM_ENTRIES, RBUS_ELEMENT_TYPE_EVENT | RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, NULL, NULL, NULL, idmDmPublishEventHandler, NULL}},
    {RM_PORT, RBUS_ELEMENT_TYPE_PROPERTY, { X_RDK_Remote_Device_GetHandler, X_RDK_Remote_Device_SetHandler, NULL, NULL, NULL, NULL}}
};

//2. local data
rbusDataElement_t idmConnHcElements[] = {
    {DM_CONN_HELLO_INTERVAL, RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Connection_GetHandler, X_RDK_Connection_SetHandler, NULL, NULL, NULL, NULL}},
    {DM_CONN_HELLO_IPV4SUBNET_LIST, RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Connection_GetHandler, NULL, NULL, NULL, NULL, NULL}},
    {DM_CONN_HELLO_IPV6SUBNET_LIST, RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Connection_GetHandler, NULL, NULL, NULL, NULL, NULL}},
    {DM_CONN_DETECTION_WINDOW, RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Connection_GetHandler, X_RDK_Connection_SetHandler, NULL, NULL, NULL, NULL}},
    {DM_CONN_INTF, RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Connection_GetHandler, X_RDK_Connection_SetHandler, NULL, NULL, NULL, NULL}},
    {DM_CONN_PORT, RBUS_ELEMENT_TYPE_PROPERTY, {X_RDK_Connection_GetHandler, X_RDK_Connection_SetHandler, NULL, NULL, NULL, NULL}}
};

//3. Remote cap
rbusDataElement_t idmRmCapElements[] = {
        {DM_REMOTE_DEVICE_ADD_CAP, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}},
        {DM_REMOTE_DEVICE_REM_CAP, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}},
        {DM_REMOTE_DEVICE_RESET_CAP, RBUS_ELEMENT_TYPE_METHOD, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}},
	{DM_REMOTE_DEVICE_INVOKE, RBUS_ELEMENT_TYPE_METHOD | RBUS_ELEMENT_TYPE_EVENT, {NULL, NULL, NULL, NULL, NULL, X_RDK_Remote_MethodHandler}}
    };

ANSC_STATUS Idm_Create_Rbus_Obj()
{
    ANSC_STATUS returnStatus   =  ANSC_STATUS_SUCCESS;
    IDM_REMOTE_DEVICE_LINK_INFO *firstNode = NULL;

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }

    // first node
    firstNode = (IDM_REMOTE_DEVICE_LINK_INFO*)AnscAllocateMemory(sizeof(IDM_REMOTE_DEVICE_LINK_INFO));

    if( firstNode == NULL )
    {
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return  ANSC_STATUS_FAILURE;
    }

    AnscZeroMemory(firstNode, (sizeof(IDM_REMOTE_DEVICE_LINK_INFO)));

    firstNode->stRemoteDeviceInfo.Status = DEVICE_CONNECTED;

    // TODO: Get device Mac
    //getDeviceMac(firstNode->MAC);
   
    //fill local data in remote table 
    firstNode->stRemoteDeviceInfo.HelloInterval = pidmDmlInfo->stConnectionInfo.HelloInterval;
    firstNode->stRemoteDeviceInfo.Index = 0;
    if(pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList[0] != '\0')
        strncpy(firstNode->stRemoteDeviceInfo.IPv4, pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList,sizeof(firstNode->stRemoteDeviceInfo.IPv4));
    if(pidmDmlInfo->stConnectionInfo.HelloIPv6SubnetList[0] != '\0')
        strncpy(firstNode->stRemoteDeviceInfo.IPv6, pidmDmlInfo->stConnectionInfo.HelloIPv6SubnetList,sizeof(firstNode->stRemoteDeviceInfo.IPv6));

    // TODO: Get device cap
    //getDeviceCap(firstNode->Capabilities);
    pidmDmlInfo->stRemoteInfo.pstDeviceLink = firstNode;
    pidmDmlInfo->stRemoteInfo.pstDeviceLink->next = NULL;

    firstNode->stRemoteDeviceInfo.Index = 1;
    returnStatus = addDevice(firstNode);

    if(returnStatus == ANSC_STATUS_SUCCESS)
    {
        pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries++;
        CcspTraceInfo(("%s %d - Number of entries : %d\n", __FUNCTION__, __LINE__,
                                        pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries));
    }
    else
    {
        CcspTraceInfo(("%s %d - Add device failed : %d\n", __FUNCTION__, __LINE__));
    }

    // Register a row for the table such that it will be populated. 
    // This should be repeated whenever we added a new device
    rbusTable_registerRow(rbusHandle, DM_REMOTE_DEVICE_TABLE, 
                        pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries, NULL);

    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return  returnStatus;
}

//TODO : idm manager should call this function
ANSC_STATUS Idm_Rbus_Init()
{
    rbusError_t rc;

    rc = rbus_open(&rbusHandle, idmComponentName);

    if(rc != RBUS_ERROR_SUCCESS)
        return ANSC_STATUS_FAILURE;

    // 1. Register publish events
    rc = rbus_regDataElements(rbusHandle, ARRAY_SZ(idmRmPublishElements), idmRmPublishElements);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        rbus_close(rbusHandle);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully registered  idmRmPublishElements\n", __FUNCTION__, __LINE__ ));

    // 2. Register local data info
    rc = rbus_regDataElements(rbusHandle, ARRAY_SZ(idmConnHcElements), idmConnHcElements);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        rbus_unregDataElements(rbusHandle, idmRmPublishElements, idmRmPublishElements);
        rbus_close(rbusHandle);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully registered  idmConnHcElements\n", __FUNCTION__, __LINE__ ));

    // 3. Register remote cap info
    rc = rbus_regDataElements(rbusHandle, ARRAY_SZ(idmRmCapElements), idmRmCapElements);

    if(rc != RBUS_ERROR_SUCCESS)
    {
        rbus_unregDataElements(rbusHandle, idmRmPublishElements, idmRmPublishElements);
        rbus_unregDataElements(rbusHandle, idmConnHcElements, idmConnHcElements);
        rbus_close(rbusHandle);
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully registered  idmRmCapElements\n", __FUNCTION__, __LINE__ ));

    rc = Idm_Create_Rbus_Obj();
   
 
#ifdef TEST_RBUS_EVENT
#if 0
    int i = 0;
    for( i = 1 ; i < 10 ; i++)
    {
        rbusTable_registerRow(rbusHandle, "Device.X_RDK_Remote.Device", NULL, i++);
        if(rc != RBUS_ERROR_SUCCESS)
        {
            CcspTraceInfo(("%s %d - created table row %d \n", __FUNCTION__, __LINE__, i ));
        }
    }
#endif
    Idm_RunEventTest();
#endif
    return rc;    
}

//idm manager can call this during idm graceful exit
ANSC_STATUS Idm_RbusExit()
{
    rbus_unregDataElements(rbusHandle, idmRmPublishElements, idmRmPublishElements);
    rbus_unregDataElements(rbusHandle, idmConnHcElements, idmConnHcElements);
    rbus_unregDataElements(rbusHandle, idmRmCapElements, idmRmCapElements);
    rbus_close(rbusHandle);
    return ANSC_STATUS_SUCCESS;
}

rbusError_t idmDmPublishEventHandler(rbusHandle_t handle, rbusEventSubAction_t action, const char* eventName, rbusFilter_t filter, int32_t interval, bool* autoPublish)
{
    char *subscribe_action = NULL;

    CcspTraceInfo(("%s %d - Event %s has been subscribed from subscribed\n", __FUNCTION__, __LINE__,eventName ));
    subscribe_action = action == RBUS_EVENT_ACTION_SUBSCRIBE ? "subscribe" : "unsubscribe";
    CcspTraceInfo(("%s %d - action=%s \n", __FUNCTION__, __LINE__, subscribe_action ));
    updteSubscriptionStatus(eventName, &sidmRmSubStatus);
    return RBUS_ERROR_SUCCESS;
}

//IDM manager should call when it has remote device data
ANSC_STATUS Idm_PublishDmEvent(char *dm_event, void *dm_value, uint32_t wait_time)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;
    uint32_t timeout = 0; // wait for 2 minutes

    if(dm_event == NULL || dm_value == NULL)
    {
        CcspTraceInfo(("%s %d - Failed publishing\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    while(timeout < wait_time)
    {
        timeout ++;
        sleep(1);
        CcspTraceInfo(("%s %d - Waiting for subscription %s.......\n", __FUNCTION__, __LINE__,dm_event));
        if(sidmRmSubStatus.idmRmStatusSubscribed == TRUE)
            break;
    }

    rbusValue_Init(&value);
    rbusObject_Init(&rdata, NULL);

    rbusObject_SetValue(rdata, dm_event, value);

    EVENT_DATA_TYPES type = getEventType(dm_event);

    CcspTraceInfo(("%s %d - event type %d\n", __FUNCTION__, __LINE__, type));
    switch(type)
    {
        case EV_BOOLEAN:
            rbusValue_SetBoolean(value, (*(bool*)(dm_value)));
            break;
        case EV_INTEGER:
            rbusValue_SetInt32(value, (*(int*)(dm_value)));
            break;
        case EV_STRING:
            rbusValue_SetString(value, (char*)dm_value);
            break;
        default:
            CcspTraceInfo(("%s %d - Cannot identify event type %d\n", __FUNCTION__, __LINE__, type));
            return ANSC_STATUS_FAILURE;
    }
    event.name = dm_event;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;
    if(rbusEvent_Publish(rbusHandle, &event) != RBUS_ERROR_SUCCESS) {
        CcspTraceInfo(("%s %d - event pusblishing failed for type %d\n", __FUNCTION__, __LINE__, type));
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully Pusblished event for event %s \n", __FUNCTION__, __LINE__, dm_event));
    rbusValue_Release(value);
    rbusObject_Release(rdata);

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS Idm_PublishDeviceChangeEvent(IDM_DeviceChangeEvent * pDeviceChangeEvent)
{
    rbusEvent_t event;
    rbusObject_t rdata;
    rbusValue_t value;

    if(pDeviceChangeEvent == NULL || pDeviceChangeEvent->deviceIndex <= 1)
    {
        CcspTraceInfo(("%s %d: Invalid args\n", __FUNCTION__, __LINE__)); 
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d: Enter\n", __FUNCTION__, __LINE__));

    if(sidmRmSubStatus.idmRmNewDeviceSubscribed == FALSE)
    {
        CcspTraceInfo(("%s %d - New device sucbscription wait time excceded.......\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    rbusObject_Init(&rdata, NULL);
    if (pDeviceChangeEvent->capability != NULL)
    {
        rbusValue_Init(&value);
        rbusValue_SetString(value, pDeviceChangeEvent->capability);
        rbusObject_SetValue(rdata, "Capabilities", value);
        rbusValue_Release(value);
    }

    rbusValue_Init(&value);
    rbusValue_SetUInt32(value, pDeviceChangeEvent->deviceIndex);
    rbusObject_SetValue(rdata, "Index", value);
    rbusValue_Release(value);

    /*set source mac */
    rbusValue_Init(&value);
    rbusValue_SetString(value, pDeviceChangeEvent->mac_addr);
    rbusObject_SetValue(rdata, "Mac_addr", value);
    rbusValue_Release(value);

    rbusValue_Init(&value);
    rbusValue_SetBoolean(value, pDeviceChangeEvent->available);
    rbusObject_SetValue(rdata, "available", value);
    rbusValue_Release(value);


    event.name = RM_NEW_DEVICE_FOUND;
    event.data = rdata;
    event.type = RBUS_EVENT_GENERAL;

    if (rbusEvent_Publish(rbusHandle, &event) != RBUS_ERROR_SUCCESS) {
        return ANSC_STATUS_FAILURE;
    }
    CcspTraceInfo(("%s %d - Successfully Pusblished new device event RM_NEW_DEVICE_FOUND\n", __FUNCTION__, __LINE__));
    rbusObject_Release(rdata);

    return ANSC_STATUS_SUCCESS;
}

/***********************************************Get handler************************/
rbusError_t X_RDK_Remote_Device_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    char const* name = rbusProperty_GetName(property);
    IDM_REMOTE_DEVICE_LINK_INFO *index_node = NULL;
    rbusValue_t value;
    uint32_t index = 0;

    rbusValue_Init(&value);

     PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
     if( pidmDmlInfo == NULL )
     {
         return  ANSC_STATUS_FAILURE;
     }

    if(name == NULL)
    {
        CcspTraceInfo(("%s %d - Property get name is NULL\n", __FUNCTION__, __LINE__));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return RBUS_ERROR_BUS_ERROR;   
    }

    if(strstr(name, ".Status"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.Status", &index);
        // get node from index
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetUInt32(value, index_node->stRemoteDeviceInfo.Status);
    }
    if(strstr(name, ".HelloInterval"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.HelloInterval", &index);
        // get node from index
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;
        }
        rbusValue_SetUInt32(value, index_node->stRemoteDeviceInfo.HelloInterval);
    }
    if(strstr(name, ".MAC"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.MAC", &index);
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetString(value, index_node->stRemoteDeviceInfo.MAC);
    }
    if(strstr(name, ".IPv4"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.IPv4", &index);
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetString(value, index_node->stRemoteDeviceInfo.IPv4);
    }
    if(strstr(name, ".IPv6"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.IPv6", &index);
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetString(value, index_node->stRemoteDeviceInfo.IPv6);
    }
    if(strstr(name, ".Capabilities"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.Capabilities", &index);
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetString(value, index_node->stRemoteDeviceInfo.Capabilities);
    }
    if(strstr(name, ".ModelNumber"))
    {
        sscanf(name, "Device.X_RDK_Remote.Device.%d.ModelNumber", &index);
        index_node = getRmDeviceNode(pidmDmlInfo, index);
        if(index_node == NULL)
        {
            CcspTraceInfo(("%s %d - index node for %d is NULL\n", __FUNCTION__, __LINE__, index));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;   
        }
        rbusValue_SetString(value, index_node->stRemoteDeviceInfo.ModelNumber);
    }

    if(strcmp(name, RM_NUM_ENTRIES) == 0)
    {
        if(pidmDmlInfo == NULL)
        {
            CcspTraceInfo(("%s %d - Failed to get number of entries\n", __FUNCTION__, __LINE__));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;   
        }
        
        rbusValue_SetUInt32(value, pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries);
        CcspTraceInfo(("%s %d - Number of entries:%d\n", __FUNCTION__, __LINE__, 
                            pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries));
    }
    else if (strcmp(name, RM_PORT) == 0)
    {
        if(pidmDmlInfo == NULL)
        {
            CcspTraceInfo(("%s %d - Failed to get remote port\n", __FUNCTION__, __LINE__));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;
        }

        rbusValue_SetUInt32(value, pidmDmlInfo->stRemoteInfo.Port);
        CcspTraceInfo(("%s %d - Port :%d\n", __FUNCTION__, __LINE__,
                            pidmDmlInfo->stRemoteInfo.Port));
    }

    rbusProperty_SetValue(property, value);

    rbusValue_Release(value);
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    return RBUS_ERROR_SUCCESS;
}

/****************************************Cap handler**********************************/
rbusError_t X_RDK_Remote_MethodHandler(rbusHandle_t handle, char const* methodName, rbusObject_t inParams, rbusObject_t outParams, rbusMethodAsyncHandle_t asyncHandle)
{
    IDM_REMOTE_DEVICE_LINK_INFO* indexNode = NULL;
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }

    if(strcmp(methodName, "Device.X_RDK_Remote.AddDeviceCapabilities()") == 0)
    {
        char *str = NULL;
        uint32_t len = 0;

        rbusValue_t value = rbusObject_GetValue(inParams, NULL );

        str = rbusValue_GetString(value, &len);

        indexNode = getRmDeviceNode(pidmDmlInfo, 1);

        if(!indexNode || (strlen(str) < 0))
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;
        }
    
        if(!strstr(indexNode->stRemoteDeviceInfo.Capabilities, str))
        {
            if (strlen(indexNode->stRemoteDeviceInfo.Capabilities) > 0)
            {
                strcat(indexNode->stRemoteDeviceInfo.Capabilities, ",");
            }
            strcat(indexNode->stRemoteDeviceInfo.Capabilities, str);        
        }
        strncpy(pidmDmlInfo->stConnectionInfo.Capabilities, indexNode->stRemoteDeviceInfo.Capabilities, sizeof(pidmDmlInfo->stConnectionInfo.Capabilities));
        CcspTraceInfo(("%s %d: DeviceCapabilities str = %s\n", __FUNCTION__, __LINE__, indexNode->stRemoteDeviceInfo.Capabilities));
        
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);

        IDM_Broadcast_LocalDeviceInfo();
        IdmMgr_write_IDM_ParametersToPSM();
        return RBUS_ERROR_SUCCESS;
    }
    else if(strcmp(methodName, "Device.X_RDK_Remote.RemoveDeviceCapabilities()") == 0)
    {
        const char *out = NULL;
        char *capPos = NULL;
        uint32_t len = 0;

        rbusValue_t value = rbusObject_GetValue(inParams, NULL );
        out = rbusValue_GetString(value, &len);

        indexNode = getRmDeviceNode(pidmDmlInfo, 1);

        if(!indexNode || len < 0)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;
        }

        char * arr = indexNode->stRemoteDeviceInfo.Capabilities;

        capPos = strstr(arr, out);
        if(capPos)
        {
            if (*(capPos + strlen(out)) == '\0')
            {
                // removing last capability, so set null char
                *capPos = '\0';
                if (strlen(arr) > 0)
                {
                    // removing last ; char
                    *(capPos - 1) = '\0';
            }
                CcspTraceInfo(("%s %d: AddDeviceCapabilities str = %s\n", __FUNCTION__, __LINE__, indexNode->stRemoteDeviceInfo.Capabilities));
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return RBUS_ERROR_SUCCESS;
            }
            strcpy(capPos, capPos + (strlen(out) + 1));
        }

        strncpy(pidmDmlInfo->stConnectionInfo.Capabilities, indexNode->stRemoteDeviceInfo.Capabilities, sizeof(pidmDmlInfo->stConnectionInfo.Capabilities));
        CcspTraceInfo(("%s %d: DeviceCapabilities str = %s\n", __FUNCTION__, __LINE__, indexNode->stRemoteDeviceInfo.Capabilities));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        IDM_Broadcast_LocalDeviceInfo();
        IdmMgr_write_IDM_ParametersToPSM();
        return RBUS_ERROR_SUCCESS;
    }
    else if(strcmp(methodName, "Device.X_RDK_Remote.ResetDeviceCapabilities()") == 0)
    {
         const char *str = NULL;
        uint32_t len = 0;

        rbusValue_t value = rbusObject_GetValue(inParams, NULL );

        str = rbusValue_GetString(value, &len);

        indexNode = getRmDeviceNode( pidmDmlInfo, 1);

        if(!indexNode)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_BUS_ERROR;
        }
        memset(indexNode->stRemoteDeviceInfo.Capabilities, 0, sizeof(indexNode->stRemoteDeviceInfo.Capabilities));
        /* TODO: Get default capability list and store it in node*/
        strncpy(pidmDmlInfo->stConnectionInfo.Capabilities, indexNode->stRemoteDeviceInfo.Capabilities, sizeof(pidmDmlInfo->stConnectionInfo.Capabilities));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        IDM_Broadcast_LocalDeviceInfo();
        IdmMgr_write_IDM_ParametersToPSM();
        return RBUS_ERROR_SUCCESS;
    }
    else if(strcmp(methodName, "Device.X_RDK_Remote.Invoke()") == 0)
    {
        CcspTraceInfo(("%s %d - Device.X_RDK_Remote.Invoke() called  \n", __FUNCTION__, __LINE__));
        uint32_t len = 0;
        rbusValue_t value;

        idm_send_msg_Params_t param;
        memset(&param,0,sizeof(param));

        value = rbusObject_GetValue(inParams, "DEST_MAC_ADDR");
        strncpy(param.Mac_dest, rbusValue_GetString(value, NULL),MAC_ADDR_SIZE);
        CcspTraceInfo(("%s %d - param.Mac_dest %s\n", __FUNCTION__, __LINE__,param.Mac_dest));

        value = rbusObject_GetValue(inParams, "paramName");
        strncpy(param.param_name, rbusValue_GetString(value, NULL),sizeof(param.param_name));
        CcspTraceInfo(("%s %d - param.param_name %s\n", __FUNCTION__, __LINE__,param.param_name));

        value = rbusObject_GetValue(inParams, "paramValue");
        strncpy(param.param_value, rbusValue_GetString(value, NULL),sizeof(param.param_value));
        CcspTraceInfo(("%s %d - param.param_value %s\n", __FUNCTION__, __LINE__,param.param_value));

        value = rbusObject_GetValue(inParams, "pComponent");
        strncpy(param.pComponent_name, rbusValue_GetString(value, NULL),sizeof(param.pComponent_name));
        CcspTraceInfo(("%s %d - param. %s\n", __FUNCTION__, __LINE__,param.pComponent_name));

        value = rbusObject_GetValue(inParams, "pBus");
        strncpy(param.pBus_path, rbusValue_GetString(value, NULL),sizeof(param.pBus_path));
        CcspTraceInfo(("%s %d - param. %s\n", __FUNCTION__, __LINE__,param.pBus_path));

        value = rbusObject_GetValue(inParams, "Timeout");
        param.timeout = rbusValue_GetInt32(value);
        CcspTraceInfo(("%s %d - param. %d\n", __FUNCTION__, __LINE__,param.timeout));

        value = rbusObject_GetValue(inParams, "DataType");
        param.type = rbusValue_GetInt32(value);
        CcspTraceInfo(("%s %d - param. %d\n", __FUNCTION__, __LINE__,param.type));

        value = rbusObject_GetValue(inParams, "Operation");
        param.operation = rbusValue_GetInt32(value);
        CcspTraceInfo(("%s %d - param. %d\n", __FUNCTION__, __LINE__,param.operation));

        //TODO: Check possibility to make subscription request as synchronous call.
        param.resCb = asyncHandle;
 
        IDM_sendMsg_to_Remote_device(&param);
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return RBUS_ERROR_ASYNC_RESPONSE;
    }
    else
    {
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return RBUS_ERROR_BUS_ERROR;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return RBUS_ERROR_SUCCESS;
}

/**************************************Get hanlder for local data*****************************************/
rbusError_t X_RDK_Connection_GetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    rbusValue_t value;
    char const* name;
    rbusValue_Init(&value);
    name = rbusProperty_GetName(property);

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo == NULL)
        return RBUS_ERROR_BUS_ERROR;

    if(strcmp(name, "Device.X_RDK_Connection.HelloInterval") == 0)
    {
        rbusValue_SetUInt32(value, pidmDmlInfo->stConnectionInfo.HelloInterval);
    }
    else if(strcmp(name, "Device.X_RDK_Connection.HelloIPv4SubnetList") == 0)
    {
        rbusValue_SetString(value, pidmDmlInfo->stConnectionInfo.HelloIPv4SubnetList);
    }
    else if (strcmp(name, "Device.X_RDK_Connection.HelloIPv6SubnetList") == 0)
    {
        rbusValue_SetString(value, pidmDmlInfo->stConnectionInfo.HelloIPv6SubnetList);
    }
    else if (strcmp(name, "Device.X_RDK_Connection.DetectionWindow") == 0)
    {
        rbusValue_SetUInt32(value, pidmDmlInfo->stConnectionInfo.DetectionWindow);
    }
    else if (strcmp(name, "Device.X_RDK_Connection.Interface") == 0)
    {
        rbusValue_SetString(value, pidmDmlInfo->stConnectionInfo.Interface);
    }
    else if (strcmp(name, "Device.X_RDK_Connection.Port") == 0)
    {
        rbusValue_SetUInt32(value, pidmDmlInfo->stConnectionInfo.Port);
    }
    else
    {
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return RBUS_ERROR_BUS_ERROR;
    }

    rbusProperty_SetValue(property, value);

    rbusValue_Release(value); 
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    return RBUS_ERROR_SUCCESS;   

}
/*************************Set hanlder for local data*****************************************/
rbusError_t X_RDK_Connection_SetHandler(rbusHandle_t handle, rbusProperty_t prop, rbusSetHandlerOptions_t* opts)
{
    (void)opts;
    char const* name = rbusProperty_GetName(prop);
    rbusValue_t value = rbusProperty_GetValue(prop);
    rbusValueType_t type = rbusValue_GetType(value);

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo == NULL)
        return RBUS_ERROR_BUS_ERROR;

    if(strcmp(name, "Device.X_RDK_Connection.HelloInterval") == 0)
    {
        if (type != RBUS_UINT32)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_INVALID_INPUT;
        }

        pidmDmlInfo->stConnectionInfo.HelloInterval = rbusValue_GetUInt32(value);
    }
    if(strcmp(name, "Device.X_RDK_Connection.DetectionWindow") == 0)
    {
        if (type != RBUS_UINT32)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_INVALID_INPUT;
        }

        pidmDmlInfo->stConnectionInfo.DetectionWindow = rbusValue_GetUInt32(value);
    }
    if(strcmp(name, "Device.X_RDK_Connection.Interface") == 0)
    {
        char *InterfaceName = rbusValue_GetString(value, NULL);
        CcspTraceInfo(("%s %d - InterfaceName %s strlen %d\n", __FUNCTION__, __LINE__, InterfaceName, strlen(InterfaceName)));
        if (type != RBUS_STRING || InterfaceName == NULL || strlen(InterfaceName) <= 0)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return RBUS_ERROR_INVALID_INPUT;
        }
        strncpy(pidmDmlInfo->stConnectionInfo.Interface, InterfaceName, sizeof(pidmDmlInfo->stConnectionInfo.Interface));
    }
    if(strcmp(name, "Device.X_RDK_Connection.Port") == 0)
    {
        if (type != RBUS_UINT32)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
	    return RBUS_ERROR_INVALID_INPUT;
	}
	pidmDmlInfo->stConnectionInfo.Port = rbusValue_GetUInt32(value);
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    IdmMgr_write_IDM_ParametersToPSM();
    return RBUS_ERROR_SUCCESS;
}

rbusError_t X_RDK_Remote_Device_SetHandler(rbusHandle_t handle, rbusProperty_t prop, rbusSetHandlerOptions_t* opts)
{
    (void)opts;
    char const* name = rbusProperty_GetName(prop);
    rbusValue_t value = rbusProperty_GetValue(prop);
    rbusValueType_t type = rbusValue_GetType(value);

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo == NULL)
        return RBUS_ERROR_BUS_ERROR;

    if(strcmp(name, "Device.X_RDK_Remote.Port") == 0)
    {
        if (type != RBUS_UINT32)
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            CcspTraceInfo(("%s %d - set Device.X_RDK_Remote.Port Failed\n", __FUNCTION__, __LINE__));
            return RBUS_ERROR_INVALID_INPUT;
        }
        pidmDmlInfo->stRemoteInfo.Port = rbusValue_GetUInt32(value);
    }
    CcspTraceInfo(("%s %d - Device.X_RDK_Remote.Port updated to %d\n", __FUNCTION__, __LINE__, pidmDmlInfo->stRemoteInfo.Port));
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return RBUS_ERROR_SUCCESS;
}
