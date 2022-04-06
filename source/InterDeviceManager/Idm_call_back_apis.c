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

#include "Idm_call_back_apis.h"

#define DM_REMOTE_DEVICE_TABLE "Device.X_RDK_Remote.Device"
#define IDM_DEVICE_DISCOVERY_PORT 4444 //TODO: port no TBD
#define DEFAULT_LOSS_DETECTION_WINDOW 30

extern rbusHandle_t        rbusHandle;

int rcv_message_cb( connection_info_t* conn_info, char *payload)
{
    //TODO:handle rbus calls
    if(!strncmp("Capabilities Request",payload, strlen("Capabilities Request")))
    {
        char SendBuf[256] ={0};
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
        if( pidmDmlInfo == NULL )
        {
            return  -1;
        }
        IDM_REMOTE_DEVICE_LINK_INFO *localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

        snprintf(SendBuf, sizeof(SendBuf),"Cap:%s; Model: %s; HI :%d",localDevice->stRemoteDeviceInfo.Capabilities, localDevice->stRemoteDeviceInfo.ModelNumber, localDevice->stRemoteDeviceInfo.HelloInterval);
        send_remote_message(conn_info, SendBuf);
    }
    //TODO:handle rbus calls
    return 0;
}
int connection_cb(device_info_t* Device, connection_info_t* conn_info, uint encryption_status)
{
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  -1;
    }

    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

    while(remoteDevice!=NULL)
    {
        if(strcmp(remoteDevice->stRemoteDeviceInfo.MAC, Device->mac_addr) == 0)
        {
            CcspTraceInfo(("%s %d -Entry found %s  \n", __FUNCTION__, __LINE__,remoteDevice->stRemoteDeviceInfo.MAC));

            if(encryption_status)
            {
                remoteDevice->stRemoteDeviceInfo.Status = DEVICE_CONNECTED;
            }
            remoteDevice->stRemoteDeviceInfo.conn_info.conn = conn_info->conn;
            //TODO: Send rbus get of Device.X_RDK_Remote.Device.1. (Local device entry of remote device)
            send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, "Capabilities Request");
            break;
        }
        remoteDevice=remoteDevice->next;
    }

    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return 0;
    
}

int discovery_cb(device_info_t* Device, uint discovery_status, uint authentication_status )
{
    int entryFount = 0;
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  -1;
    }
    
    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    while(remoteDevice!=NULL)
    {
        if(strcmp(remoteDevice->stRemoteDeviceInfo.MAC, Device->mac_addr) == 0)
        {
            CcspTraceInfo(("Entry found %s  \n",remoteDevice->stRemoteDeviceInfo.MAC));
            entryFount = 1;

            if(!discovery_status)
            {
                remoteDevice->stRemoteDeviceInfo.Status = DEVICE_NOT_DETECTED;
                close_remote_connection(remoteDevice->stRemoteDeviceInfo.conn_info.conn);
            }

            strncpy(remoteDevice->stRemoteDeviceInfo.IPv4, Device->ipv4_addr, IPv4_ADDR_SIZE);
            strncpy(remoteDevice->stRemoteDeviceInfo.IPv6, Device->ipv6_addr, IPv6_ADDR_SIZE);
            break;
        }
        remoteDevice=remoteDevice->next;
    }    

    if(!entryFount)
    {
        CcspTraceInfo((" ADD new entry\n"));
        IDM_REMOTE_DEVICE_LINK_INFO *newNode = NULL;
        newNode = (IDM_REMOTE_DEVICE_LINK_INFO*)AnscAllocateMemory(sizeof(IDM_REMOTE_DEVICE_LINK_INFO));

        if( newNode == NULL )
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return  -1;
        }
        if(authentication_status)
            newNode->stRemoteDeviceInfo.Status = DEVICE_AUTHENTICATED;
        else if(discovery_status)
            newNode->stRemoteDeviceInfo.Status = DEVICE_DETECTED;

        newNode->stRemoteDeviceInfo.Index = pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries;
        newNode->stRemoteDeviceInfo.Index++;
        strncpy(newNode->stRemoteDeviceInfo.MAC, Device->mac_addr, MAC_ADDR_SIZE);
        strncpy(newNode->stRemoteDeviceInfo.IPv4, Device->ipv4_addr, IPv4_ADDR_SIZE);
        strncpy(newNode->stRemoteDeviceInfo.IPv6, Device->ipv6_addr, IPv6_ADDR_SIZE);

        if(addDevice(newNode) == ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s %d - new Device entry %d added\n", __FUNCTION__, __LINE__, newNode->stRemoteDeviceInfo.Index ));
            pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries++;
        }
        // add row for table
        rbusTable_registerRow(rbusHandle, DM_REMOTE_DEVICE_TABLE,
                                pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries, NULL);

        /* Create link */
        connection_config_t connectionConf;
        strcpy(connectionConf.interface, pidmDmlInfo->stConnectionInfo.Interface);
        connectionConf.port = IDM_DEVICE_DISCOVERY_PORT;
        connectionConf.device = Device;
        if(open_remote_connection(&connectionConf, connection_cb, rcv_message_cb) !=0)
        {
            CcspTraceError(("%s %d - open_remote_connection failed\n", __FUNCTION__, __LINE__));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            return -1;
        }
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return 0;
}

ANSC_STATUS IDMMgr_Start_Device_Discovery()
{
    discovery_config_t discoveryConf;

    /* Update discovery_config deatils */
    discoveryConf.port = IDM_DEVICE_DISCOVERY_PORT;
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo != NULL)
    {
        discoveryConf.discovery_interval = (pidmDmlInfo->stConnectionInfo.HelloInterval /1000);
        strcpy(discoveryConf.interface, pidmDmlInfo->stConnectionInfo.Interface);
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    }
    discoveryConf.loss_detection_window = DEFAULT_LOSS_DETECTION_WINDOW;

    /*Start CAL Device discovery process */
    if(start_discovery(&discoveryConf, discovery_cb) !=0)
    {
        CcspTraceInfo(("%s %d - start_discovery start failed\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    CcspTraceInfo(("%s %d - discovery process started successfully \n", __FUNCTION__, __LINE__));
    return ANSC_STATUS_SUCCESS;
}
