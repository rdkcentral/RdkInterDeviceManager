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
#include "Idm_TCP_apis.h"
#include "Idm_msg_process.h"

#define DM_REMOTE_DEVICE_TABLE "Device.X_RDK_Remote.Device"
#define IDM_DEFAULT_DEVICE_TCP_PORT 50765 //TODO: port no TBD
#define DEFAULT_LOSS_DETECTION_WINDOW 30
#define DEFAULT_IDM_REQUEST_TIMEOUT 10

typedef struct discovery_cb_threadargs
{
    device_info_t device;
    uint discovery_status;
    uint auth_status;
} Discovery_cb_threadargs;

extern rbusHandle_t        rbusHandle;

void discovery_cb_thread(void *arg);

//====================================================================================//
/*dummy function */
//TODO: delete after integrating Upnp
int start_discovery(discovery_config_t* discoveryConf, int (*discovery_cb)(device_info_t* Device, uint discovery_status, uint authentication_status))
{
    CcspTraceInfo(("%s %d - \n", __FUNCTION__, __LINE__));
    return 0;
}
//====================================================================================//

int rcv_message_cb( connection_info_t* conn_info, void *payload)
{
    CcspTraceInfo(("%s %d - \n", __FUNCTION__, __LINE__));

    payload_t *recvData = (payload_t*)payload;
    if(recvData->msgType == REQ)
    {
        IDM_Incoming_Request_handler(recvData);
    }else if(recvData->msgType == RES)
    {
        IDM_Incoming_Response_handler(recvData);
    }
    return 0;
}

void Capabilities_get_cb(IDM_REMOTE_DEVICE_INFO *device, ANSC_STATUS status ,char *mac)
{

        if(status == ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s %d -IDM Capabilities_get_cb from  device %s success \n", __FUNCTION__, __LINE__,mac));
        }else
            CcspTraceInfo(("%s %d -IDM Capabilities_get_cb from  device %s failed \n", __FUNCTION__, __LINE__,mac));

        //find device entry
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
            if( pidmDmlInfo == NULL )
        {
            return  -1;
        }

        IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
        while(remoteDevice!=NULL)
        {
            if(strncasecmp(remoteDevice->stRemoteDeviceInfo.MAC, mac ,MAC_ADDR_SIZE) == 0)
            {
                CcspTraceInfo(("%s %d : Entry found %s\n",__FUNCTION__, __LINE__,remoteDevice->stRemoteDeviceInfo.MAC));
                remoteDevice->stRemoteDeviceInfo.Status = DEVICE_CONNECTED;
                strncpy(remoteDevice->stRemoteDeviceInfo.Capabilities,device->Capabilities, sizeof(remoteDevice->stRemoteDeviceInfo.Capabilities));
                strncpy(remoteDevice->stRemoteDeviceInfo.ModelNumber,device->ModelNumber, sizeof(remoteDevice->stRemoteDeviceInfo.ModelNumber));
                remoteDevice->stRemoteDeviceInfo.HelloInterval = device->HelloInterval;
                break;
            }
            remoteDevice=remoteDevice->next;
        }
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);

}

int connection_cb(device_info_t* Device, connection_info_t* conn_info, uint encryption_status)
{

    //TODO: Send request all parameters of remote device
    //Send request to get Capabilities
    idm_send_msg_Params_t param;
    memset(&param, 0, sizeof(param));
    strncpy(param.Mac_dest, Device->mac_addr,MAC_ADDR_SIZE);
    param.timeout = DEFAULT_IDM_REQUEST_TIMEOUT;
    param.operation = IDM_REQUEST;
    param.resCb = NULL;

    while(1)
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

                break;
            }
            remoteDevice=remoteDevice->next;
        }
        if(encryption_status)
        {
            remoteDevice->stRemoteDeviceInfo.conn_info.conn = conn_info->conn;
            if(remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED)
            {
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                break;
            }
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            CcspTraceInfo(("%s %d - sending Capabilities Request socket : %d\n", __FUNCTION__, __LINE__,remoteDevice->stRemoteDeviceInfo.conn_info.conn));
            IDM_sendMsg_to_Remote_device(&param);

            sleep(5);
        }
    }
    return 0;
    
}


int discovery_cb(device_info_t* Device, uint discovery_status, uint authentication_status )
{


    CcspTraceInfo(("%s %d -  \n", __FUNCTION__, __LINE__));

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  -1;
    }

    if(strncasecmp(Device->mac_addr, pidmDmlInfo->stRemoteInfo.pstDeviceLink->stRemoteDeviceInfo.MAC, MAC_ADDR_SIZE )==0)
    {
        CcspTraceInfo(("%s %d -detected local device, don't add to remote device list\n", __FUNCTION__, __LINE__));
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return 0;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    pthread_t                discovery_cb_threadID;
    int                      iErrorCode     = 0;

    Discovery_cb_threadargs *threadArgs = malloc(sizeof(Discovery_cb_threadargs));
    strncpy(threadArgs->device.mac_addr, Device->mac_addr, MAC_ADDR_SIZE);
    strncpy(threadArgs->device.ipv4_addr, Device->ipv4_addr, IPv4_ADDR_SIZE);
    strncpy(threadArgs->device.ipv6_addr, Device->ipv6_addr, IPv6_ADDR_SIZE); 
    threadArgs->discovery_status = discovery_status;
    threadArgs->auth_status = authentication_status;


    iErrorCode = pthread_create( &discovery_cb_threadID, NULL, &discovery_cb_thread, threadArgs);
    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start discovery_cb_thread Thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        return -1;
    }
    else
    {
        CcspTraceInfo(("%s %d - IDM discovery_cb_thread Started Successfully\n", __FUNCTION__, __LINE__ ));
    }    
    return 0;
}
void discovery_cb_thread(void *arg)
{
    Discovery_cb_threadargs *threadArgs = (Discovery_cb_threadargs*) arg;

    device_info_t* Device = &(threadArgs->device);
    uint discovery_status = threadArgs->discovery_status;
    uint authentication_status = threadArgs->auth_status;

    CcspTraceInfo(("%s %d - Discovery callback for Device mac %s \n", __FUNCTION__, __LINE__,Device->mac_addr));

    pthread_detach(pthread_self());

    int entryFount = 0;
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        free(threadArgs);
        return  -1;
    }

    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    while(remoteDevice!=NULL)
    {
        if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, Device->mac_addr) == 0)
        {
            CcspTraceInfo(("Entry found %s  \n",remoteDevice->stRemoteDeviceInfo.MAC));
            entryFount = 1;

            if(!discovery_status)
            {
                remoteDevice->stRemoteDeviceInfo.Status = DEVICE_NOT_DETECTED;
                if(remoteDevice->stRemoteDeviceInfo.conn_info.conn != 0)
                {
                    close_remote_connection(remoteDevice->stRemoteDeviceInfo.conn_info.conn);
                }
                remoteDevice->stRemoteDeviceInfo.conn_info.conn = 0;
            }


            strncpy(remoteDevice->stRemoteDeviceInfo.IPv4, Device->ipv4_addr, IPv4_ADDR_SIZE);
            strncpy(remoteDevice->stRemoteDeviceInfo.IPv6, Device->ipv6_addr, IPv6_ADDR_SIZE);
            break;
        }
        remoteDevice=remoteDevice->next;
    }    

    if(!entryFount)
    {
        CcspTraceInfo(("%s %d - New device detected MAC %s \n", __FUNCTION__, __LINE__, Device->mac_addr));

        //Create new entry in remote deice list
        IDM_REMOTE_DEVICE_LINK_INFO *newNode = NULL;
        newNode = (IDM_REMOTE_DEVICE_LINK_INFO*)AnscAllocateMemory(sizeof(IDM_REMOTE_DEVICE_LINK_INFO));

        if( newNode == NULL )
        {
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            free(threadArgs);
            return  -1;
        }
        if(authentication_status)
            newNode->stRemoteDeviceInfo.Status = DEVICE_AUTHENTICATED;
        else if(discovery_status)
            newNode->stRemoteDeviceInfo.Status = DEVICE_DETECTED;

        newNode->stRemoteDeviceInfo.Index = pidmDmlInfo->stRemoteInfo.ulDeviceNumberOfEntries;
        newNode->stRemoteDeviceInfo.Index++;
        //TODO: convert MAC address to Uppercase
        strncpy(newNode->stRemoteDeviceInfo.MAC, Device->mac_addr, MAC_ADDR_SIZE);
        strncpy(newNode->stRemoteDeviceInfo.IPv4, Device->ipv4_addr, IPv4_ADDR_SIZE);
        strncpy(newNode->stRemoteDeviceInfo.IPv6, Device->ipv6_addr, IPv6_ADDR_SIZE);
        newNode->stRemoteDeviceInfo.conn_info.conn = 0;

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
        memset(&connectionConf, 0, sizeof(connection_config_t));
        strncpy(connectionConf.interface, pidmDmlInfo->stConnectionInfo.Interface,sizeof(connectionConf.interface));
        connectionConf.port = IDM_DEFAULT_DEVICE_TCP_PORT;
        connectionConf.device = Device;
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        if(open_remote_connection(&connectionConf, connection_cb, rcv_message_cb) !=0)
        {
            CcspTraceError(("%s %d - open_remote_connection failed\n", __FUNCTION__, __LINE__));
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            free(threadArgs);
            return -1;
        }
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                CcspTraceError(("%s %d - exit \n", __FUNCTION__, __LINE__));
    free(threadArgs);
    pthread_exit(NULL);
    return 0;
}

ANSC_STATUS IDM_Start_Device_Discovery()
{
    discovery_config_t discoveryConf;
    pthread_t                threadId;
    int                      iErrorCode     = 0;

    //TODO:(Remove after mesh implementation) wait for IDM interface static configurations
    while(access("/tmp/idmReady", F_OK) == -1)
    {
        CcspTraceInfo(("%s %d - wait for /tmp/idmReady file \n", __FUNCTION__, __LINE__));
        sleep(10);
    }


    /* Start incoming req handler thread */
    iErrorCode = pthread_create( &threadId, NULL, &IDM_Incoming_req_handler_thread, NULL);
    if( 0 != iErrorCode )
    {
        CcspTraceInfo(("%s %d - Failed to start Incoming_req_handler_thread Thread EC:%d\n", __FUNCTION__, __LINE__, iErrorCode ));
        return ANSC_STATUS_FAILURE;
    }
    else
    {
        CcspTraceInfo(("%s %d - IDM Incoming_req_handler_thread Started Successfully\n", __FUNCTION__, __LINE__ ));
    }

    /* Update discovery_config deatils */
    discoveryConf.port = IDM_DEFAULT_DEVICE_TCP_PORT;
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if(pidmDmlInfo != NULL)
    {
        discoveryConf.discovery_interval = (pidmDmlInfo->stConnectionInfo.HelloInterval / 1000);

        strncpy(discoveryConf.interface, pidmDmlInfo->stConnectionInfo.Interface,sizeof(discoveryConf.interface));
        discoveryConf.loss_detection_window = (pidmDmlInfo->stConnectionInfo.DetectionWindow /1000);//TODO: update 
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
