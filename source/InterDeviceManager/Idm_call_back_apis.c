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
#define IDM_DEVICE_DISCOVERY_PORT 4444 //TODO: port no TBD
#define DEFAULT_LOSS_DETECTION_WINDOW 30

extern rbusHandle_t        rbusHandle;

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
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
            if( pidmDmlInfo == NULL )
        {
            return  -1;
        }

    payload_t *recvData = (payload_t*)payload;
    if(recvData->msgType == REQ)
    {
        IDM_Incoming_Reqest_handler(recvData);
    }else if(recvData->msgType == RES)
    {
        IDM_Incoming_Response_handler(recvData);
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return 0;
}

//====================================================================================//
//TODO: CleanUp
void dummycb(char *param_name, char *param_value, ANSC_STATUS status)
{

        if(status == ANSC_STATUS_SUCCESS)
        {
            CcspTraceInfo(("%s %d -IDM set/get to remote device success\n", __FUNCTION__, __LINE__));
            CcspTraceInfo(("%s %d - %s => %s \n", __FUNCTION__, __LINE__,param_name , param_value));
        }else
            CcspTraceInfo(("%s %d -IDM set/get to remote failed \n", __FUNCTION__, __LINE__,param_name));

        //find device entry
        PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
            if( pidmDmlInfo == NULL )
        {
            return  -1;
        }

        IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
        while(remoteDevice!=NULL)
        {
            if(strncmp(remoteDevice->stRemoteDeviceInfo.MAC, "A0:BD:CD:FF:77:D2" ,MAC_ADDR_SIZE) == 0)
            {
                CcspTraceInfo(("%s %d : Entry found %s\n",__FUNCTION__, __LINE__,remoteDevice->stRemoteDeviceInfo.MAC));
                remoteDevice->stRemoteDeviceInfo.Status = DEVICE_CONNECTED;
                break;
            }
            remoteDevice=remoteDevice->next;
        }
            IdmMgrDml_GetConfigData_release(pidmDmlInfo);

}
//====================================================================================//
int connection_cb(device_info_t* Device, connection_info_t* conn_info, uint encryption_status)
{
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  -1;
    }

    //TODO: Send request all parameters of remote device
    //Send request to get Capabilities
    idm_send_msg_Params_t param;
    strcpy(param.Mac_dest, Device->mac_addr);
    param.timeout = 5;
    strcpy(param.param_name,"Device.X_RDK_Remote.Device.1.Capabilities");
    param.operation = GET;
    param.resCb = &dummycb;


    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    while(remoteDevice!=NULL)
    {
        if(strcmp(remoteDevice->stRemoteDeviceInfo.MAC, Device->mac_addr) == 0)
        {
            if(encryption_status)
            {
                remoteDevice->stRemoteDeviceInfo.conn_info.conn = conn_info->conn;
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                while(remoteDevice->stRemoteDeviceInfo.Status != DEVICE_CONNECTED)
                {
                    CcspTraceInfo(("%s %d - sending Capabilities Request socket : %d\n", __FUNCTION__, __LINE__,remoteDevice->stRemoteDeviceInfo.conn_info.conn));
                    IDM_sendMsg_to_Remote_device(&param);

                    sleep(5);
                }
                //TODO: Cleanup /*test code for DML set */
                //====================================================================================//
                strcpy(param.param_name,"Device.X_RDK_WanManager.CPEInterface.2.Name");

                param.operation = SET;
                param.type = ccsp_string;
                srand(time(0));
                snprintf(param.param_value, sizeof(param.param_value),"update_wan_%d",((rand()%(14000 - 13000 + 1)) + 13000));
                CcspTraceInfo(("%s %d - Setting Device.X_RDK_WanManager.CPEInterface.2.Name to %s\n", __FUNCTION__, __LINE__,param.param_value));
                IDM_sendMsg_to_Remote_device(&param);
                //====================================================================================//
            }

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
                CcspTraceError(("%s %d - device lost :MAC %s\n", __FUNCTION__, __LINE__,remoteDevice->stRemoteDeviceInfo.MAC));
                remoteDevice->stRemoteDeviceInfo.Status = DEVICE_NOT_DETECTED;
                if(remoteDevice->stRemoteDeviceInfo.conn_info.conn != 0)
                {
                    close_remote_connection(remoteDevice->stRemoteDeviceInfo.conn_info.conn);
                }
                remoteDevice->stRemoteDeviceInfo.conn_info.conn = 0;
            }

            strncpy(remoteDevice->stRemoteDeviceInfo.IPv4, Device->ipv4_addr, IPv4_ADDR_SIZE);
            strncpy(remoteDevice->stRemoteDeviceInfo.IPv6, Device->ipv6_addr, IPv6_ADDR_SIZE);
            free(Device);
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
        strcpy(connectionConf.interface, pidmDmlInfo->stConnectionInfo.Interface);
        connectionConf.port = IDM_DEVICE_DISCOVERY_PORT;
        connectionConf.device = Device;
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
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

ANSC_STATUS IDM_Start_Device_Discovery()
{
    discovery_config_t discoveryConf;
    pthread_t                threadId;
    int                      iErrorCode     = 0;

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
