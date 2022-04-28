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

#include "Idm_msg_process.h"
sendReqList *headsendReqList =NULL;
RecvReqList *headRecvReqList = NULL;
uint gReqIdCounter = 0;
extern ANSC_HANDLE  bus_handle;
void IDM_addToSendRequestList( sendReqList *newReq)
{
    if(!headsendReqList)
    {
        headsendReqList  = newReq;
    }else
    {

        sendReqList *temp = headsendReqList;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = newReq;
    }
}

sendReqList* IDM_getFromSendRequestList(uint reqID)
{
    /* find req entry in LL */
    sendReqList *req = headsendReqList, *temp = NULL;
    if(headsendReqList == NULL)
    {
        return NULL;
    }
    if(headsendReqList->reqId == reqID)
    {
        temp = headsendReqList;
        headsendReqList = headsendReqList->next;
        return temp;
    }else
    {
        while (req->next != NULL)
        {
            if(req->next->reqId == reqID)
            {
                /*entry found */
                temp = req->next;
                //Remove from LL. memory should br freed in calling function
                req->next = req->next->next;
                break;
            }
            req = req->next;
        }
        return temp;
    }
}

ANSC_STATUS IDM_sendMsg_to_Remote_device(idm_send_msg_Params_t *param)
{

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }
    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    IDM_REMOTE_DEVICE_LINK_INFO *localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

    while(remoteDevice!=NULL)
    {
        if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, param->Mac_dest) == 0)
        {
            if(remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0)
            {
                /* Create request entry */
                sendReqList *newReq = malloc(sizeof(sendReqList));
                memset(newReq, 0, sizeof(sendReqList));
                newReq->reqId = gReqIdCounter++;
                strncpy(newReq->Mac_dest,param->Mac_dest, MAC_ADDR_SIZE);
                newReq->resCb = param->resCb;
                newReq->timeout = param->timeout;
                newReq->next = NULL;

                IDM_addToSendRequestList(newReq);

                /* Create payload */
                payload_t payload;
                memset(&payload, 0, sizeof(payload_t));
                payload.reqID = newReq->reqId;
                payload.operation = param->operation;
                payload.msgType = REQ;
                strncpy(payload.Mac_source, localDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE);
                strncpy(payload.param_name,param->param_name,sizeof(payload.param_name));
                strncpy(payload.param_value,param->param_value,sizeof(payload.param_value));
                payload.type = param->type;

                /* send message */
                send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
            }
            break;
        }
        remoteDevice=remoteDevice->next;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    return ANSC_STATUS_SUCCESS;
}

int IDM_Incoming_Response_handler(payload_t * payload)
{
    /* find req entry in LL */
    sendReqList *req = IDM_getFromSendRequestList(payload->reqID);
    if(req == NULL)
    {
        //Entry not found. may be timed out.
        return -1;
    }

    //call the responce callback API
    if(payload->operation == IDM_REQUEST)
    {
        req->resCb((IDM_REMOTE_DEVICE_INFO *)payload->param_value, payload->status,payload->Mac_source);
    }

    //Free mem
    free(req);
    return 0;
}

void IDM_addToReceivedReqList( RecvReqList *newReq)
{
    if(!headRecvReqList)
    {
        headRecvReqList  = newReq;
    }else
    {

        RecvReqList *temp = headRecvReqList;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = newReq;
    }
}

RecvReqList* IDM_ReceivedReqList_pop()
{
    if(!headRecvReqList)
    {
        return NULL;
    }
    /* return Head. Memory should be freed in calling funtion */
    RecvReqList *temp = headRecvReqList;
    headRecvReqList = headRecvReqList->next;
    return temp;
}

int IDM_Incoming_Request_handler(payload_t * payload)
{
    CcspTraceInfo(("%s %d - \n", __FUNCTION__, __LINE__));

    /*Create entry in incoming req list */
    RecvReqList *getReq = malloc(sizeof(RecvReqList));
    memset(getReq, 0, sizeof(RecvReqList));
    getReq->reqId = payload->reqID;
    getReq->operation = payload->operation;
    getReq->timeout = payload->timeout;
    getReq->type = payload->type;
    strncpy(getReq->Mac_dest, payload->Mac_source,sizeof(getReq->Mac_dest));
    strncpy(getReq->param_name, payload->param_name,sizeof(getReq->param_name));
    strncpy(getReq->param_value, payload->param_value,sizeof(getReq->param_value));
    getReq->next = NULL;

    IDM_addToReceivedReqList(getReq);
    return 0;
}

void IDM_Incoming_req_handler_thread()
{
    PIDM_DML_INFO pidmDmlInfo = NULL;
    while(true)
    {
        RecvReqList *ReqEntry = IDM_ReceivedReqList_pop();
        if(ReqEntry!= NULL)
        {
            payload_t payload;
            memset(&payload, 0, sizeof(payload_t));

            CcspTraceInfo(("%s %d -processing get request from %s paramName %s \n", __FUNCTION__, __LINE__,ReqEntry->Mac_dest, ReqEntry->param_name));
            /* Rbus get implementation */
            if(ReqEntry->operation == GET)
            {
                parameterValStruct_t   **retVal;
                char                    *ParamName[ 1 ];
                int                    ret               = 0,
                                       nval;

                //Assign address for get parameter name
                ParamName[0] = ReqEntry->param_name;
                ret = CcspBaseIf_getParameterValues(
                        bus_handle,
                        "eRT.com.cisco.spvtg.ccsp.interdevicemanager",//pComponent,TODO: Remove hard coded value get it from payload
                        "/com/cisco/spvtg/ccsp/interdevicemanager",//pBus,TODO: Remove hard coded value get it from payload
                        ParamName,
                        1,
                        &nval,
                        &retVal);

                //Copy the value
                if( CCSP_SUCCESS == ret )
                {

                    if( NULL != retVal[0]->parameterValue )
                    {
                        memcpy( payload.param_value, retVal[0]->parameterValue, strlen( retVal[0]->parameterValue ) + 1 );
                    }

                    if( retVal )
                    {
                        free_parameterValStruct_t (bus_handle, nval, retVal);
                    }
                    /* Set return status */
                    payload.status = ANSC_STATUS_SUCCESS;
                }else
                {
                    payload.status = ANSC_STATUS_FAILURE;
                }
            }else if(ReqEntry->operation == SET)
            {
                CcspTraceInfo(("%s %d -Processing Set request from %s paramName %s paramValue %s\n", __FUNCTION__, __LINE__,ReqEntry->Mac_dest, ReqEntry->param_name,ReqEntry->param_value));
                CCSP_MESSAGE_BUS_INFO *bus_info              = (CCSP_MESSAGE_BUS_INFO *)bus_handle;
                parameterValStruct_t   param_val[1]          = { 0 };
                char                  *faultParam            = NULL;
                char                   acParameterName[256]  = { 0 },
                                       acParameterValue[128] = { 0 };
                int                    ret                   = 0;
                //Copy Name
                snprintf( acParameterName,sizeof(acParameterName)-1, "%s", ReqEntry->param_name );
                param_val[0].parameterName  = acParameterName;

                //Copy Value
                snprintf( acParameterValue,sizeof(acParameterValue)-1, "%s", ReqEntry->param_value );
                param_val[0].parameterValue = acParameterValue;

                //Copy Type
                param_val[0].type           = ReqEntry->type;
                ret = CcspBaseIf_setParameterValues(
                        bus_handle,
                        "eRT.com.cisco.spvtg.ccsp.wanmanager",//pComponent,TODO: Remove hard coded value get it from payload
                        "/com/cisco/spvtg/ccsp/wanmanager",//pBus,TODO: Remove hard coded value get it from payload
                        0,
                        0,
                        param_val,
                        1,
                        TRUE,
                        &faultParam
                        );

                if( ( ret != CCSP_SUCCESS ) && ( faultParam != NULL ) )
                {
                    CcspTraceError(("%s-%d Failed to set %s\n",__FUNCTION__,__LINE__,ReqEntry->param_name));
                    bus_info->freefunc( faultParam );
                    payload.status = ANSC_STATUS_FAILURE;
                }
                payload.status = ANSC_STATUS_SUCCESS;
            }else if(ReqEntry->operation == IDM_REQUEST)
            {
                CcspTraceInfo(("%s %d -Processing IDM_REQUEST request from %s \n", __FUNCTION__, __LINE__,ReqEntry->Mac_dest));

                pidmDmlInfo = IdmMgr_GetConfigData_locked();
                if( pidmDmlInfo == NULL )
                {
                    payload.status =  ANSC_STATUS_FAILURE;
                }
                /*get local deivce struct */
                memcpy(payload.param_value, &(pidmDmlInfo->stRemoteInfo.pstDeviceLink->stRemoteDeviceInfo),sizeof(IDM_REMOTE_DEVICE_INFO));
                payload.status =  ANSC_STATUS_SUCCESS;
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                pidmDmlInfo = NULL;
            } 

            //create payload
            pidmDmlInfo = IdmMgr_GetConfigData_locked();
            if( pidmDmlInfo == NULL )
            {
                return  ANSC_STATUS_FAILURE;
            }
            IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
            payload.reqID = ReqEntry->reqId;
            payload.operation = ReqEntry->operation;
            payload.msgType = RES;
            /* Update local device mac */
            strncpy(payload.Mac_source,remoteDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE);
            strncpy(payload.param_name,ReqEntry->param_name,sizeof(payload.param_name));
            //Find the device using mac
            while(remoteDevice!=NULL)
            {
                if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, ReqEntry->Mac_dest) == 0)
                {
                    if(remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0)
                        send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
                    break;
                }
                remoteDevice=remoteDevice->next;
            }

            IdmMgrDml_GetConfigData_release(pidmDmlInfo);
            free(ReqEntry);
        }
    }
}








