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

#define DM_REMOTE_DEVICE_INVOKE "Device.X_RDK_Remote.Invoke()"

sendReqList *headsendReqList =NULL;
RecvReqList *headRecvReqList = NULL;

sendSubscriptionList *headsendSubscriptionList =NULL;
RecvSubscriptionList *headRecvSubscriptionList = NULL;

uint gReqIdCounter = 0;
extern ANSC_HANDLE  bus_handle;
extern rbusHandle_t        rbusHandle;

extern Capabilities_get_cb(IDM_REMOTE_DEVICE_INFO *device, ANSC_STATUS status ,char *mac);
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


void IDM_addToSendSubscriptionuestList( sendSubscriptionList *newSubscription)
{
    if(!headsendSubscriptionList)
    {
        headsendSubscriptionList  = newSubscription;
    }else
    {

        sendSubscriptionList *temp = headsendSubscriptionList;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = newSubscription;
    }
}

void IDM_addToReceivedSubscriptionList( RecvSubscriptionList *newSubscription)
{
    if(!headRecvSubscriptionList)
    {
        headRecvSubscriptionList  = newSubscription;
    }else
    {

        RecvSubscriptionList *temp = headRecvSubscriptionList;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = newSubscription;
    }
}
ANSC_STATUS IDM_sendFile_to_Remote_device(char* Mac_dest,char* filename,char* output_location)
{
    CcspTraceDebug(("Inside %s:%d\n",__FUNCTION__,__LINE__));
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return  ANSC_STATUS_FAILURE;
    }
    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    IDM_REMOTE_DEVICE_LINK_INFO *localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

    while(remoteDevice!=NULL)
    {
        if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC,Mac_dest) == 0 && (remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED ))
        {
            if((remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0))
            {
                payload_t payload;
                memset(&payload, 0, sizeof(payload_t));
                sendReqList *newReq = malloc(sizeof(sendReqList));
                memset(newReq, 0, sizeof(sendReqList));
                newReq->reqId = gReqIdCounter++;
                strncpy(newReq->Mac_dest,Mac_dest, MAC_ADDR_SIZE);
                payload.operation = SFT;
                payload.msgType = SFT;
                strncpy(payload.Mac_source, localDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE);
                strncpy(payload.param_name,filename,sizeof(payload.param_name));
                CcspTraceDebug(("Inside %s:%d peer MAC=%s\n",__FUNCTION__,__LINE__,Mac_dest,localDevice->stRemoteDeviceInfo.MAC));
                sendFile_to_remote(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload,output_location);
                usleep(250000);
                break;
            }
            else
            {
                CcspTraceError(("%s: conn value is equals to zero\n",__FUNCTION__));
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return  ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            remoteDevice=remoteDevice->next;
        }
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return ANSC_STATUS_SUCCESS;
}
ANSC_STATUS IDM_getFile_from_Remote_device(char* Mac_dest,char* filename,char* output_location)
{
    CcspTraceDebug(("Inside %s:%d\n",__FUNCTION__,__LINE__));
    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return  ANSC_STATUS_FAILURE;
    }
    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    IDM_REMOTE_DEVICE_LINK_INFO *localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

    while(remoteDevice!=NULL)
    {
        if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC,Mac_dest) == 0 && (remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED ))
        {
            if((remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0))
            {
                payload_t payload;
                memset(&payload, 0, sizeof(payload_t));
                sendReqList *newReq = malloc(sizeof(sendReqList));
                memset(newReq, 0, sizeof(sendReqList));
                newReq->reqId = gReqIdCounter++;
                strncpy(newReq->Mac_dest,Mac_dest, MAC_ADDR_SIZE);
                payload.operation = GFT;
                payload.msgType = REQ;
                strncpy(payload.Mac_source, localDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE);
                strncpy(payload.param_name,filename,sizeof(payload.param_name));
                strncpy(newReq->output_location,output_location,strlen(output_location));
                payload.reqID = newReq->reqId;
                IDM_addToSendRequestList(newReq);
                CcspTraceDebug(("Inside %s:%d peer MAC=%s\n",__FUNCTION__,__LINE__,Mac_dest));
                send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
                usleep(250000);
                break;
            }
            else
            {
                CcspTraceError(("%s: conn value is equals to zero\n",__FUNCTION__));
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return  ANSC_STATUS_FAILURE;
            }
        }
        else
        {
            remoteDevice=remoteDevice->next;
        }
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS IDM_sendMsg_to_Remote_device(idm_send_msg_Params_t *param)
{

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        IdmMgrDml_GetConfigData_release(pidmDmlInfo);
        return  ANSC_STATUS_FAILURE;
    }
    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    IDM_REMOTE_DEVICE_LINK_INFO *localDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;

    while(remoteDevice!=NULL)
    {
        if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, param->Mac_dest) == 0)
        {
            if((remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0))
            {
                /* Create payload */
                payload_t payload;
                memset(&payload, 0, sizeof(payload_t));
                if(param->operation == GET || param->operation == SET || param->operation == IDM_REQUEST)
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
                    payload.reqID = newReq->reqId;
                }else if(param->operation == IDM_SUBS)
                {
                    /* Create request entry */
                    sendSubscriptionList *newReq = malloc(sizeof(sendSubscriptionList));
                    memset(newReq, 0, sizeof(sendSubscriptionList));
                    newReq->reqId = gReqIdCounter++;
                    newReq->resCb = param->resCb;
                    newReq->next = NULL;
                    IDM_addToSendSubscriptionuestList(newReq);
                    payload.reqID = newReq->reqId;
                }

                payload.operation = param->operation;
                payload.msgType = REQ;
                strncpy(payload.Mac_source, localDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE);
                strncpy(payload.param_name,param->param_name,sizeof(payload.param_name));
                strncpy(payload.param_value,param->param_value,sizeof(payload.param_value));
                strncpy(payload.pComponent_name,param->pComponent_name,sizeof(payload.pComponent_name));
                strncpy(payload.pBus_path,param->pBus_path,sizeof(payload.pBus_path));
                payload.type = param->type;

                /* send message */
                send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
                usleep(250000); //Sleep for 250ms
            }else
            {
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                return  ANSC_STATUS_FAILURE;
            }
            break;
        }
        remoteDevice=remoteDevice->next;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);

    return ANSC_STATUS_SUCCESS;
}

void IDM_Incoming_FT_Response(connection_info_t* conn_info,payload_t* payload)
{
    CcspTraceDebug(("Inside %s:%d\n",__FUNCTION__,__LINE__));
    char* buf;
    int bytes=0,length=0,total_bytes=0;
    if(payload != NULL)
    {
        total_bytes=atoi(payload->param_value);
        CcspTraceInfo(("%s file with size %d will be transferred\n",payload->param_name,total_bytes));

        FILE* fptr;
        sendReqList *req;
        req = IDM_getFromSendRequestList(payload->reqID);
        fptr = fopen(req->output_location,"wb");
        CcspTraceInfo(("output location = %s\n",req->output_location));
        if(!fptr){
            CcspTraceError(("file not found\n"));
            return;
        }
        else{
            buf = (char*) malloc(total_bytes);
            while(length<total_bytes){
#ifndef IDM_DEBUG
                if(conn_info->enc.ssl != NULL){
                    bytes = SSL_read(conn_info->enc.ssl, buf, total_bytes-bytes);
                }
                else{
                    CcspTraceError(("%s:%d ssl session is null\n",__FUNCTION__,__LINE__));
                    break;
                }
#else
                bytes = read( conn_info->conn , buf, total_bytes-bytes);
#endif
                CcspTraceInfo(("bytes transfered : %d\n",bytes));
                if(bytes > 0){
                    fwrite(buf,1,bytes,fptr);
                    length+=bytes;
                }
                else{
                    CcspTraceError(("(%s:%d) Data encryption failed (Err: %d)\n", __FUNCTION__, __LINE__,bytes));
                }
            }
        }
        fclose(fptr);
        if(buf){
            free(buf);
        }
    }
    else
    {
        CcspTraceError(("%s:%d payload is null\n",__FUNCTION__, __LINE__));
    }
}

int IDM_Incoming_Response_handler(payload_t * payload)
{
    rbusMethodAsyncHandle_t async_callBack_handler;
    /* find req entry in LL */
    if(payload->operation == IDM_SUBS)
    {
        sendSubscriptionList *subsReq = headsendSubscriptionList;
        while(subsReq != NULL)
        {
            if (payload->reqID == subsReq->reqId)
            {
                //TODO: Subscription call back is handled by DM_REMOTE_DEVICE_INVOKE publish event. Call back not required
                async_callBack_handler = subsReq->resCb;
                break;
            }
            subsReq = subsReq->next;
        }

    }else
    {
        sendReqList *req;
        req = IDM_getFromSendRequestList(payload->reqID);
        if(req == NULL)
        {
            if(payload->operation != IDM_REQUEST) /* Async device info update. */
                return -1; //Entry not found. may be timed out.
        }else{
            async_callBack_handler = req->resCb;
            free(req);
        }
    }
    //call the responce callback API
    if(payload->operation == IDM_REQUEST)
    {
        Capabilities_get_cb((IDM_REMOTE_DEVICE_INFO *)payload->param_value, payload->status,payload->Mac_source);
    }else
    {
        rbusObject_t outParams;
        rbusValue_t value;
        rbusError_t err;

        rbusObject_Init(&outParams, NULL);

        /*set DM Value */
        rbusValue_Init(&value);
        rbusValue_SetString(value, payload->param_value);
        rbusObject_SetValue(outParams, "param_value", value);
        rbusValue_Release(value);

        /*set source mac */
        rbusValue_Init(&value);
        rbusValue_SetString(value, payload->Mac_source);
        rbusObject_SetValue(outParams, "Mac_source", value);
        rbusValue_Release(value);

        /*set DM Name */
        rbusValue_Init(&value);
        rbusValue_SetString(value, payload->param_name);
        rbusObject_SetValue(outParams, "param_name", value);
        rbusValue_Release(value);

        /*set OPeration type */
        rbusValue_Init(&value);
        rbusValue_SetInt32(value, payload->operation);
        rbusObject_SetValue(outParams, "operation", value);
        rbusValue_Release(value);

        if(payload->operation == IDM_SUBS)
        {
            rbusEvent_t event = {0};
            event.name = DM_REMOTE_DEVICE_INVOKE;
            event.data = outParams;
            event.type = RBUS_EVENT_GENERAL;

            CcspTraceInfo(("%s sending rbus Subcription responce using RM_REMOTE_INVOKE publish\n", __FUNCTION__));
            rbusEvent_Publish(rbusHandle, &event);

        }else
        {
            if(payload->status == ANSC_STATUS_SUCCESS)
            {
                err = rbusMethod_SendAsyncResponse(async_callBack_handler, RBUS_ERROR_SUCCESS, outParams);
                if(err != RBUS_ERROR_SUCCESS)
                {
                    CcspTraceInfo(("%s rbusMethod_SendAsyncResponse failed err:%d\n", __FUNCTION__, err));
                }
            }else
            {
                err = rbusMethod_SendAsyncResponse(async_callBack_handler, RBUS_ERROR_BUS_ERROR, outParams);
                if(err != RBUS_ERROR_SUCCESS)
                {
                    CcspTraceInfo(("%s rbusMethod_SendAsyncResponse failed err:%d\n", __FUNCTION__, err));
                }
            }
        }
        rbusObject_Release(outParams);
    }

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

static void IDM_Rbus_subscriptionEventHandler(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    (void)handle;
    (void)subscription;

    const char* eventName = event->name;
    rbusValue_t valBuff = rbusObject_GetValue(event->data, NULL );

    if((valBuff == NULL) || (eventName == NULL))
    {
        CcspTraceError(("%s : FAILED , value is NULL\n",__FUNCTION__));
        return;
    }

    PIDM_DML_INFO pidmDmlInfo = IdmMgr_GetConfigData_locked();
    if( pidmDmlInfo == NULL )
    {
        return  ANSC_STATUS_FAILURE;
    }

    RecvSubscriptionList *req = headRecvSubscriptionList;

    while(req != NULL)
    {
        if (strcmp(eventName, req->param_name) == 0)
        {
            IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
            payload_t payload;
            memset(&payload, 0, sizeof(payload_t));
            payload.operation = IDM_SUBS;
            payload.msgType = RES;
            payload.reqID = req->reqId;
            strncpy(payload.Mac_source,remoteDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE);
            strncpy(payload.param_name,req->param_name,sizeof(payload.param_name));
            //Convert rbus value to string.
            rbusValue_ToString(valBuff,payload.param_value,sizeof(payload.param_value));
            payload.status =  ANSC_STATUS_SUCCESS;

            while(remoteDevice!=NULL)
            {
                if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, req->Mac_dest) == 0)
                {
                    if(remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0)
                        send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
                    break;
                }
                remoteDevice=remoteDevice->next;
            }

        }
        req = req->next;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
}
void IDM_SFT_receive(connection_info_t* conn_info,payload_t* payload)
{
    CcspTraceDebug(("Inside %s:%d\n",__FUNCTION__,__LINE__));
    char* buf;
    int retry=0,bytes=0,length=0,total_bytes=0,send_start=0;
    if(payload != NULL)
    {
        total_bytes=atoi(payload->param_value);
        CcspTraceInfo(("%s file with size %d will be transferred\n",payload->param_name,total_bytes));

        FILE* fptr;
        fptr = fopen(payload->param_name,"wb");
        if(!fptr){
            CcspTraceError(("file not found\n"));
#ifndef IDM_DEBUG
            if(conn_info->enc.ssl != NULL)
            {
                SSL_write(conn_info->enc.ssl,"not found",strlen("not found"));
            }
#else
            send(conn_info->conn,"not found",strlen("not found"),0);
#endif
            return;
        }
        else
        {
            buf = (char*) malloc(total_bytes);
            while(total_bytes > 0 && length<total_bytes)
            {
#ifndef IDM_DEBUG
                if(conn_info->enc.ssl != NULL)
                {
                    if(send_start == 0 && (bytes = SSL_write(conn_info->enc.ssl,"start",strlen("start")) <= 0 ))
                    {
                        retry++;
                        CcspTraceError(("acknowledgement not transformed\n"));
                    }
                    else
                    {
                        send_start = 1;
                        bytes = SSL_read(conn_info->enc.ssl, buf, total_bytes-bytes);
                    }
                }
                else
                {
                    CcspTraceError(("%s:%d ssl session is null\n",__FUNCTION__,__LINE__));
                    break;
                }
#else
                if(send_start == 0 && (bytes = send(conn_info->conn,"start",strlen("start"),0) <= 0 ))
                {
                    retry++;
                    CcspTraceError(("acknowledgement not transformed\n"));
                }
                else
                {
                    send_start = 1;
                    bytes = read( conn_info->conn , buf, total_bytes-bytes);
                }
#endif
                CcspTraceInfo(("bytes transfered : %d\n",bytes));
                if(bytes > 0)
                {
                    fwrite(buf,1,bytes,fptr);
                    length+=bytes;
                }
                else
                {
                    CcspTraceError(("(%s:%d) Data encryption failed (Err: %d)\n", __FUNCTION__, __LINE__,bytes));
                }
                if(retry>30)
                {
                    CcspTraceError(("break the loop as we failed to send acknowledgement for 30 times\n"));
                    break;
                }
            }
        }
        fclose(fptr);
        if(buf)
        {
            free(buf);
        }
    }
    else
    {
        CcspTraceError(("%s:%d payload is null\n",__FUNCTION__, __LINE__));
    }
}

int IDM_Incoming_Request_handler(payload_t * payload)
{
    CcspTraceInfo(("%s %d - \n", __FUNCTION__, __LINE__));

    if(payload->operation == IDM_SUBS)
    {
        /*Create entry in incoming subscription list */
        RecvSubscriptionList *getReq =  malloc(sizeof(RecvSubscriptionList));
        memset(getReq, 0, sizeof(RecvSubscriptionList));
        strncpy(getReq->Mac_dest, payload->Mac_source,sizeof(getReq->Mac_dest));
        strncpy(getReq->param_name, payload->param_name,sizeof(getReq->param_name));
        getReq->reqId = payload->reqID;
        IDM_addToReceivedSubscriptionList(getReq);

        //TODO: check timeout and userdata
        rbusEvent_Subscribe(rbusHandle, payload->param_name, IDM_Rbus_subscriptionEventHandler, NULL, 0);


    }else
    {
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
        strncpy(getReq->pComponent_name, payload->pComponent_name,sizeof(getReq->pComponent_name));
        strncpy(getReq->pBus_path, payload->pBus_path,sizeof(getReq->pBus_path));
        getReq->next = NULL;
        IDM_addToReceivedReqList(getReq);
    }
    return 0;
}

void IDM_Incoming_req_handler_thread()
{
    // event handler
    int n = 0;
    struct timeval tv;

    PIDM_DML_INFO pidmDmlInfo = NULL;
    while(true)
    {
        /* Wait up to 250 milliseconds */
        tv.tv_sec = 0;
        tv.tv_usec = 250000;

        n = select(0, NULL, NULL, NULL, &tv);
        if (n < 0)
        {
            /* interrupted by signal or something, continue */
            continue;
        }
        RecvReqList *ReqEntry = IDM_ReceivedReqList_pop();
        if(ReqEntry!= NULL)
        {
            payload_t payload;
            memset(&payload, 0, sizeof(payload_t));

            CcspTraceInfo(("%s %d -processing request from %s \n \tparamName %s \n", __FUNCTION__, __LINE__,ReqEntry->Mac_dest, ReqEntry->param_name));
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
                        ReqEntry->pComponent_name,
                        ReqEntry->pBus_path,
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
                        ReqEntry->pComponent_name,
                        ReqEntry->pBus_path,
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

            }else if(ReqEntry->operation == GFT)
            {
                IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
                payload.reqID = ReqEntry->reqId;
                payload.operation = ReqEntry->operation;
                payload.msgType = GFT;
                strncpy(payload.Mac_source,remoteDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE);
                strncpy(payload.param_name,ReqEntry->param_name,sizeof(payload.param_name));
                //Find the device using MAC
                while(remoteDevice!=NULL)
                {
                    CcspTraceDebug(("Inside %s:%d remote device MAC=%s\n",__FUNCTION__,__LINE__,remoteDevice->stRemoteDeviceInfo.MAC));
                    if(strcasecmp(remoteDevice->stRemoteDeviceInfo.MAC, ReqEntry->Mac_dest) == 0 && (remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED ))
                    {
                        if(remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0)
                        {
                            getFile_to_remote(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
                        }
                        break;
                    }
                    remoteDevice=remoteDevice->next;
                }
                IdmMgrDml_GetConfigData_release(pidmDmlInfo);
                free(ReqEntry);
                continue;
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


void IDM_Broadcast_LocalDeviceInfo()
{
    PIDM_DML_INFO pidmDmlInfo = NULL;
    /*Create Payload */
    payload_t payload;
    memset(&payload, 0, sizeof(payload_t));

    pidmDmlInfo = IdmMgr_GetConfigData_locked();
    IDM_REMOTE_DEVICE_LINK_INFO *remoteDevice = pidmDmlInfo->stRemoteInfo.pstDeviceLink;
    if( pidmDmlInfo == NULL )
    {
        payload.status =  ANSC_STATUS_FAILURE;
    }
    /*get local deivce struct */
    memcpy(payload.param_value, &(pidmDmlInfo->stRemoteInfo.pstDeviceLink->stRemoteDeviceInfo),sizeof(IDM_REMOTE_DEVICE_INFO));
    payload.status =  ANSC_STATUS_SUCCESS;

    payload.reqID = -1; //It's an Async message reqID not avaiable.
    payload.operation = IDM_REQUEST;
    payload.msgType = RES;
    strncpy(payload.Mac_source,remoteDevice->stRemoteDeviceInfo.MAC,MAC_ADDR_SIZE);

    remoteDevice=remoteDevice->next; 
    while(remoteDevice!=NULL)
    {
        if(remoteDevice->stRemoteDeviceInfo.Status == DEVICE_CONNECTED)
        {
            if(remoteDevice->stRemoteDeviceInfo.conn_info.conn !=0)
                send_remote_message(&remoteDevice->stRemoteDeviceInfo.conn_info, &payload);
        }
        remoteDevice=remoteDevice->next;
    }
    IdmMgrDml_GetConfigData_release(pidmDmlInfo);
}

