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

extern ANSC_HANDLE  bus_handle;
extern char         g_Subsystem[32];

ANSC_STATUS addDevice(IDM_REMOTE_DEVICE_LINK_INFO *newNode, IDM_DML_LINK_LIST *sidmDmlListInfo)
{
    if(NULL == newNode || NULL == sidmDmlListInfo)
        return ANSC_STATUS_FAILURE;

    IDM_REMOTE_DEVICE_LINK_INFO *tmp = NULL;
    IDM_REMOTE_DEVICE_LINK_INFO *head = sidmDmlListInfo->pListHead;

    if(head == NULL)
    {
        sidmDmlListInfo->pListHead = newNode;
        sidmDmlListInfo->pListTail = sidmDmlListInfo->pListHead;
        sidmDmlListInfo->pListHead->next = NULL;
        return ANSC_STATUS_SUCCESS;
    }
    
    IDM_REMOTE_DEVICE_LINK_INFO *tail = sidmDmlListInfo->pListTail;

    // we should have a tail node
    if(tail == NULL)
        return ANSC_STATUS_FAILURE;

    //update pidmDmlInfo->stRemoteInfo
    tail->next = newNode;
    tail->next->next = NULL;

    sidmDmlListInfo->pListTail = newNode;
    CcspTraceInfo(("%s %d - new Device has been added\n", __FUNCTION__, __LINE__));

    return ANSC_STATUS_SUCCESS;
}

ANSC_STATUS updateDeviceStatus(IDM_DML_LINK_LIST *sidmDmlListInfo, uint32_t index, uint32_t newStatus)
{
    if(NULL == sidmDmlListInfo)
        return ANSC_STATUS_FAILURE;

    IDM_REMOTE_DEVICE_LINK_INFO *head = sidmDmlListInfo->pListHead;

    while(head != NULL)
    {
        CcspTraceInfo(("%s %d - Head is not NULL. Index is %d\n", __FUNCTION__, __LINE__,head->stRemoteDeviceInfo.Index ));
        if(head->stRemoteDeviceInfo.Index == index)
        {
            head->stRemoteDeviceInfo.Status = newStatus;
            CcspTraceInfo(("%s %d - Device %d status updated to %d\n", __FUNCTION__, __LINE__, index, newStatus ));
            return ANSC_STATUS_SUCCESS;
        }
        head=head->next;
    }
    CcspTraceInfo(("%s %d - Failed to update status for device %d\n", __FUNCTION__, __LINE__, index ));

    return ANSC_STATUS_FAILURE;
}

EVENT_DATA_TYPES getEventType(char *event)
{
    if(event != NULL)
    {
        if(strstr(event, ".MAC") || strstr(event, ".IPv4") || strstr(event, ".IPv6") || 
                strstr(event, ".Capabilities") || strstr(event, ".ModelNumber"))
            return EV_STRING;

        if(strstr(event, ".Status") || strstr(event, ".HelloInterval"))
            return EV_INTEGER;
    }
}

// Retun device node corresponding to index
//eg: Device.2.Status . 2 is the index. Get node for 2nd device
IDM_REMOTE_DEVICE_LINK_INFO* getRmDeviceNode(const IDM_DML_LINK_LIST sidmDmlListInfo, uint32_t index)
{

    IDM_REMOTE_DEVICE_LINK_INFO *head = sidmDmlListInfo.pListHead;

     while(head != NULL)
    {
        CcspTraceInfo(("%s %d - Head is not NULL. Index is %d\n", __FUNCTION__, __LINE__,head->stRemoteDeviceInfo.Index ));
        if(head->stRemoteDeviceInfo.Index == index)
        {
            
            CcspTraceInfo(("%s %d - Device found for index %d\n", __FUNCTION__, __LINE__, index));
            return head;
        }
        head = head->next;
    }
    return NULL;
}

ANSC_STATUS updteSubscriptionStatus(char *event, IDM_RBUS_SUBS_STATUS *sidmRmSubStatus)
{

    if(event == NULL || sidmRmSubStatus == NULL)
        return ANSC_STATUS_FAILURE;   
 
    if(strstr(event, ".Status"))
        sidmRmSubStatus->idmRmStatusSubscribed = TRUE;
    else if(strstr(event, ".MAC"))
        sidmRmSubStatus->idmRmHelloIntervalSubscribed = TRUE;
    else if(strstr(event, ".IPv4"))
        sidmRmSubStatus->idmRmIPv4Subscribed = TRUE;
    else if(strstr(event, ".IPv6"))
        sidmRmSubStatus->idmRmIPv6Subscribed = TRUE;
    else if(strstr(event, ".Capabilities"))
        sidmRmSubStatus->idmRmCapSubscribed = TRUE;
    else if(strstr(event, ".HelloInterval"))
        sidmRmSubStatus->idmRmCapSubscribed = TRUE;
    else if(strstr(event, ".ModelNumber"))
        sidmRmSubStatus->idmRmModelNumSubscribed = TRUE;
    else if(strcmp(event, "RM_NEW_DEVICE") == 0)
        sidmRmSubStatus->idmRmNewDeviceSubscribed = TRUE;
    else
    {
        CcspTraceInfo(("%s %d - Failed to update subscripton status for %s\n", __FUNCTION__, __LINE__, event));
        return ANSC_STATUS_FAILURE;    
    }

    CcspTraceInfo(("%s %d - Updatig subscription status for %s\n", __FUNCTION__, __LINE__, event));
    return ANSC_STATUS_SUCCESS;
}


int IDMMgr_RdkBus_GetParamValuesFromDB( char *pParamName, char *pReturnVal, int returnValLength )
{
    int     retPsmGet     = CCSP_SUCCESS;
    CHAR   *param_value   = NULL, tmpOutput[256] = {0};
    /* Input Validation */
    if( ( NULL == pParamName) || ( NULL == pReturnVal ) || ( 0 >= returnValLength ) )
    {
        CcspTraceError(("%s Invalid Input Parameters\n",__FUNCTION__));
        return CCSP_FAILURE;
    }
    retPsmGet = PSM_Get_Record_Value2(bus_handle, g_Subsystem, pParamName, NULL, &param_value);
    if (retPsmGet != CCSP_SUCCESS)
    {
        CcspTraceError(("%s Error %d reading %s\n", __FUNCTION__, retPsmGet, pParamName));
    }
    else
    {
        /* Copy DB Value */
        snprintf(pReturnVal, returnValLength, "%s", param_value);
        ((CCSP_MESSAGE_BUS_INFO *)bus_handle)->freefunc(param_value);
    }
   return retPsmGet;
}

int IDMMgr_RdkBus_SetParamValuesToDB( char *pParamName, char *pParamVal )
{
    int     retPsmSet  = CCSP_SUCCESS;
    /* Input Validation */
    if( ( NULL == pParamName) || ( NULL == pParamVal ) )
    {
        CcspTraceError(("%s Invalid Input Parameters\n",__FUNCTION__));
        return CCSP_FAILURE;
    }
    retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, pParamName, ccsp_string, pParamVal);
    if (retPsmSet != CCSP_SUCCESS)
    {
        CcspTraceError(("%s Error %d writing %s\n", __FUNCTION__, retPsmSet, pParamName));
    }
    return retPsmSet;
}
