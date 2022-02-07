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

#include "inter_device_manager_plugin_main_apis.h"
#include "inter_device_manager_dml.h"
#include "inter_device_manager_global.h"

extern PBACKEND_MANAGER_OBJECT g_pBEManager;

/**********************************************************************
    caller:     owner of this object
    prototype:
        ULONG
        IDM_Conn_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );
    description:
        This function is called to retrieve string parameter value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pValue,
                The string value buffer;
                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;
    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.
**********************************************************************/

ULONG
IDM_Conn_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PIDM_DEVICE_INFO pMyObject = (PIDM_DEVICE_INFO) g_pBEManager->pIDMDeviceInfo;

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "HelloIPv4SubnetList", TRUE) )
    {
        if ( strlen(pMyObject->ipv4) >= *pUlSize )
        {
            *pUlSize = strlen(pMyObject->ipv4);
            return 1;
        }

        AnscCopyString(pValue, pMyObject->ipv4);
        return 0;
    }
    return -1;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        ULONG
        IDM_Conn_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );
    description:
        This function is called to set string parameter value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pValue,
                The string value buffer;
    return:     TRUE if succeeded;
                FALSE if failed
**********************************************************************/

BOOL
IDM_Conn_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue
    )
{
    PIDM_DEVICE_INFO pMyObject = (PIDM_DEVICE_INFO) g_pBEManager->pIDMDeviceInfo;

    if( AnscEqualString(ParamName, "HelloIPv4SubnetList", TRUE))
    {
        AnscCopyString(pMyObject->ipv4, pValue);
        return TRUE;
    }
    return FALSE;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        BOOL
        IDM_Conn_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      pInt
            );

    description:
        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      pInt
                The buffer of returned integer value;

    return:     ULONG if succeeded.
    		
**********************************************************************/
ULONG
IDM_Conn_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pInt
    )
{
    PIDM_DEVICE_INFO pMyObject = (PIDM_DEVICE_INFO) g_pBEManager->pIDMDeviceInfo;

    if( AnscEqualString(ParamName, "HelloInterval", TRUE))
    {
        return pMyObject->helloInterval;
    }    
    return -1;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        BOOL
        IDM_Conn_SetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG                       uValue
            );

    description:

        This function is called to set ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG                       uValue
                The updated ULONG value;

    return:     TRUE if succeeded.

**********************************************************************/

BOOL
IDM_Conn_SetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG                       uValue
    )
{
    PIDM_DEVICE_INFO pMyObject = (PIDM_DEVICE_INFO) g_pBEManager->pIDMDeviceInfo;

    if( AnscEqualString(ParamName, "HelloInterval", TRUE))
    {
        pMyObject->helloInterval = uValue;
	return TRUE;
    }
    return FALSE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IDM_Conn_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
IDM_Conn_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IDM_Conn_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
IDM_Conn_Commit
    (
        ANSC_HANDLE                 hInsContext
    )

{
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IDM_Conn_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
IDM_Conn_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        BOOL
        IDM_Remote_GetParamBoolValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                BOOL*                       pBool
            );
    description:
        This function is called to retrieve Boolean parameter value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                BOOL*                       pBool
                The buffer of returned boolean value;
    return:     TRUE if succeeded.
**********************************************************************/
BOOL
IDM_Remote_GetParamBoolValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        BOOL*                       pBool
    )
{
    return TRUE;
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        ULONG
        IDM_Conn_SetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );
    description:
        This function is called to set string parameter value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pValue,
                The string value buffer;
    return:     0 if succeeded;
                -1 if failed
		1 if buffer shortage
**********************************************************************/
ULONG
IDM_Remote_SetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    PIDM_DEVICE_INFO pMyObject = (PIDM_DEVICE_INFO) g_pBEManager->pIDMDeviceInfo;

    /* check the parameter name and return the corresponding value */
    if( AnscEqualString(ParamName, "AddDeviceCapabilities", TRUE) )
    {
        /* collect value */
        if ( strlen(pMyObject->capabilities) >= *pUlSize )
        {
            *pUlSize = strlen(pMyObject->capabilities);
            return 1;
        }

        AnscCopyString(pMyObject->capabilities, pValue);
        return 0;
    }
    return -1;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        BOOL
        IDM_Remote_Validate
            (
                ANSC_HANDLE                 hInsContext,
                char*                       pReturnParamName,
                ULONG*                      puLength
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       pReturnParamName,
                The buffer (128 bytes) of parameter name if there's a validation. 

                ULONG*                      puLength
                The output length of the param name. 

    return:     TRUE if there's no validation.

**********************************************************************/
BOOL
IDM_Remote_Validate
    (
        ANSC_HANDLE                 hInsContext,
        char*                       pReturnParamName,
        ULONG*                      puLength
    )
{
    return TRUE;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IDM_Remote_Commit
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to finally commit all the update.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
IDM_Remote_Commit
    (
        ANSC_HANDLE                 hInsContext
    )

{
    return 0;
}

/**********************************************************************  

    caller:     owner of this object 

    prototype: 

        ULONG
        IDM_Remote_Rollback
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to roll back the update whenever there's a 
        validation found.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The status of the operation.

**********************************************************************/
ULONG
IDM_Remote_Rollback
    (
        ANSC_HANDLE                 hInsContext
    )
{
    return ANSC_STATUS_SUCCESS;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ULONG
        IDM_RemoteList_GetEntryCount
            (
                ANSC_HANDLE                 hInsContext
            );

    description:

        This function is called to retrieve the count of the table.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

    return:     The count of the table

**********************************************************************/
ULONG
IDM_RemoteList_GetEntryCount
    (
        ANSC_HANDLE                 hInsContext
    )
{
    PIDM_DEVICE_INFO pMyObject = (PIDM_DEVICE_INFO) g_pBEManager->pIDMDeviceInfo;
    return pMyObject->numberOfDevices;
}

/**********************************************************************

    caller:     owner of this object

    prototype:

        ANSC_HANDLE
        IDM_RemoteList__GetEntry
            (
                ANSC_HANDLE                 hInsContext,
                ULONG                       nIndex,
                ULONG*                      pInsNumber
            );

    description:

        This function is called to retrieve the entry specified by the index.

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                ULONG                       nIndex,
                The index of this entry;

                ULONG*                      pInsNumber
                The output instance number;

    return:     The handle to identify the entry

**********************************************************************/
ANSC_HANDLE
IDM_RemoteList_GetEntry
    (
        ANSC_HANDLE                 hInsContext,
        ULONG                       nIndex,
        ULONG*                      pInsNumber
    )
{
    PIDM_DEVICE_INFO pMyObject = (PIDM_DEVICE_INFO) g_pBEManager->pIDMDeviceInfo;
    *pInsNumber = nIndex + 1;
    return (&pMyObject->pdeviceList[nIndex]);
}

/**********************************************************************
    caller:     owner of this object
    prototype:
        ULONG
        IDM_RemoteList_GetParamStringValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                char*                       pValue,
                ULONG*                      pUlSize
            );
    description:
        This function is called to retrieve string parameter value;
    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;
                char*                       ParamName,
                The parameter name;
                char*                       pValue,
                The string value buffer;
                ULONG*                      pUlSize
                The buffer of length of string value;
                Usually size of 1023 will be used.
                If it's not big enough, put required size here and return 1;
    return:     0 if succeeded;
                1 if short of buffer size; (*pUlSize = required size)
                -1 if not supported.
**********************************************************************/

ULONG
IDM_RemoteList_GetParamStringValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        char*                       pValue,
        ULONG*                      pUlSize
    )
{
    return -1;
}

/**********************************************************************
    caller:     owner of this object

    prototype:
        BOOL
        IDM_RemoteList_GetParamUlongValue
            (
                ANSC_HANDLE                 hInsContext,
                char*                       ParamName,
                ULONG*                      pInt
            );

    description:
        This function is called to retrieve ULONG parameter value;

    argument:   ANSC_HANDLE                 hInsContext,
                The instance handle;

                char*                       ParamName,
                The parameter name;

                ULONG*                      pInt
                The buffer of returned integer value;

    return:     TRUE if succeeded.
**********************************************************************/
BOOL
IDM_RemoteList_GetParamUlongValue
    (
        ANSC_HANDLE                 hInsContext,
        char*                       ParamName,
        ULONG*                      pInt
    )
{
    return 0;
}

