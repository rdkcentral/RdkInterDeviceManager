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

#include "inter_device_manager_internal.h"
#include "inter_device_manager_plugin_main_apis.h"
#include "inter_device_manager_global.h"

/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        BackEndManagerCreate
            (
            );

    description:

        This function constructs datamodel object and return handle.

    argument:

    return:     newly created qos object.

**********************************************************************/

ANSC_HANDLE
BackEndManagerCreate
    (
        VOID
    )
{
    CcspTraceInfo(("Enter %s", __func__));
    ANSC_STATUS                returnStatus = ANSC_STATUS_SUCCESS;
    PBACKEND_MANAGER_OBJECT    pMyObject    = (PBACKEND_MANAGER_OBJECT)NULL;

    /*
        * We create object by first allocating memory for holding the variables and member functions.
        */
    pMyObject = (PBACKEND_MANAGER_OBJECT) AnscAllocateMemory(sizeof(BACKEND_MANAGER_OBJECT));

    if (!pMyObject)
    {
        return  (ANSC_HANDLE)NULL;
    }
    pMyObject->pIDMDeviceInfo        = (PIDM_DEVICE_INFO) AnscAllocateMemory(sizeof(IDM_DEVICE_INFO));

    if (!pMyObject->pIDMDeviceInfo)
    {
        return  (ANSC_HANDLE)NULL;
    }
    memset (pMyObject->pIDMDeviceInfo, 0, sizeof(IDM_DEVICE_INFO));

    pMyObject->pIDMDeviceInfo->pdeviceList = (PIDM_DEVICE_LIST) AnscAllocateMemory(sizeof(IDM_DEVICE_LIST) * 1);

    if (!pMyObject->pIDMDeviceInfo->pdeviceList)
    {
        return  (ANSC_HANDLE)NULL;
    }
    memset (pMyObject->pIDMDeviceInfo->pdeviceList, 0, sizeof(IDM_DEVICE_LIST));

    /*
     * Initialize the common variables and functions for a container object.
     */
    pMyObject->Oid               = DATAMODEL_BASE_OID;
    pMyObject->Create            = BackEndManagerCreate;
    pMyObject->Remove            = BackEndManagerRemove;
    pMyObject->Initialize        = BackEndManagerInitialize;

    return  (ANSC_HANDLE)pMyObject;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        BackEndManagerRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function remove manager object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
BackEndManagerRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBACKEND_MANAGER_OBJECT         pMyObject    = (PBACKEND_MANAGER_OBJECT)hThisObject;

    if (pMyObject == NULL)
    {
        AnscTraceError(("%s:%d:: Pointer is null!!\n", __FUNCTION__, __LINE__));
        return ANSC_STATUS_FAILURE;
    }

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        BackEndManagerInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate manager object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
BackEndManagerInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    CcspTraceInfo(("Enter %s", __func__));
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PBACKEND_MANAGER_OBJECT  pMyObject    = (PBACKEND_MANAGER_OBJECT)hThisObject;

    if (pMyObject == NULL || pMyObject->pIDMDeviceInfo == NULL || pMyObject->pIDMDeviceInfo->pdeviceList == NULL)
    {
        AnscTraceError(("%s:%d:: Pointer is null!!\n", __FUNCTION__, __LINE__));
        //return ANSC_STATUS_FAILURE;
    }

    if (syscfg_init() != 0)
    {
        AnscTraceError(("%s:%d:: syscfg_init failed \n", __FUNCTION__, __LINE__));
    }

    return ANSC_STATUS_SUCCESS;
}
