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
/*
 * Copyright [2014] [Cisco Systems, Inc.]
 * Licensed under the Apache License, Version 2.0
 */

#ifndef  _IDM_GLOBAL_H
#define  _IDM_GLOBAL_H

#include <time.h>
#include "ccsp_trace.h"
#include "ansc_status.h"
#include "ansc_debug_wrapper_base.h"
#include "ansc_common_structures.h"
#include "slap_definitions.h"

#ifndef WIN32
#include "ccsp_message_bus.h"
#endif

#include "ccsp_base_api.h"

#include "slap_vco_exported_api.h"

#include "dslh_ifo_mpa.h"
#include "dslh_dmagnt_interface.h"
#include "dslh_dmagnt_exported_api.h"

#include "ccsp_ifo_ccd.h"
#include "ccc_ifo_mbi.h"

#include "messagebus_interface_helper.h"
#include "dslh_cpeco_interface.h"
#include "dslh_cpeco_exported_api.h"
#include "safec_lib_common.h"
#include "user_socket.h"
#include "ansc_platform.h"

#include "ansc_string.h"

#endif
