/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Smartcard logon
 *
 * Copyright 2017 Dorian Ducournau <dorian.ducournau@gmail.com>
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

#ifndef LIBFREERDP_CORE_SMARTCARDLOGON_H
#define LIBFREERDP_CORE_SMARTCARDLOGON_H

#include <pkcs11-helper-1.0/pkcs11.h>

#include <freerdp/freerdp.h>


#define AT_KEYEXCHANGE 1
#define AT_SIGNATURE   2
#define AT_AUTHENTICATE   3


/*
get_info_smartcard
returns 0 upon success.
*/
int get_info_smartcard(freerdp* instance);



#endif
