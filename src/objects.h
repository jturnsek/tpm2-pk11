/*
 * This file is part of tpm2-pk11.
 * Copyright (C) 2018 Jernej Turnsek
 * Copyright (C) 2017 Iwan Timmer
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef OBJECTS_H_
#define OBJECTS_H_

#include "config.h"
#include "object.h"

#include <sapi/tpm20.h>

extern AttrIndex OBJECT_INDEX[4];
extern AttrIndex KEY_INDEX[5];
extern AttrIndex PUBLIC_KEY_RSA_INDEX[1];
extern AttrIndex MODULUS_INDEX[2];
extern AttrIndex PUBLIC_KEY_EC_INDEX[2];
extern AttrIndex CERTIFICATE_INDEX[5];

typedef struct object_list_t {
  pObject object;
  struct object_list_t* next;
} ObjectList, *pObjectList;

pObject object_get(pObjectList list, int id);
void object_add(pObjectList list, pObject object);
void object_free(pObjectList list);

pObjectList object_load(TSS2_SYS_CONTEXT *ctx, struct config *config);
pObject object_generate_pair(TSS2_SYS_CONTEXT *ctx, TPM2_ALG_ID algorithm);
void object_destroy_pair(TSS2_SYS_CONTEXT *ctx, pObject object);

#endif /** OBJECTS_H_ */
