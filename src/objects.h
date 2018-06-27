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
#include <stddef.h>
#include <stdbool.h>
#include <p11-kit/pkcs11.h>
#include <sapi/tpm20.h>

#define NELEMS(x) (sizeof(x) / sizeof((x)[0]))

#define attr_index_of(type, struct, attribute) {type, offsetof(struct, attribute), sizeof(((struct*)0)->attribute), 0}
#define attr_dynamic_index_of(type, struct, attribute, size_attribute) {type, offsetof(struct, attribute), 0, offsetof(struct, size_attribute)}
#define attr_index_entry(object, index) {object, index, NELEMS(index)}

typedef struct attr_index_t {
  CK_ATTRIBUTE_TYPE type;
  size_t offset;
  size_t size;
  size_t size_offset;
} AttrIndex, *pAttrIndex;

typedef struct attr_index_entry_t {
  void* object;
  pAttrIndex indexes;
  size_t num_attrs;
} AttrIndexEntry, *pAttrIndexEntry;

typedef struct object_t {
  void* userdata;
  pAttrIndexEntry entries;
  size_t num_entries;
  TPMI_DH_OBJECT tpm_handle;
  struct object_t *opposite;
  bool is_certificate;
} Object, *pObject;

typedef struct pkcs_object_t {
  void* id;
  size_t id_size;
  char* label;
  size_t label_size;
  CK_OBJECT_CLASS class;
  CK_BBOOL token;
} PkcsObject, *pPkcsObject;

typedef struct pkcs_key_t {
  CK_BBOOL sign;
  CK_BBOOL verify;
  CK_BBOOL decrypt;
  CK_BBOOL encrypt;
  CK_KEY_TYPE key_type;
} PkcsKey, *pPkcsKey;

typedef struct pkcs_rsa_public_key_t {
  uint32_t exponent;
} PkcsRSAPublicKey, *pPkcsRSAPublicKey;

typedef struct pkcs_modulus_t {
  void* modulus;
  size_t modulus_size;
  CK_ULONG bits;
} PkcsModulus, *pPkcsModulus;

typedef struct pkcs_ec_public_key_t {
  void* ec_params;
  size_t ec_params_len;
  void* ec_point;
  size_t ec_point_len;
} PkcsECPublicKey, *pPkcsECPublicKey;

typedef struct pkcs_ec_private_key_t {
  void* ec_params;
  size_t ec_params_len;
} PkcsECPrivateKey, *pPkcsECPrivateKey;

typedef union pkcs_public_key_t {
  PkcsRSAPublicKey rsa; 
  PkcsECPublicKey ec;
} PkcsPublicKey, *pPkcsPublicKey;

typedef union pkcs_private_key_t { 
  PkcsECPrivateKey ec;
} PkcsPrivateKey, *pPkcsPrivateKey;

typedef struct pkcs_x509_t {
  char* value;
  size_t value_size;
  char* subject;
  size_t subject_size;
  char* issuer;
  size_t issuer_size;
  char* serial;
  size_t serial_size;
  CK_CERTIFICATE_TYPE cert_type;
} PkcsX509, *pPkcsX509;

typedef struct object_list_t {
  pObject object;
  struct object_list_t* next;
} ObjectList, *pObjectList;

extern AttrIndex OBJECT_INDEX[4];
extern AttrIndex KEY_INDEX[5];
extern AttrIndex PUBLIC_KEY_RSA_INDEX[1];
extern AttrIndex MODULUS_INDEX[2];
extern AttrIndex PUBLIC_KEY_EC_INDEX[2];
extern AttrIndex PRIVATE_KEY_EC_INDEX[1];
extern AttrIndex CERTIFICATE_INDEX[5];

void* object_attr_get(pObject object, CK_ATTRIBUTE_TYPE type, size_t *size);
int object_attr_set(pObject object, CK_ATTRIBUTE_TYPE type, void* value, size_t size);
int object_attr_write(pObject object, struct config *config);
void object_add(pObjectList list, pObject object);
void object_remove(pObjectList *list, pObject object);
int object_delete(pObject object, struct config *config);
void object_free_list(pObjectList list);
pObjectList object_load_list(TSS2_SYS_CONTEXT *ctx, struct config *config);
pObject object_generate_pair(TSS2_SYS_CONTEXT *ctx, TPM2_ALG_ID algorithm, pObjectList list, struct config *config);

#endif /** OBJECTS_H_ */
