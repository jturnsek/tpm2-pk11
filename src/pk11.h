/*
 * This file is part of tpm2-pk11.
 * Copyright (C) 2017 Jernej Turnsek
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

#ifndef PK11_H_
#define PK11_H_

#include <stdint.h>
#include <p11-kit/pkcs11.h>
#include "asn1.h"

#define TPM2_PK11_CONFIG_DIR ".tpm2"
#define TPM2_PK11_CONFIG_FILE "config"

#define TPM2_PK11_LABEL "TPM2"
#define TPM2_PK11_SLOT_DESCRIPTION "TPM2 PKCS11 slot"
#define TPM2_PK11_MANUFACTURER "Iskraemeco,d.d."
#define TPM2_PK11_LIBRARY_DESCRIPTION "TPM2 PKCS11 Library"
#define TPM2_PK11_MODEL "TPM2"
#define TPM2_PK11_SERIAL "123456789"
#define LIBRARY_VERSION_MAJOR   1
#define LIBRARY_VERSION_MINOR   1

typedef struct pkcs_object_t {
  void* id;
  size_t id_size;
  CK_OBJECT_CLASS class;
} PkcsObject, *pPkcsObject;

typedef struct pkcs_key_t {
  CK_BBOOL sign;
  CK_BBOOL verify;
  CK_BBOOL decrypt;
  CK_BBOOL encrypt;
  CK_KEY_TYPE key_type;
} PkcsKey, *pPkcsKey;

typedef struct pkcs_rsa_public_key_t {
  void* modulus;
  size_t modulus_size;
  CK_ULONG bits;
  uint32_t exponent;
} PkcsRSAPublicKey, *pPkcsRSAPublicKey;

typedef struct pkcs_ec_public_key_t {
  chunk_t ec_params;
  chunk_t ec_point;
} PkcsECPublicKey, *pPkcsECPublicKey;

typedef union pkcs_public_key_t {
  PkcsRSAPublicKey rsa; 
  PkcsECPublicKey ec;
} PkcsPublicKey, *pPkcsPublicKey;

typedef struct pkcs_x509_t {
  char* value;
  size_t value_size;
} PkcsX509, *pPkcsX509;

#endif /** PK11_H_ */