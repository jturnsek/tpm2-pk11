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

#include "objects.h"
#include "certificate.h"
#include "tpm.h"
#include "pk11.h"
#include "asn.h"
#include "log.h"

#include <stdio.h>
#include <endian.h>
#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#include <glob.h>


typedef struct userdata_tpm_t {
  TPM2B_PUBLIC tpm_key;
  TPM2B_NAME name;
  CK_UTF8CHAR label[256];
  PkcsObject public_object, private_object;
  PkcsKey key;
  PkcsPublicKey public_key;
  PkcsModulus modulus;
} UserdataTpm, *pUserdataTpm;


static inline int hex_to_char(int c)
{
  return c >= 10 ? c - 10 + 'A' : c + '0';
}

pObject object_get(pObjectList list, int id)
{
  while (list != NULL) {
    if (list->object != NULL && list->object->id == id)
      return list->object;
    list = list->next;
  }
  return NULL;
}

void object_add(pObjectList list, pObject object)
{
  if (list->object == NULL)
    list->object = object;
  else {
    pObjectList next = list->next;
    list->next = malloc(sizeof(ObjectList));
    list->next->object = object;
    list->next->next = next;
  }
}

pObject object_generate_pair(TSS2_SYS_CONTEXT *ctx, TPM2_ALG_ID algorithm)
{
  TPMI_DH_OBJECT persistent;
  pObject public_object = NULL;
  pUserdataTpm userdata = malloc(sizeof(UserdataTpm));
  if (userdata == NULL) {
    return NULL;
  }
  memset(userdata, 0, sizeof(UserdataTpm));
  userdata->name.size = sizeof(TPMU_NAME);
  TPM2_RC rc = tpm_generate_key_pair(ctx, algorithm, &userdata->tpm_key, &userdata->name, &persistent);
  if (rc != TPM2_RC_SUCCESS) {
    free(userdata);
    return NULL;
  }

  if (userdata->tpm_key.publicArea.type == TPM2_ALG_RSA) {
    TPM2B_PUBLIC_KEY_RSA *rsa_key = &userdata->tpm_key.publicArea.unique.rsa;
    TPMS_RSA_PARMS *rsa_key_parms = &userdata->tpm_key.publicArea.parameters.rsaDetail;
    /*
     * fill the label with the same value as the name (they both have
     * different uses ; some application never display the id but only
     * the label). Since the label is an UTF8 string, we need to
     * transform the binary name into a hexadecimal string.
     */
    size_t max_label_size = userdata->name.size;
    if (max_label_size >= sizeof(userdata->label) / 2) {
      max_label_size = sizeof(userdata->label) / 2;
    }
    for (size_t n = 0; n < max_label_size; ++n) {
      userdata->label[2 * n + 0] = hex_to_char(userdata->name.name[n] >> 4);
      userdata->label[2 * n + 1] = hex_to_char(userdata->name.name[n] & 0x0f);
    }

    userdata->public_object.id = userdata->name.name;
    userdata->public_object.id_size = userdata->name.size;
    userdata->public_object.label = userdata->label;
    userdata->public_object.label_size = max_label_size * 2;
    userdata->public_object.class = CKO_PUBLIC_KEY;
    userdata->public_object.token = CK_TRUE;
    userdata->private_object.id = userdata->name.name;
    userdata->private_object.id_size = userdata->name.size;
    userdata->private_object.label = userdata->label;
    userdata->private_object.label_size = max_label_size * 2;
    userdata->private_object.class = CKO_PRIVATE_KEY;
    userdata->private_object.token = CK_TRUE;
    userdata->key.sign = CK_TRUE;
    userdata->key.verify = CK_TRUE;
    userdata->key.decrypt = CK_TRUE;
    userdata->key.encrypt = CK_TRUE;
    userdata->key.key_type = CKK_RSA;
    userdata->modulus.modulus = rsa_key->buffer;
    userdata->modulus.modulus_size = rsa_key_parms->keyBits / 8;
    userdata->modulus.bits = rsa_key_parms->keyBits;
    userdata->public_key.rsa.exponent = htobe32(rsa_key_parms->exponent == 0 ? 65537 : rsa_key_parms->exponent);

    pObject object = malloc(sizeof(Object));
    if (object == NULL) {
      free(userdata);
      return NULL;
    }

    object->tpm_handle = 0;
    object->userdata = userdata;
    object->num_entries = 4;
    object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
    object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->public_object, OBJECT_INDEX);
    object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
    object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->public_key.rsa, PUBLIC_KEY_RSA_INDEX);
    object->entries[3] = (AttrIndexEntry) attr_index_entry(&userdata->modulus, MODULUS_INDEX);
    
    public_object = object;

    object = malloc(sizeof(Object));
    if (object == NULL) {
      free(userdata);
      free(public_object);
      return NULL;
    }

    object->tpm_handle = persistent;
    object->userdata = NULL;
    object->num_entries = 3;
    object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
    object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->private_object, OBJECT_INDEX);
    object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
    object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->modulus, MODULUS_INDEX);

    public_object->opposite = object;
    object->opposite = public_object;
  }
  else if (userdata->tpm_key.publicArea.type == TPM2_ALG_ECC) {
    TPMS_ECC_POINT *ecc = &userdata->tpm_key.publicArea.unique.ecc;
    asn_buf_t ecc_point;
    uint8_t *pos;
    /*
     * fill the label with the same value as the name (they both have
     * different uses ; some application never display the id but only
     * the label). Since the label is an UTF8 string, we need to
     * transform the binary name into a hexadecimal string.
     */
    size_t max_label_size = userdata->name.size;
    if (max_label_size >= sizeof(userdata->label) / 2) {
      max_label_size = sizeof(userdata->label) / 2;
    }
    for (size_t n = 0; n < max_label_size; ++n) {
      userdata->label[2 * n + 0] = hex_to_char(userdata->name.name[n] >> 4);
      userdata->label[2 * n + 1] = hex_to_char(userdata->name.name[n] & 0x0f);
    }

    userdata->public_object.id = userdata->name.name;
    userdata->public_object.id_size = userdata->name.size;
    userdata->public_object.label = userdata->label;
    userdata->public_object.label_size = max_label_size * 2;
    userdata->public_object.class = CKO_PUBLIC_KEY;
    userdata->public_object.token = CK_TRUE;
    userdata->private_object.id = userdata->name.name;
    userdata->private_object.id_size = userdata->name.size;
    userdata->private_object.label = userdata->label;
    userdata->private_object.label_size = max_label_size * 2;
    userdata->private_object.class = CKO_PRIVATE_KEY;
    userdata->private_object.token = CK_TRUE;
    userdata->key.sign = CK_TRUE;
    userdata->key.verify = CK_TRUE;
    userdata->key.decrypt = CK_FALSE;
    userdata->key.encrypt = CK_FALSE;
    userdata->key.key_type = CKK_EC;
    
    /* allocate space for bit string */
    pos = asn_build_object(&ecc_point, ASN1_BIT_STRING, 2 + ecc->x.size + ecc->y.size);
    /* bit string length is a multiple of octets */
    *pos++ = 0x00;
    /* uncompressed ECC point format */
    *pos++ = 0x04;
    /* copy x coordinate of ECC point */
    memcpy(pos, ecc->x.buffer, ecc->x.size);
    pos += ecc->x.size;
    /* copy y coordinate of ECC point */
    memcpy(pos, ecc->y.buffer, ecc->y.size);
    /* encoding of AIK ECC point */
    userdata->public_key.ec.ec_point = asn_wrap(ASN1_SEQUENCE, "m", ecc_point);
    /* encoding of AIK ECC params */
    userdata->public_key.ec.ec_params = asn_wrap(ASN1_SEQUENCE, "mm",
                                          asn_build_known_oid(OID_EC_PUBLICKEY),
                                          asn_build_known_oid(OID_PRIME256V1));
    pObject object = malloc(sizeof(Object));
    if (object == NULL) {
      free(userdata);
      return NULL;
    }

    object->tpm_handle = 0;
    object->userdata = userdata;
    object->num_entries = 3;
    object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
    object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->public_object, OBJECT_INDEX);
    object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
    object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->public_key.ec, PUBLIC_KEY_EC_INDEX);
    
    public_object = object;

    object = malloc(sizeof(Object));
    if (object == NULL) {
      free(userdata);
      free(public_object);
      return NULL;
    }

    object->tpm_handle = persistent;
    object->userdata = NULL;
    object->num_entries = 2;
    object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
    object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->private_object, OBJECT_INDEX);
    object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);

    public_object->opposite = object;
    object->opposite = public_object;
  }

  return public_object;
}

void object_destroy_pair(TSS2_SYS_CONTEXT *ctx, pObject object)
{

}

void object_free(pObjectList list)
{
  while (list != NULL) {
    pObjectList next = list->next;
    if (list->object != NULL) {
      pObject object = list->object;
      if (object->userdata != NULL)
        free(object->userdata);

      free(object->entries);
      free(object);
    }
    free(list);
    list = next;
  }
}

pObjectList object_load(TSS2_SYS_CONTEXT *ctx, struct config *config)
{
  pObjectList list = malloc(sizeof(ObjectList));
  list->object = NULL;
  list->next = NULL;

  if (list == NULL)
    goto error;
  
  TPMS_CAPABILITY_DATA persistent;
  TPM2_RC rc = tpm_list(ctx, &persistent);
  if (rc != TPM2_RC_SUCCESS)
    goto error;

  for (int i = 0; i < persistent.data.handles.count; i++) {
    pUserdataTpm userdata = malloc(sizeof(UserdataTpm));
    if (userdata == NULL)
      goto error;

    memset(userdata, 0, sizeof(UserdataTpm));
    userdata->name.size = sizeof(TPMU_NAME);
    rc = tpm_read_public(ctx, persistent.data.handles.handle[i], &userdata->tpm_key, &userdata->name);
    if (rc != TPM2_RC_SUCCESS) {
      free(userdata);
      goto error;
    }

    if (userdata->tpm_key.publicArea.type == TPM2_ALG_RSA) {
      TPM2B_PUBLIC_KEY_RSA *rsa_key = &userdata->tpm_key.publicArea.unique.rsa;
      TPMS_RSA_PARMS *rsa_key_parms = &userdata->tpm_key.publicArea.parameters.rsaDetail;

      /*
       * fill the label with the same value as the name (they both have
       * different uses ; some application never display the id but only
       * the label). Since the label is an UTF8 string, we need to
       * transform the binary name into a hexadecimal string.
       */
      size_t max_label_size = userdata->name.size;
      if (max_label_size >= sizeof(userdata->label) / 2)
        max_label_size = sizeof(userdata->label) / 2;
      for (size_t n = 0; n < max_label_size; ++n) {
        userdata->label[2 * n + 0] = hex_to_char(userdata->name.name[n] >> 4);
        userdata->label[2 * n + 1] = hex_to_char(userdata->name.name[n] & 0x0f);
      }

      userdata->public_object.id = userdata->name.name;
      userdata->public_object.id_size = userdata->name.size;
      userdata->public_object.label = userdata->label;
      userdata->public_object.label_size = max_label_size * 2;
      userdata->public_object.class = CKO_PUBLIC_KEY;
      userdata->public_object.token = CK_TRUE;
      userdata->private_object.id = userdata->name.name;
      userdata->private_object.id_size = userdata->name.size;
      userdata->private_object.label = userdata->label;
      userdata->private_object.label_size = max_label_size * 2;
      userdata->private_object.class = CKO_PRIVATE_KEY;
      userdata->private_object.token = CK_TRUE;
      userdata->key.sign = CK_TRUE;
      userdata->key.verify = CK_TRUE;
      userdata->key.decrypt = CK_TRUE;
      userdata->key.encrypt = CK_TRUE;
      userdata->key.key_type = CKK_RSA;
      userdata->modulus.modulus = rsa_key->buffer;
      userdata->modulus.modulus_size = rsa_key_parms->keyBits / 8;
      userdata->modulus.bits = rsa_key_parms->keyBits;
      userdata->public_key.rsa.exponent = htobe32(rsa_key_parms->exponent == 0 ? 65537 : rsa_key_parms->exponent);

      pObject object = malloc(sizeof(Object));
      if (object == NULL) {
        free(userdata);
        goto error;
      }

      object->tpm_handle = 0;
      object->userdata = userdata;
      object->num_entries = 4;
      object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
      object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->public_object, OBJECT_INDEX);
      object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
      object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->public_key.rsa, PUBLIC_KEY_RSA_INDEX);
      object->entries[3] = (AttrIndexEntry) attr_index_entry(&userdata->modulus, MODULUS_INDEX);
      object_add(list, object);
      pObject public_object = object;

      object = malloc(sizeof(Object));
      if (object == NULL)
        goto error;

      object->tpm_handle = persistent.data.handles.handle[i];
      object->userdata = NULL;
      object->num_entries = 3;
      object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
      object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->private_object, OBJECT_INDEX);
      object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
      object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->modulus, MODULUS_INDEX);
      object_add(list, object);

      public_object->opposite = object;
      object->opposite = public_object;
    }
    else if (userdata->tpm_key.publicArea.type == TPM2_ALG_ECC) {
      TPMS_ECC_POINT *ecc = &userdata->tpm_key.publicArea.unique.ecc;
      asn_buf_t ecc_point;
      uint8_t *pos;

      /*
       * fill the label with the same value as the name (they both have
       * different uses ; some application never display the id but only
       * the label). Since the label is an UTF8 string, we need to
       * transform the binary name into a hexadecimal string.
       */
      size_t max_label_size = userdata->name.size;
      if (max_label_size >= sizeof(userdata->label) / 2)
        max_label_size = sizeof(userdata->label) / 2;
      for (size_t n = 0; n < max_label_size; ++n) {
        userdata->label[2 * n + 0] = hex_to_char(userdata->name.name[n] >> 4);
        userdata->label[2 * n + 1] = hex_to_char(userdata->name.name[n] & 0x0f);
      }

      userdata->public_object.id = userdata->name.name;
      userdata->public_object.id_size = userdata->name.size;
      userdata->public_object.label = userdata->label;
      userdata->public_object.label_size = max_label_size * 2;
      userdata->public_object.class = CKO_PUBLIC_KEY;
      userdata->public_object.token = CK_TRUE;
      userdata->private_object.id = userdata->name.name;
      userdata->private_object.id_size = userdata->name.size;
      userdata->private_object.label = userdata->label;
      userdata->private_object.label_size = max_label_size * 2;
      userdata->private_object.class = CKO_PRIVATE_KEY;
      userdata->private_object.token = CK_TRUE;
      userdata->key.sign = CK_TRUE;
      userdata->key.verify = CK_TRUE;
      userdata->key.decrypt = CK_FALSE;
      userdata->key.encrypt = CK_FALSE;
      userdata->key.key_type = CKK_EC;
      
      /* allocate space for bit string */
      pos = asn_build_object(&ecc_point, ASN1_BIT_STRING, 2 + ecc->x.size + ecc->y.size);
      /* bit string length is a multiple of octets */
      *pos++ = 0x00;
      /* uncompressed ECC point format */
      *pos++ = 0x04;
      /* copy x coordinate of ECC point */
      memcpy(pos, ecc->x.buffer, ecc->x.size);
      pos += ecc->x.size;
      /* copy y coordinate of ECC point */
      memcpy(pos, ecc->y.buffer, ecc->y.size);
      /* encoding of AIK ECC point */
      userdata->public_key.ec.ec_point = asn_wrap(ASN1_SEQUENCE, "m", ecc_point);
      /* encoding of AIK ECC params */
      userdata->public_key.ec.ec_params = asn_wrap(ASN1_SEQUENCE, "mm",
                                            asn_build_known_oid(OID_EC_PUBLICKEY),
                                            asn_build_known_oid(OID_PRIME256V1));
      pObject object = malloc(sizeof(Object));
      if (object == NULL) {
        free(userdata);
        goto error;
      }

      object->tpm_handle = 0;
      object->userdata = userdata;
      object->num_entries = 3;
      object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
      object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->public_object, OBJECT_INDEX);
      object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
      object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->public_key.ec, PUBLIC_KEY_EC_INDEX);
      object_add(list, object);
      pObject public_object = object;

      object = malloc(sizeof(Object));
      if (object == NULL)
        goto error;

      object->tpm_handle = persistent.data.handles.handle[i];
      object->userdata = NULL;
      object->num_entries = 2;
      object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
      object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->private_object, OBJECT_INDEX);
      object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
      object_add(list, object);

      public_object->opposite = object;
      object->opposite = public_object;
    }
  }

  if (config->certificates) {
    glob_t results;
    char search_path[PATH_MAX];
    snprintf(search_path, PATH_MAX, "%s/*.der", config->certificates);
    if (glob(search_path, GLOB_TILDE, NULL, &results) == 0) {
      for (int i = 0; i < results.gl_pathc; i++) {
        pObject object = certificate_read(results.gl_pathv[i]);
        if (object)
          object_add(list, object);
      }
    }
  }

  return list;

error:
  object_free(list);
  return NULL;
}
