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
#include "log.h"
#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <endian.h>
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 256
#endif
#include <glob.h>

static inline int hex_to_char(int c)
{
  return c >= 10 ? c - 10 + 'A' : c + '0';
}

CK_BYTE oidP256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

typedef struct userdata_tpm_t {
  TPM2B_PUBLIC tpm_key;
  TPM2B_NAME name;
  CK_BYTE id[256];
  CK_UTF8CHAR label[256];
  PkcsObject public_object, private_object;
  PkcsKey key;
  PkcsPublicKey public_key;
  PkcsPrivateKey private_key;
  PkcsModulus modulus;
} UserdataTpm, *pUserdataTpm;


AttrIndex OBJECT_INDEX[] = {
  attr_dynamic_index_of(CKA_ID, PkcsObject, id, id_size),
  attr_dynamic_index_of(CKA_LABEL, PkcsObject, label, label_size),
  attr_index_of(CKA_CLASS, PkcsObject, class),
  attr_index_of(CKA_TOKEN, PkcsObject, token)
};

AttrIndex KEY_INDEX[] = {
  attr_index_of(CKA_SIGN, PkcsKey, sign),
  attr_index_of(CKA_VERIFY, PkcsKey, verify),
  attr_index_of(CKA_DECRYPT, PkcsKey, decrypt),
  attr_index_of(CKA_ENCRYPT, PkcsKey, encrypt),
  attr_index_of(CKA_KEY_TYPE, PkcsKey, key_type)
};

AttrIndex PUBLIC_KEY_RSA_INDEX[] = {
  attr_index_of(CKA_PUBLIC_EXPONENT, PkcsRSAPublicKey, exponent)
};

AttrIndex MODULUS_INDEX[] = {
  attr_dynamic_index_of(CKA_MODULUS, PkcsModulus, modulus, modulus_size),
  attr_index_of(CKA_MODULUS_BITS, PkcsModulus, bits)
};

AttrIndex PUBLIC_KEY_EC_INDEX[] = {
  attr_dynamic_index_of(CKA_EC_PARAMS, PkcsECPublicKey, ec_params, ec_params_len),
  attr_dynamic_index_of(CKA_EC_POINT, PkcsECPublicKey, ec_point, ec_point_len)  
};

AttrIndex PRIVATE_KEY_EC_INDEX[] = {
  attr_dynamic_index_of(CKA_EC_PARAMS, PkcsECPrivateKey, ec_params, ec_params_len)  
};

AttrIndex CERTIFICATE_INDEX[] = {
  attr_dynamic_index_of(CKA_VALUE, PkcsX509, value, value_size),
  attr_dynamic_index_of(CKA_SUBJECT, PkcsX509, subject, subject_size),
  attr_dynamic_index_of(CKA_ISSUER, PkcsX509, issuer, issuer_size),
  attr_dynamic_index_of(CKA_SERIAL_NUMBER, PkcsX509, serial, serial_size),
  attr_index_of(CKA_CERTIFICATE_TYPE, PkcsX509, cert_type),
};

void* attr_get(pObject object, CK_ATTRIBUTE_TYPE type, size_t *size)
{
  if (!object) {
    print_log(DEBUG, "attribute get: null object");
    return NULL;
  }

  for (int i = 0; i < object->num_entries; i++) {
    pAttrIndexEntry entries = &object->entries[i];
    for (int j = 0; j < entries->num_attrs; j++) {
      if (type == entries->indexes[j].type) {
        pAttrIndex index = &entries->indexes[j];
        if (index->size_offset == 0) {
          if (size) {
            *size = index->size;
          }
          print_log(DEBUG, "attribute get (1): type = 0x%x, size = %d", type, *size);
          return entries->object + index->offset;
        } else {
          if (size) {
            *size = *((size_t*) (entries->object + index->size_offset));
          }
          print_log(DEBUG, "attribute get (2): type = 0x%x, size = %d", type, *size);
          return *((void**) (entries->object + index->offset));
        }
      }
    }
  }

  print_log(DEBUG, "attribute not found: type = 0x%x", pTemplate[i].type);
  return NULL;
}

int attr_set(pObject object, CK_ATTRIBUTE_TYPE type, void* value, size_t size)
{
  if (!object) {
    print_log(DEBUG, "attribute set: null object");
    return -1;
  }

  for (int i = 0; i < object->num_entries; i++) {
    pAttrIndexEntry entries = &object->entries[i];
    for (int j = 0; j < entries->num_attrs; j++) {
      if (type == entries->indexes[j].type) {
        pAttrIndex index = &entries->indexes[j];
        if (index->size_offset == 0) {
          print_log(DEBUG, "attribute set (1): type = 0x%x, size = %d", type,  size);
          memcpy(entries->object + index->offset, value, size);
          index->size = size;
        } else {
          print_log(DEBUG, "attribute set (2): type = 0x%x, size = %d", type, size);
          memcpy(*((void**) (entries->object + index->offset)), value, size);
          *((size_t*) (entries->object + index->size_offset)) = size;
        }
      }
    }
  }

  return 0;
}

int attr_read(pObject object, CK_ATTRIBUTE_TYPE type)
{
  #if 0
  pUserdataTpm userdata = (pUserdataTpm)object->userdata;
  size_t size = userdata->name.size;
  const char* attr1 = "id";
  const char* attr2 = "label"
  char *attr;
  
  if (type == CKA_ID) {
    attr = (char*)attr1;
  }
  else if (type == CKA_LABEL) {
     attr = (char*)attr2;
  }
  else {
    return -ENOENT;  
  }

  char filename[64] = {0};
  char pathname[256] = {0};

  if (size >= sizeof(filename) / 2)
    size = sizeof(filename) / 2;
  for (size_t n = 0; n < size; ++n) {
    filename[2 * n + 0] = hex_to_char(userdata->name.name[n] >> 4);
    filename[2 * n + 1] = hex_to_char(userdata->name.name[n] & 0x0f);
  }

  if (config->keys) { 
    strcpy(pathname, config->keys);
    strcat(pathname, "/");
    strcat(pathname, filename);
  }
  else {
    return -ENOENT;
  }

  FILE* fd = fopen(pathname, "r");

  if (fd == NULL) {
    return -ENOENT;
  }

  char *line = NULL;
  size_t len = 0;

  while (getline(&line, &len, fd) != -1) {
    char *key = NULL, *value = NULL;
    if (sscanf(line, "%ms %m[^\n]", &key, &value) == 2) {
      if (strcmp(key, attr) == 0) {
        attr_set(object, type, value, sizeof(value));
      }
    }
    if (key != NULL)
      free(key);

    if (value != NULL)
      free(value);
  }

  if (line != NULL)
    free(line);

  fclose(fd);
  #endif
  return 0;
}

int attr_write(pObject object, CK_ATTRIBUTE_TYPE type)
{
  #if 0

  #endif
  return 0; 
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

void object_remove(pObjectList *list, pObject object)
{
  pObjectList currlist = *list;
  pObjectList prevlist = *list;
  while (currlist != NULL) {
    if (currlist->object != NULL && currlist->object == object) {
      /* kill object list entry */
      if (prevlist == currlist) {
        *list = currlist->next;
      }
      else {
        prevlist->next = currlist->next;
      }
      free(currlist);  
      break;  
    }
    prevlist = currlist;
    currlist = currlist->next;
  }
}

pObject object_generate_pair(TSS2_SYS_CONTEXT *ctx, TPM2_ALG_ID algorithm, pObjectList list, struct config *config)
{
  pObject public_object = NULL;
  pUserdataTpm userdata = malloc(sizeof(UserdataTpm));
  if (userdata == NULL) {
    return NULL;
  }
  memset(userdata, 0, sizeof(UserdataTpm));
  userdata->name.size = sizeof(TPMU_NAME);
  TPMI_DH_OBJECT handle = (TPMI_DH_OBJECT)TPM_DEFAULT_EK_HANDLE;
  int i = TPM_MAX_NUM_OF_AK_HANDLES;
  pObjectList tmplist = list;

  while (i-- > 0) {
    while (tmplist != NULL) {   
      if (tmplist->object != NULL && tmplist->object->tpm_handle == handle) {
        handle++;
        tmplist = list;
        break; 
      }
      tmplist = tmplist->next;
    }
    if (tmplist == NULL) {
      break;
    }
  }
  if (handle == (TPMI_DH_OBJECT)TPM_DEFAULT_EK_HANDLE || i == 0) {
    /* No EK handle or no more space */
    free(userdata);
    return NULL;
  }

  print_log(VERBOSE, "object_generate_pair: final handle = %x", handle);
  
  TPM2_RC rc = tpm_generate_key_pair(ctx, handle, algorithm, &userdata->tpm_key, &userdata->name);
  if (rc != TPM2_RC_SUCCESS) {
    free(userdata);
    return NULL;
  }

  if (userdata->tpm_key.publicArea.type == TPM2_ALG_RSA) {
    TPM2B_PUBLIC_KEY_RSA *rsa_key = &userdata->tpm_key.publicArea.unique.rsa;
    TPMS_RSA_PARMS *rsa_key_parms = &userdata->tpm_key.publicArea.parameters.rsaDetail;

    userdata->public_object.id = userdata->id;
    userdata->public_object.id_size = 0;
    userdata->public_object.label = userdata->label;
    userdata->public_object.label_size = 0;
    userdata->public_object.class = CKO_PUBLIC_KEY;
    userdata->public_object.token = CK_TRUE;
    userdata->private_object.id = userdata->id;
    userdata->private_object.id_size = 0;
    userdata->private_object.label = userdata->label;
    userdata->private_object.label_size = 0;
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
    object->is_certificate = false;
    public_object = object;

    object = malloc(sizeof(Object));
    if (object == NULL) {
      free(userdata);
      free(public_object);
      return NULL;
    }

    object->tpm_handle = handle;
    object->userdata = NULL;
    object->num_entries = 3;
    object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
    object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->private_object, OBJECT_INDEX);
    object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
    object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->modulus, MODULUS_INDEX);
    object->is_certificate = false;
    public_object->opposite = object;
    object->opposite = public_object;

    attr_write(object, CKA_ID);
    attr_write(object, CKA_LABEL);
  }
  else if (userdata->tpm_key.publicArea.type == TPM2_ALG_ECC) {
    TPMS_ECC_POINT *ecc = &userdata->tpm_key.publicArea.unique.ecc;

    userdata->public_object.id = userdata->id;
    userdata->public_object.id_size = 0;
    userdata->public_object.label = userdata->label;
    userdata->public_object.label_size = 0;
    userdata->public_object.class = CKO_PUBLIC_KEY;
    userdata->public_object.token = CK_TRUE;
    userdata->private_object.id = userdata->id;
    userdata->private_object.id_size = 0;
    userdata->private_object.label = userdata->label;
    userdata->private_object.label_size = 0;
    userdata->private_object.class = CKO_PRIVATE_KEY;
    userdata->private_object.token = CK_TRUE;
    userdata->key.sign = CK_TRUE;
    userdata->key.verify = CK_TRUE;
    userdata->key.decrypt = CK_FALSE;
    userdata->key.encrypt = CK_FALSE;
    userdata->key.key_type = CKK_EC;
    
    /* allocate space for octet string */
    userdata->public_key.ec.ec_point[0] = 0x04; /* EC_POINT_FORM_UNCOMPRESSED */
    /* copy x coordinate of ECC point */
    memcpy(&userdata->public_key.ec.ec_point[1], ecc->x.buffer, ecc->x.size);
    /* copy y coordinate of ECC point */
    memcpy(&userdata->public_key.ec.ec_point[1 + ecc->x.size], ecc->y.buffer, ecc->y.size);
    userdata->public_key.ec.ec_point_len = 1 + ecc->x.size + ecc->y.size;
    
    /* encoding of AIK ECC params */
    userdata->public_key.ec.ec_params = oidP256;
    userdata->public_key.ec.ec_params_len = sizeof(oidP256);
    userdata->private_key.ec.ec_params = oidP256;
    userdata->private_key.ec.ec_params_len = sizeof(oidP256);
    pObject object = malloc(sizeof(Object));
    if (object == NULL) {
      free(pos);
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
    object->is_certificate = false;
    public_object = object;

    object = malloc(sizeof(Object));
    if (object == NULL) {
      free(pos);
      free(userdata);
      free(public_object);
      return NULL;
    }

    object->tpm_handle = handle;
    object->userdata = NULL;
    object->num_entries = 3;
    object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
    object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->private_object, OBJECT_INDEX);
    object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
    object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->private_key.ec, PRIVATE_KEY_EC_INDEX);
    object->is_certificate = false;
    public_object->opposite = object;
    object->opposite = public_object;

    attr_write(object, CKA_ID);
    attr_write(object, CKA_LABEL);
  }

  return public_object;
}

void object_free_list(pObjectList list)
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

pObjectList object_load_list(TSS2_SYS_CONTEXT *ctx, struct config *config)
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

      userdata->public_object.id = userdata->id;
      userdata->public_object.id_size = 0;
      userdata->public_object.label = userdata->label;
      userdata->public_object.label_size = 0;
      userdata->public_object.class = CKO_PUBLIC_KEY;
      userdata->public_object.token = CK_TRUE;
      userdata->private_object.id = userdata->id;
      userdata->private_object.id_size = 0;
      userdata->private_object.label = userdata->label;
      userdata->private_object.label_size = 0;
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
      object->is_certificate = false;
      object_add(list, object);
      pObject public_object = object;

      object = malloc(sizeof(Object));
      if (object == NULL) {
        free(userdata);
        free(public_object);
        goto error;
      }

      object->tpm_handle = persistent.data.handles.handle[i];
      object->userdata = NULL;
      object->num_entries = 3;
      object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
      object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->private_object, OBJECT_INDEX);
      object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
      object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->modulus, MODULUS_INDEX);
      object->is_certificate = false;
      object_add(list, object);

      public_object->opposite = object;
      object->opposite = public_object;

      attr_read(object, CKA_ID);
      attr_read(object, CKA_LABEL);
    }
    else if (userdata->tpm_key.publicArea.type == TPM2_ALG_ECC) {
      TPMS_ECC_POINT *ecc = &userdata->tpm_key.publicArea.unique.ecc;

      userdata->public_object.id = userdata->id;
      userdata->public_object.id_size = 0;
      userdata->public_object.label = userdata->label;
      userdata->public_object.label_size = 0;
      userdata->public_object.class = CKO_PUBLIC_KEY;
      userdata->public_object.token = CK_TRUE;
      userdata->private_object.id = userdata->id;
      userdata->private_object.id_size = 0;
      userdata->private_object.label = userdata->label;
      userdata->private_object.label_size = 0;
      userdata->private_object.class = CKO_PRIVATE_KEY;
      userdata->private_object.token = CK_TRUE;
      userdata->key.sign = CK_TRUE;
      userdata->key.verify = CK_TRUE;
      userdata->key.decrypt = CK_FALSE;
      userdata->key.encrypt = CK_FALSE;
      userdata->key.key_type = CKK_EC;
      
      /* allocate space for octet string */
      userdata->public_key.ec.ec_point[0] = 0x04; /* EC_POINT_FORM_UNCOMPRESSED */
      /* copy x coordinate of ECC point */
      memcpy(&userdata->public_key.ec.ec_point[1], ecc->x.buffer, ecc->x.size);
      /* copy y coordinate of ECC point */
      memcpy(&userdata->public_key.ec.ec_point[1 + ecc->x.size], ecc->y.buffer, ecc->y.size);
      userdata->public_key.ec.ec_point_len = 1 + ecc->x.size + ecc->y.size;

      /* encoding of AIK ECC params */
      userdata->public_key.ec.ec_params = oidP256;
      userdata->public_key.ec.ec_params_len = sizeof(oidP256);
      userdata->private_key.ec.ec_params = oidP256;
      userdata->private_key.ec.ec_params_len = sizeof(oidP256);
      pObject object = malloc(sizeof(Object));
      if (object == NULL) {
        free(pos);
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
      object->is_certificate = false;
      object_add(list, object);
      pObject public_object = object;

      object = malloc(sizeof(Object));
      if (object == NULL) {
        free(pos);
        free(userdata);
        free(public_object);
        goto error;
      }

      object->tpm_handle = persistent.data.handles.handle[i];
      object->userdata = NULL;
      object->num_entries = 3;
      object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
      object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->private_object, OBJECT_INDEX);
      object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->key, KEY_INDEX);
      object->entries[2] = (AttrIndexEntry) attr_index_entry(&userdata->private_key.ec, PRIVATE_KEY_EC_INDEX);
      object->is_certificate = false;
      object_add(list, object);

      public_object->opposite = object;
      object->opposite = public_object;

      attr_read(object, CKA_ID);
      attr_read(object, CKA_LABEL);
    }
  }

  if (config->certificates) {
    glob_t results;
    char search_path[PATH_MAX];
    snprintf(search_path, PATH_MAX, "%s/*", config->certificates);
    if (glob(search_path, GLOB_TILDE | GLOB_NOCHECK, NULL, &results) == 0) {
      for (int i = 0; i < results.gl_pathc; i++) {
        pObject object = certificate_read(results.gl_pathv[i]);
        if (object)
          object_add(list, object);
      }
      globfree(&results);
    }
  }

  return list;

error:
  object_free_list(list);
  return NULL;
}
