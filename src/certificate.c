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
#include "pk11.h"
#include "utils.h"
#include "db.h"
#include "log.h"

#include <stdio.h>
#include <string.h>

#include <libtasn1.h>

#ifndef PATH_MAX
#define PATH_MAX 256
#endif

#define MAX_HASH_TABLE_SIZE           512
#define ID_MAX_SIZE                   20
#define LABEL_MAX_SIZE                256
#define VALUE_MAX_SIZE                4096
#define MAX_DER_LENGTH                256

extern const asn1_static_node pkix_asn1_tab[];

typedef struct userdata_certificate_t {
  PkcsObject object;
  PkcsX509 certificate;
  CK_BYTE subject[MAX_DER_LENGTH];
  CK_BYTE issuer[MAX_DER_LENGTH];
  CK_BYTE serial[MAX_DER_LENGTH];
  CK_BYTE id[ID_MAX_SIZE];
  CK_UTF8CHAR label[LABEL_MAX_SIZE];
  char value[VALUE_MAX_SIZE];
} UserdataCertificate, *pUserdataCertificate;


int certificate_load_list(pObjectList list, struct config *config)
{
  if (config->data) {  
    DB db;
    DB_ITERATOR dbi;
    char pathname[PATH_MAX]; 
    snprintf(pathname, PATH_MAX, "%s/" TPM2_PK11_CERTS_FILE, config->data);
    if (DB_open(&db, pathname, DB_OPEN_MODE_RWCREAT, MAX_HASH_TABLE_SIZE, ID_MAX_SIZE, sizeof(UserdataCertificate)) != 0) {
      print_log(DEBUG, "certificate_load_list: ERROR - certificate database %s cannot be open!", pathname);
      return -1;
    }

    DB_iterator_init(&db, &dbi);

    bool loop = true;

    while (loop) {
      CK_BYTE id[ID_MAX_SIZE];
      pUserdataCertificate userdata = malloc(sizeof(UserdataCertificate));
      if (userdata == NULL) {
        DB_close(&db);
        return -1;
      }

      int ret = DB_iterator_next(&dbi, id, userdata);
      if (ret < 0) {
        free(userdata);
        DB_close(&db);
        return -1;
      }
      else if (ret == 0) {
        loop = false;
        free(userdata);
        break;
      }

      memset(id, 0, ID_MAX_SIZE);
      if (memcmp(userdata->id, id, ID_MAX_SIZE) == 0) {
        /* Certificate was removed, skip it */
        free(userdata);
        continue;
      } 

      userdata->object.id = userdata->id;
      userdata->object.label = userdata->label;
      userdata->certificate.value = userdata->value;
      userdata->certificate.subject = userdata->subject;
      userdata->certificate.issuer = userdata->issuer;
      userdata->certificate.serial = userdata->serial;

      pObject object = malloc(sizeof(Object));
      if (!object) {
        free(userdata);
        DB_close(&db);
        return -1;
      }

      object->userdata = userdata;
      object->num_entries = 2;
      object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
      object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->object, OBJECT_INDEX);
      object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->certificate, CERTIFICATE_INDEX);

      object->is_certificate = true; 

      object_add(list, object); 
    }
    DB_close(&db);
    return 0;
  }
  else {
    print_log(DEBUG, "certificate_load_list: ERROR - configuration!");
    return -1;
  }
}

int certificate_remove(pObject object, struct config *config)
{
  if (!object) {
    return -1;
  }

  if (config->data) {
    DB db;
    char pathname[PATH_MAX]; 
    snprintf(pathname, PATH_MAX, "%s/" TPM2_PK11_CERTS_FILE, config->data);
    if (DB_open(&db, pathname, DB_OPEN_MODE_RDWR, MAX_HASH_TABLE_SIZE, ID_MAX_SIZE, sizeof(UserdataCertificate)) != 0) {
      print_log(DEBUG, "certificate_remove: ERROR - certificate database %s cannot be open!", pathname);
      return -1;
    }

    UserdataCertificate userdata;
    memset(&userdata, 0, sizeof(userdata));

    if (DB_put(&db, userdata.id, &userdata) != 0) {
      /* Write error */
      print_log(DEBUG, "certificate_remove: ERROR - write failed!");
      DB_close(&db);
      return -1;
    }
    DB_close(&db); 
    return 0;      
  }
  else {
    print_log(DEBUG, "certificate_remove: ERROR - configuration!");
    return -1;
  }
}

pObject certificate_create(pObjectList list, struct config *config, void* id, size_t id_len, void* value, size_t value_len)
{
  if (config->data) {
    DB db;
    char pathname[PATH_MAX]; 
    snprintf(pathname, PATH_MAX, "%s/" TPM2_PK11_CERTS_FILE, config->data);
    if (DB_open(&db, pathname, DB_OPEN_MODE_RDWR, MAX_HASH_TABLE_SIZE, ID_MAX_SIZE, sizeof(UserdataCertificate)) != 0) {
      print_log(DEBUG, "certificate_write: ERROR - certificate database %s cannot be open!", pathname);
      return NULL;
    }

    pUserdataCertificate userdata = malloc(sizeof(UserdataCertificate));
    if (userdata == NULL) {
      DB_close(&db);
      return NULL;
    }

    if ((id_len > ID_MAX_SIZE) || (value_len > VALUE_MAX_SIZE)) {
      free(userdata);
      DB_close(&db);
      return NULL;
    }
    memcpy(userdata->id, id, id_len);
    memcpy(userdata->value, value, value_len);

    userdata->object.class = CKO_CERTIFICATE;
    userdata->object.token = CK_TRUE;
    userdata->object.id = userdata->id;
    userdata->object.id_size = id_len;
    userdata->object.label = userdata->label;
    userdata->object.label_size = 0;
    userdata->certificate.value_size = value_len;
    userdata->certificate.value = userdata->value;
    userdata->certificate.cert_type = CKC_X_509;
    userdata->certificate.subject = userdata->subject;
    userdata->certificate.subject_size = 0;
    userdata->certificate.issuer = userdata->issuer;
    userdata->certificate.issuer_size = 0;
    userdata->certificate.serial = userdata->serial;
    userdata->certificate.serial_size = 0;

    ASN1_TYPE definition = ASN1_TYPE_EMPTY;
    ASN1_TYPE element = ASN1_TYPE_EMPTY;
    char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];

    asn1_array2tree(pkix_asn1_tab, &definition, errorDescription);
    asn1_create_element(definition, "PKIX1.Certificate", &element);
    if (asn1_der_decoding(&element, userdata->certificate.value, userdata->certificate.value_size, errorDescription) != ASN1_SUCCESS) {
      free(userdata);
      DB_close(&db);
      return NULL;
    }

    int length = MAX_DER_LENGTH;
    if (asn1_der_coding(element, "tbsCertificate.subject", userdata->subject, &length, errorDescription) == ASN1_SUCCESS)
      userdata->certificate.subject_size = length;

    length = MAX_DER_LENGTH;
    if (asn1_der_coding(element, "tbsCertificate.issuer", userdata->issuer, &length, errorDescription) == ASN1_SUCCESS)
      userdata->certificate.issuer_size = length;

    length = MAX_DER_LENGTH;
    if (asn1_der_coding(element, "tbsCertificate.serialNumber", userdata->serial, &length, errorDescription) == ASN1_SUCCESS)
      userdata->certificate.serial_size = length;

    asn1_delete_structure(&definition);
    asn1_delete_structure(&element);

    pObject object = malloc(sizeof(Object));
    if (!object) {
      free(userdata);
      DB_close(&db);
      return NULL;
    }

    object->userdata = userdata;
    object->num_entries = 2;
    object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
    object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->object, OBJECT_INDEX);
    object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->certificate, CERTIFICATE_INDEX);
    object->is_certificate = true;

    if (DB_put(&db, userdata->id, userdata) != 0) {
      /* Write error */
      print_log(DEBUG, "certificate_write: ERROR - write failed!");
      free(userdata);
      DB_close(&db);
      return NULL;
    }
    DB_close(&db);
    object_add(list, object); 
    return object;      
  }
  else {
    print_log(DEBUG, "certificate_write: ERROR - configuration!");
    return NULL;
  }  
}

int certificate_attrs_write(pObject object, struct config *config)
{
  pUserdataCertificate userdata = (pUserdataCertificate)object->userdata;

  if (config->data) {
    DB db;
    char pathname[PATH_MAX]; 
    snprintf(pathname, PATH_MAX, "%s/" TPM2_PK11_CERTS_FILE, config->data);
    if (DB_open(&db, pathname, DB_OPEN_MODE_RDWR, MAX_HASH_TABLE_SIZE, ID_MAX_SIZE, sizeof(userdata)) != 0) {
      return -1;  
    }
  
    if (DB_put(&db, userdata->id, userdata) != 0) {
      /* Write error */
      DB_close(&db);
      return -1;
    }
    DB_close(&db); 
  }
  else {
    return -1; 
  }

  return 0; 
}
