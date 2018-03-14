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

#include "object.h"
#include "objects.h"
#include "pk11.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>


#define MAX_ID_BITS 512
#define MAX_DER_LENGTH 256

typedef struct userdata_certificate_t {
  CK_BYTE id[MAX_ID_BITS / 4];
  CK_UTF8CHAR label[MAX_ID_BITS / 2];
  CK_BYTE subject[MAX_DER_LENGTH];
  CK_BYTE issuer[MAX_DER_LENGTH];
  CK_BYTE serial[MAX_DER_LENGTH];
  PkcsObject object;
  PkcsX509 certificate;
} UserdataCertificate, *pUserdataCertificate;


pObject certificate_read(const char* pathname) {
  pObject object = malloc(sizeof(Object));
  if (!object)
    return NULL;

  size_t size = sizeof(UserdataCertificate);
  pUserdataCertificate userdata = (pUserdataCertificate) read_file(pathname, &size);
  if (!userdata) {
    free(object);
    return NULL;
  }

  userdata->object.class = CKO_CERTIFICATE;
  userdata->object.token = CK_TRUE;
  userdata->object.id = userdata->id;
  userdata->object.id_size = 0;
  userdata->object.label = userdata->label;
  char* filename = basename(pathname);
  while (userdata->object.id_size < sizeof(userdata->id)) {
    if (sscanf(filename + (userdata->object.id_size * 2), "%2hhx", userdata->id + userdata->object.id_size) != 1)
      break;

    sprintf((char*) userdata->label + userdata->object.id_size * 2, "%02X", userdata->id[userdata->object.id_size]);
    userdata->object.id_size++;
  }

  userdata->object.label_size = userdata->object.id_size * 2;

  userdata->certificate.value_size = size;
  userdata->certificate.value = ((char*) userdata) + sizeof(UserdataCertificate);
  userdata->certificate.cert_type = CKC_X_509;
  userdata->certificate.subject = userdata->subject;
  userdata->certificate.subject_size = 0;
  userdata->certificate.issuer = userdata->issuer;
  userdata->certificate.issuer_size = 0;
  userdata->certificate.serial = userdata->serial;
  userdata->certificate.serial_size = 0;


  //TODO: ASN encoding


  object->userdata = userdata;
  object->num_entries = 2;
  object->entries = calloc(object->num_entries, sizeof(AttrIndexEntry));
  object->entries[0] = (AttrIndexEntry) attr_index_entry(&userdata->object, OBJECT_INDEX);
  object->entries[1] = (AttrIndexEntry) attr_index_entry(&userdata->certificate, CERTIFICATE_INDEX);

  return object;
}

void certificate_write(const char* pathname, pObject object) {

}
