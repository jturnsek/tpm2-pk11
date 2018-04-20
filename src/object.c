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

AttrIndex CERTIFICATE_INDEX[] = {
  attr_dynamic_index_of(CKA_VALUE, PkcsX509, value, value_size),
  attr_dynamic_index_of(CKA_SUBJECT, PkcsX509, subject, subject_size),
  attr_dynamic_index_of(CKA_ISSUER, PkcsX509, issuer, issuer_size),
  attr_dynamic_index_of(CKA_SERIAL_NUMBER, PkcsX509, serial, serial_size),
  attr_index_of(CKA_CERTIFICATE_TYPE, PkcsX509, cert_type),
};

void* attr_get(pObject object, CK_ATTRIBUTE_TYPE type, size_t *size) {
  if (!object) {
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
          return entries->object + index->offset;
        } else {
          if (size) {
            *size = *((size_t*) (entries->object + index->size_offset));
          }
          return *((void**) (entries->object + index->offset));
        }
      }
    }
  }

  return NULL;
}
