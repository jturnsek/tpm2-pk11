/*
 * This file is part of tpm2-pk11.
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
#include "log.h"

void* attr_get(pObject object, CK_ATTRIBUTE_TYPE type, size_t *size) {
  print_log(VERBOSE, "attr_get: num_entries=%d", (int)object->num_entries);
  for (int i = 0; i < object->num_entries; i++) {
    print_log(VERBOSE, "attr_get: i=%d", i);
    pAttrIndexEntry entries = &object->entries[i];
    print_log(VERBOSE, "attr_get: entries->num_attrs=%d", (int)entries->num_attrs);
    for (int j = 0; j < entries->num_attrs; j++) {
      print_log(VERBOSE, "attr_get: j=%d", j);
      if (type == entries->indexes[j].type) {
        pAttrIndex index = &entries->indexes[j];
        print_log(VERBOSE, "attr_get: index=%d", (int)index);
        if (index->size_offset == 0) {
          if (size) {
            print_log(VERBOSE, "attr_get: *size=%d", (int)(index->size));
            *size = index->size;
          }
          print_log(VERBOSE, "attr_get: foobar1");
          return entries->object + index->offset;
        } else {
          if (size) {
            print_log(VERBOSE, "attr_get: krneki=%d", (int)(entries->object + index->size_offset));
            *size = *((size_t*) (entries->object + index->size_offset));
          }
          print_log(VERBOSE, "attr_get: foobar2");
          return *((void**) (entries->object + index->offset));
        }
      }
    }
  }

  return NULL;
}
