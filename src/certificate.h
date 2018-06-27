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

#ifndef CERTIFICATE_H_
#define CERTIFICATE_H_

#include "objects.h"

int certificate_load_list(pObjectList list, struct config *config);
pObject certificate_create(pObjectList list, struct config *config, 
							void* id, size_t id_len, 
							void* label, size_t label_len, 
							void* value, size_t value_len);
int certificate_delete(pObject object, struct config *config);
int certificate_attr_write(pObject object, struct config *config);

#endif /** CERTIFICATE_H_ */
