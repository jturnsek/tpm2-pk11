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

#ifndef UTILS_H_
#define UTILS_H_

#include <stddef.h>
#include <stdint.h>

void strncpy_pad(char *dest, const char *src, size_t n);
void retmem(void* dest, size_t* size, const void* src, size_t n);
void* alloc_userdata_and_read_file(const char* filename, size_t* length);
int write_file(const char* filename, const void* src, size_t length);
int remove_file(const char* filename);

#endif /** UTILS_H_ */
