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

#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"

/**
 * Described in header.
 */
void memxor(uint8_t dst[], const uint8_t src[], size_t n)
{
  int m, i;

  /* byte wise XOR until dst aligned */
  for (i = 0; (uintptr_t)&dst[i] % sizeof(long) && i < n; i++)
  {
    dst[i] ^= src[i];
  }
  /* try to use words if src shares an aligment with dst */
  switch (((uintptr_t)&src[i] % sizeof(long)))
  {
    case 0:
      for (m = n - sizeof(long); i <= m; i += sizeof(long))
      {
        *(long*)&dst[i] ^= *(long*)&src[i];
      }
      break;
    case sizeof(int):
      for (m = n - sizeof(int); i <= m; i += sizeof(int))
      {
        *(int*)&dst[i] ^= *(int*)&src[i];
      }
      break;
    case sizeof(short):
      for (m = n - sizeof(short); i <= m; i += sizeof(short))
      {
        *(short*)&dst[i] ^= *(short*)&src[i];
      }
      break;
    default:
      break;
  }
  /* byte wise XOR of the rest */
  for (; i < n; i++)
  {
    dst[i] ^= src[i];
  }
}

/**
 * Described in header.
 */
void memwipe_noinline(void *ptr, size_t n)
{
  memwipe_inline(ptr, n);
}

/**
 * Described in header.
 */
bool memeq_const(const void *x, const void *y, size_t len)
{
  const u_char *a, *b;
  uint8_t bad = 0;
  size_t i;

  a = (const u_char*)x;
  b = (const u_char*)y;

  for (i = 0; i < len; i++)
  {
    bad |= a[i] != b[i];
  }
  return !bad;
}

/**
 * Described in header.
 */
void *memstr(const void *haystack, const char *needle, size_t n)
{
  const unsigned char *pos = haystack;
  size_t l;

  if (!haystack || !needle || (l = strlen(needle)) == 0)
  {
    return NULL;
  }
  for (; n >= l; ++pos, --n)
  {
    if (memeq(pos, needle, l))
    {
      return (void*)pos;
    }
  }
  return NULL;
}

/**
 * Described in header.
 */
void* malloc_align(size_t size, uint8_t align)
{
  uint8_t pad;
  void *ptr;

  if (align == 0)
  {
    align = 1;
  }
  ptr = malloc(align + sizeof(pad) + size);
  if (!ptr)
  {
    return NULL;
  }
  /* store padding length just before data, down to the allocation boundary
   * to do some verification during free_align() */
  pad = align - ((uintptr_t)ptr % align);
  memset(ptr, pad, pad);
  return ptr + pad;
}

/**
 * Described in header.
 */
void free_align(void *ptr)
{
  uint8_t pad, *pos;

  pos = ptr - 1;
  /* verify padding to check any corruption */
  for (pad = *pos; (void*)pos >= ptr - pad; pos--)
  {
    if (*pos != pad)
    {
      return;
    }
  }
  free(ptr - pad);
}

void strncpy_pad(char *dest, const char *src, size_t n) {
  size_t len = strlen(src);
  memcpy(dest, src, len < n ? len : n);
  if (len < n)
    memset(dest + len, ' ', n - len);
}

void retmem(void* dest, size_t* size, const void* src, size_t n) {
  if (n <= *size)
    memcpy(dest, src, n);

  *size = n;
}

void* read_file(const char* filename, size_t* length) {
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    *length = 0;
    return NULL;
  }

  struct stat s;
  char* buffer = NULL;
  int ret = fstat(fd, &s);
  if (ret < 0) {
    *length = 0;
    goto cleanup;
  }

  size_t pre_length = *length;
  *length = s.st_size;
  buffer = malloc(*length + pre_length);
  if (buffer == NULL || read(fd, buffer + pre_length, *length) != *length)
    *length = 0;

  cleanup:
  close(fd);
  return buffer;
}

