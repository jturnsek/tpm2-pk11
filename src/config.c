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

#include "config.h"
#include "log.h"

#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

int config_load(char* filename, struct config *config) {
  FILE* fd = fopen(filename, "r");

  if (fd == NULL)
    return -ENOENT;

  char *line = NULL;
  size_t len = 0;

  while (getline(&line, &len, fd) != -1) {
    char *key = NULL, *value = NULL;
    if (sscanf(line, "%ms %m[^\n]", &key, &value) == 2) {
      if (strcmp(key, "device") == 0) {
        config->device = value;
        value = NULL;
      } else if (strcmp(key, "data") == 0) {
        config->data = value;
        value = NULL;
      else if (strcmp(key, "login-required") == 0)
        config->login_required = strcasecmp(value, "true") == 0;
      else if (strcmp(key, "log-level") == 0)
        config->log_level = atoi(value);
      else if (strcmp(key, "log") == 0) {
        config->log_file = value;
        value = NULL;
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
  return 0;
}
