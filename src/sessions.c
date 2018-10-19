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

#include "sessions.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_DEVICE "/dev/tpmrm0"
#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_PORT 2323

unsigned int open_sessions = 0;
extern struct session main_session;
extern TSS2_TCTI_CONTEXT *tcti;

int session_init(struct session* session, struct config *config, bool have_write) {
  size_t size = 0;
  TSS2_RC rc;

  memset(session, 0, sizeof(struct session));
  session->have_write = have_write;

  size = Tss2_Sys_GetContextSize(0);
  session->context = (TSS2_SYS_CONTEXT*) calloc(1, size);
  if (session->context == NULL) {
    goto cleanup;
  }

  TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
  
  rc = Tss2_Sys_Initialize(session->context, size, tcti, &abi_version);
  if (rc != TSS2_RC_SUCCESS) {
    goto cleanup;
  }

  session->objects = main_session.objects;
  open_sessions++;
  return 0;

cleanup:
  if (session->context != NULL)
    free(session->context);

  return -1;
}

void session_close(struct session* session) {
  if (session->password) {
    free(session->password);
  }

  Tss2_Sys_Finalize(session->context);
  free(session->context);
  open_sessions--;
}
