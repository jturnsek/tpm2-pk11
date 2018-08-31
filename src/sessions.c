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

#include <stdlib.h>

#ifdef TCTI_SOCKET_ENABLED
#include <tss2/tss2_tcti_mssim.h>
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_DEVICE_ENABLED
#include <tss2/tss2_tcti_device.h>
#endif // TCTI_DEVICE_ENABLED
#ifdef TCTI_TABRMD_ENABLED
#include <tss2/tss2-tcti-tabrmd.h>
#endif // TCTI_TABRMD_ENABLED

#define DEFAULT_DEVICE "/dev/tpm0"
#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_PORT 2323


int token_init(struct token* token, struct config *config) {
  token->sapi_context = NULL;

  size_t size = 0;
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
  TSS2_RC rc;

  switch(config->type) {
#ifdef TCTI_SOCKET_ENABLED
    case TPM_TYPE_SOCKET:
      rc = Tss2_Tcti_Mssim_Init(NULL, &size, NULL);
      break;
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_DEVICE_ENABLED
    case TPM_TYPE_DEVICE:
      rc = Tss2_Tcti_Device_Init(NULL, &size, NULL);
      break;
#endif // TCTI_DEVICE_ENABLED
#ifdef TCTI_TABRMD_ENABLED
    case TPM_TYPE_TABRMD:
      rc = Tss2_Tcti_Tabrmd_Init(tcti_ctx, &size, NULL);
      break;
#endif // TCTI_TABRMD_ENABLED
    default:
      rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
      break;
  }

  if (rc != TSS2_RC_SUCCESS)
    goto cleanup;

  tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc(1, size);
  if (tcti_ctx == NULL)
    goto cleanup;

  switch(config->type) {
#ifdef TCTI_SOCKET_ENABLED
    case TPM_TYPE_SOCKET: {}
      char *conf = "tcp://127.0.0.1:2323";
      rc = Tss2_Tcti_Mssim_Init(tcti_ctx, &size, conf);
      break;
    }
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_DEVICE_ENABLED
    case TPM_TYPE_DEVICE: {
      char *conf = DEFAULT_DEVICE;
      rc = Tss2_Tcti_Device_Init(tcti_ctx, &size, conf);
      break;
    }
#endif // TCTI_DEVICE_ENABLED
#ifdef TCTI_TABRMD_ENABLED
    case TPM_TYPE_TABRMD:
      rc = Tss2_Tcti_Tabrmd_Init(tcti_ctx, &size, NULL);
      break;
#endif // TCTI_TABRMD_ENABLED
    default:
      rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
      break;
  }

  if (rc != TSS2_RC_SUCCESS)
    goto cleanup;
  
  size = Tss2_Sys_GetContextSize(0);
  token->sapi_context = (TSS2_SYS_CONTEXT*) calloc(1, size);
  if (token->sapi_context == NULL)
    goto cleanup;

  TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
  
  rc = Tss2_Sys_Initialize(token->sapi_context, size, tcti_ctx, &abi_version);

  token->objects = object_load_list(token->sapi_context, config);
  return 0;

  cleanup:
  if (tcti_ctx != NULL)
    free(tcti_ctx);

  if (token->sapi_context != NULL)
    free(token->sapi_context);

  return -1;
}

void token_close(struct token* token) {
  object_free_list(token->objects);
  Tss2_Sys_Finalize(token->sapi_context);
}

int session_init(struct session* session, bool have_write) {
  session->have_write = have_write; 
  return 0;
}

void session_close(struct session* session) {
}
