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
#include <dlfcn.h>

#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>


#define DEFAULT_DEVICE "/dev/tpm0"
#define DEFAULT_HOSTNAME "127.0.0.1"
#define DEFAULT_PORT 2323

unsigned int open_sessions;
pObjectList objects;

int session_init(struct session* session, struct config *config, bool have_write, bool is_main) {
  setlogmask (LOG_UPTO (LOG_NOTICE));
  openlog ("tpm2-pk11", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog (LOG_NOTICE, "session_init: User %d, Session 0x%x", getuid(), (long)session);
  closelog ();

  memset(session, 0, sizeof(struct session));

  session->have_write = have_write;

  size_t size = 0;
  TSS2_RC rc;

#if 0
  TSS2_RC (*init)(TSS2_TCTI_CONTEXT *, size_t *, const char *conf);
#ifdef TCTI_DEVICE_ENABLED
  char* device_conf;
#endif // TCTI_DEVICE_ENABLED
  
  switch(config->type) {
#ifdef TCTI_SOCKET_ENABLED
    case TPM_TYPE_SOCKET:
      rc = InitSocketTcti(NULL, &size, NULL, 0);
      break;
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_MSSIM_ENABLED
    case TPM_TYPE_SOCKET:
      rc = Tss2_Tcti_Mssim_Init(NULL, &size, NULL);
      break;
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_DEVICE_ENABLED
    case TPM_TYPE_DEVICE:
      rc = Tss2_Tcti_Device_Init(NULL, &size, device_conf);
      break;
#endif // TCTI_DEVICE_ENABLED
#ifdef TCTI_TABRMD_ENABLED
    case TPM_TYPE_TABRMD:
      session->tcti_handle = dlopen("libtss2-tcti-tabrmd.so.0", RTLD_LAZY);
      setlogmask (LOG_UPTO (LOG_NOTICE));
      openlog ("tpm2-pk11", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
      syslog (LOG_NOTICE, "tcti_handle=0x%x", (long)session->tcti_handle);
      closelog ();
      if (!session->tcti_handle) {
        goto cleanup;
      }
      init = dlsym(session->tcti_handle, "Tss2_Tcti_Tabrmd_Init");
      setlogmask (LOG_UPTO (LOG_NOTICE));
      openlog ("tpm2-pk11", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
      syslog (LOG_NOTICE, "init=0x%x", (long)init);
      closelog ();
      if (!init) {
        dlclose(session->tcti_handle);
        goto cleanup; 
      }
      rc = init(NULL, &size, NULL);
      if (rc != TSS2_RC_SUCCESS) {
        dlclose(session->tcti_handle);
      } 
      break;
#endif // TCTI_TABRMD_ENABLED
    default:
      rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
      break;
  }

  if (rc != TSS2_RC_SUCCESS)
    goto cleanup;

  session->tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc(1, size);
  if (session->tcti_ctx == NULL)
    goto cleanup;

#ifdef TCTI_SOCKET_ENABLED
  TCTI_SOCKET_CONF socket_conf;
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_MSSIM_ENABLED
  const char tcti_uri[256];
#endif // TCTI_MSSIM_ENABLED

  switch(config->type) {
#ifdef TCTI_SOCKET_ENABLED
    case TPM_TYPE_SOCKET:
      socket_conf = (TCTI_SOCKET_CONF) { .hostname = config->hostname != NULL ? config->hostname : DEFAULT_HOSTNAME, .port = config->port > 0 ? config->port : DEFAULT_PORT };
      rc = InitSocketTcti(session->tcti_ctx, &size, &socket_conf, 0);
      break;
#endif // TCTI_SOCKET_ENABLED
#ifdef TCTI_MSSIM_ENABLED
    case TPM_TYPE_SOCKET:
      snprintf("tcp://%s:%d", sizeof(tcti_uri), config->hostname != NULL ? config->hostname : DEFAULT_HOSTNAME, config->port > 0 ? config->port : DEFAULT_PORT);
      rc = Tss2_Tcti_Mssim_Init(session->tcti_ctx, &size, (const char*) &tcti_uri);
      break;
#endif // TCTI_MSSIM_ENABLED
#ifdef TCTI_DEVICE_ENABLED
    case TPM_TYPE_DEVICE: {
      char *conf = (config->device != NULL ? config->device : DEFAULT_DEVICE);
      rc = Tss2_Tcti_Device_Init(session->tcti_ctx, &size, device_conf);
      break;
    }
#endif // TCTI_DEVICE_ENABLED
#ifdef TCTI_TABRMD_ENABLED
    case TPM_TYPE_TABRMD:
      rc = init(session->tcti_ctx, &size, NULL);
      if (rc != TSS2_RC_SUCCESS) {
        setlogmask (LOG_UPTO (LOG_NOTICE));
        openlog ("tpm2-pk11", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
        syslog (LOG_NOTICE, "rc=0x%x", (long)rc);
        closelog ();
        dlclose(session->tcti_handle);
      }
      break;
#endif // TCTI_TABRMD_ENABLED
    default:
      rc = TSS2_TCTI_RC_NOT_IMPLEMENTED;
      break;
  }

  if (rc != TSS2_RC_SUCCESS)
    goto cleanup;

#endif //0

  size = Tss2_Sys_GetContextSize(0);
  session->context = (TSS2_SYS_CONTEXT*) calloc(1, size);
  if (session->context == NULL)
    goto cleanup;

  TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
  
  rc = Tss2_Sys_Initialize(session->context, size, session->tcti_ctx, &abi_version);

  if (is_main) {
    objects = object_load_list(session->context, config);
    if (!objects) {
      goto cleanup;
    }
  }

  session->objects = objects;
  open_sessions++;
   
  return 0;

  cleanup:
#if 0
  if (session->tcti_ctx != NULL)
    free(session->tcti_ctx);
#endif //0
  if (session->context != NULL)
    free(session->context);

  return -1;
}

void session_close(struct session* session, bool is_main) {
  setlogmask (LOG_UPTO (LOG_NOTICE));
  openlog ("tpm2-pk11", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog (LOG_NOTICE, "session_close: session=0x%x", (long)session);
  closelog ();

  if (session->password) {
    free(session->password);
  }

  if (is_main) {
    object_free_list(session->objects);
  }

  Tss2_Sys_Finalize(session->context);
  free(session->context);
  open_sessions--;
}
