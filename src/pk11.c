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

#include "pk11.h"
#include "config.h"
#include "sessions.h"
#include "utils.h"
#include "tpm.h"
#include "objects.h"
#include "log.h"
#include "certificate.h"

#include <sys/mman.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <endian.h>

#include <dlfcn.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>

#define SLOT_ID 0x1234

#ifndef PATH_MAX
#define PATH_MAX 256
#endif

#define get_session(x) ((struct session*) x)


struct config pk11_config = {0};
struct session main_session;
bool is_initialised = false;
static void *handle;
static const TSS2_TCTI_INFO *info;
TSS2_TCTI_CONTEXT *tcti = NULL;

#define DISABLE_DLCLOSE

void tpm2_tcti_ldr_unload(void) {
  if (handle) {
#ifndef DISABLE_DLCLOSE
    dlclose(handle);
#endif
    handle = NULL;
    info = NULL;
  }
}

const TSS2_TCTI_INFO *tpm2_tcti_ldr_getinfo(void) {
  return info;
}

static void* tpm2_tcti_ldr_dlopen(const char *name) {
  char path[PATH_MAX];
  size_t size = snprintf(path, sizeof(path), TSS2_TCTI_SO_FORMAT, name);
  if (size >= sizeof(path)) {
    return NULL;
  }

  return dlopen(path, RTLD_LAZY);
}

bool tpm2_tcti_ldr_is_tcti_present(const char *name) {
  void *handle = tpm2_tcti_ldr_dlopen(name);
  if (handle) {
    dlclose(handle);
  }

  return handle != NULL;
}

TSS2_TCTI_CONTEXT *tpm2_tcti_ldr_load(const char *path) {
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

  if (handle) {
    print_log(DEBUG, "Attempting to load multiple tcti's simultaneously is not supported!");
    return NULL;
  }

  /*
  * Try what they gave us, if it doesn't load up, try
  * libtss2-tcti-xxx.so replacing xxx with what they gave us.
  */
  handle = dlopen (path, RTLD_LAZY);
  if (!handle) {

    handle = tpm2_tcti_ldr_dlopen(path);
    if (!handle) {
      print_log(DEBUG, "Could not dlopen library: \"%s\"", path);
      return NULL;
    }
  }

  TSS2_TCTI_INFO_FUNC infofn = (TSS2_TCTI_INFO_FUNC)dlsym(handle, TSS2_TCTI_INFO_SYMBOL);
  if (!infofn) {
    print_log(DEBUG, "Symbol \"%s\"not found in library: \"%s\"", TSS2_TCTI_INFO_SYMBOL, path);
    goto err;
  }

  info = infofn();

  TSS2_TCTI_INIT_FUNC init = info->init;

  size_t size;
  TSS2_RC rc = init(NULL, &size, NULL);
  if (rc != TPM2_RC_SUCCESS) {
    print_log(DEBUG, "tcti init setup routine failed for library: \"%s\"", path);
    goto err;
  }

  tcti_ctx = (TSS2_TCTI_CONTEXT*) calloc(1, size);
  if (tcti_ctx == NULL) {
    goto err;
  }

  rc = init(tcti_ctx, &size, NULL);
  if (rc != TPM2_RC_SUCCESS) {
    print_log(DEBUG, "tcti init allocation routine failed for library: \"%s\"", path);
    goto err;
  }

  return tcti_ctx;

err:
  free(tcti_ctx);
  dlclose(handle);
  return NULL;
}

static CK_RV extractObjectInformation(CK_ATTRIBUTE_PTR template,
              CK_ULONG count,
              CK_OBJECT_CLASS *objClass,
              CK_KEY_TYPE *keyType,
              CK_CERTIFICATE_TYPE *certType,
              CK_BBOOL *isOnToken,
              CK_BBOOL *isPrivate,
              bool bImplicit)
{
  bool bHasClass = false;
  bool bHasKeyType = false;
  bool bHasCertType = false;
  bool bHasPrivate = false;

  // Extract object information
  for (CK_ULONG i = 0; i < count; ++i) {
    switch (template[i].type) {
      case CKA_CLASS:
        if (template[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
          *objClass = *(CK_OBJECT_CLASS_PTR)template[i].pValue;
          bHasClass = true;
        }
        break;
      case CKA_KEY_TYPE:
        if (template[i].ulValueLen == sizeof(CK_KEY_TYPE)) {
          *keyType = *(CK_KEY_TYPE*)template[i].pValue;
          bHasKeyType = true;
        }
        break;
      case CKA_CERTIFICATE_TYPE:
        if (template[i].ulValueLen == sizeof(CK_CERTIFICATE_TYPE)) {
          *certType = *(CK_CERTIFICATE_TYPE*)template[i].pValue;
          bHasCertType = true;
        }
        break;
      case CKA_TOKEN:
        if (template[i].ulValueLen == sizeof(CK_BBOOL)) {
          *isOnToken = *(CK_BBOOL*)template[i].pValue;
        }
        break;
      case CKA_PRIVATE:
        if (template[i].ulValueLen == sizeof(CK_BBOOL)) {
          *isPrivate = *(CK_BBOOL*)template[i].pValue;
          bHasPrivate = true;
        }
        break;
      default:
        break;
    }
  }

  if (bImplicit) {
    return CKR_OK;
  }

  if (!bHasClass) {
    return CKR_TEMPLATE_INCOMPLETE;
  }

  bool bKeyTypeRequired = (*objClass == CKO_PUBLIC_KEY || *objClass == CKO_PRIVATE_KEY || *objClass == CKO_SECRET_KEY);
  if (bKeyTypeRequired && !bHasKeyType) {
     return CKR_TEMPLATE_INCOMPLETE;
  }

  if (*objClass == CKO_CERTIFICATE) {
    if (!bHasCertType) {
      return CKR_TEMPLATE_INCOMPLETE;
    }

    if (!bHasPrivate) {
      // Change default value for certificates
      isPrivate = CK_FALSE;
    }
  }

  if (*objClass == CKO_PUBLIC_KEY && !bHasPrivate) {
    // Change default value for public keys
    isPrivate = CK_FALSE;
  }

  return CKR_OK;
}


CK_RV C_GetInfo(CK_INFO_PTR info) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_GetInfo");
  info->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
  info->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
  strncpy_pad(info->manufacturerID, sizeof(info->manufacturerID), TPM2_PK11_MANUFACTURER, sizeof(info->manufacturerID));
  strncpy_pad(info->libraryDescription, sizeof(info->libraryDescription), TPM2_PK11_LIBRARY_DESCRIPTION, sizeof(info->libraryDescription));
  info->flags = 0;

  return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL present, CK_SLOT_ID_PTR list, CK_ULONG_PTR count) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_GetSlotList: present = %s", present ? "true" : "false");
  if (*count && list)
    *list = SLOT_ID;

  *count = 1;

  return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID id, CK_FLAGS flags, CK_VOID_PTR application, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_OpenSession: id = %d, flags = %x", id, flags);
  *session = (unsigned long) malloc(sizeof(struct session));
  if ((void*) *session == NULL)
    return CKR_GENERAL_ERROR;

  int ret = session_init((struct session*) *session, &pk11_config, flags & CKF_RW_SESSION ? true : false);

  return ret != 0 ? CKR_GENERAL_ERROR : CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE session_handle) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_CloseSession: session = %x", session_handle);
  session_close(get_session(session_handle));
  free(get_session(session_handle));
  return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE session_handle, CK_SESSION_INFO_PTR info) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_GetSessionInfo: session = %x", session_handle);
  info->slotID = 0;
  info->state = CKS_RO_USER_FUNCTIONS;
  info->flags = CKF_SERIAL_SESSION;
  info->ulDeviceError = 0;
  return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID id, CK_SLOT_INFO_PTR info) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_GetSlotInfo: id = %d", id);
  TPMS_CAPABILITY_DATA fixed;
  if (tpm_info(main_session.context, TPM2_PT_FIXED, &fixed) != TPM2_RC_SUCCESS)
    return CKR_DEVICE_ERROR;

  TPML_TAGGED_TPM_PROPERTY props = fixed.data.tpmProperties;
  TPMS_TAGGED_PROPERTY* manufacturer = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_MANUFACTURER);
  UINT32 manufacturer_val = manufacturer ? htobe32(manufacturer->value) : 0;
  strncpy_pad(info->manufacturerID, sizeof(info->manufacturerID), manufacturer ? (char*) &manufacturer_val : TPM2_PK11_MANUFACTURER, manufacturer ? 4 : sizeof(info->manufacturerID));
  strncpy_pad(info->slotDescription, sizeof(info->slotDescription), TPM2_PK11_SLOT_DESCRIPTION, sizeof(info->slotDescription));

  info->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
  TPMS_TAGGED_PROPERTY* revision = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_REVISION);
  info->hardwareVersion.major = revision ? revision->value / 100 : 0;
  info->hardwareVersion.minor = revision ? revision->value % 100 : 0;
  TPMS_TAGGED_PROPERTY* major = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_FIRMWARE_VERSION_1);
  info->firmwareVersion.major = major ? major->value : 0;
  TPMS_TAGGED_PROPERTY* minor = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_FIRMWARE_VERSION_2);
  info->firmwareVersion.minor = major ? major->value : 0;
  return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID id, CK_TOKEN_INFO_PTR info) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_GetTokenInfo: id = %d", id);
  TPMS_CAPABILITY_DATA fixed;
  if (tpm_info(main_session.context, TPM2_PT_FIXED, &fixed) != TPM2_RC_SUCCESS)
    return CKR_DEVICE_ERROR;

  TPML_TAGGED_TPM_PROPERTY props = fixed.data.tpmProperties;
  strncpy_pad(info->label, sizeof(info->label), TPM2_PK11_LABEL, sizeof(info->label));
  TPMS_TAGGED_PROPERTY* manufacturer = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_MANUFACTURER);
  UINT32 manufacturer_val = manufacturer ? htobe32(manufacturer->value) : 0;
  strncpy_pad(info->manufacturerID, sizeof(info->manufacturerID), manufacturer ? (char*) &manufacturer_val : TPM2_PK11_MANUFACTURER, manufacturer ? 4 : sizeof(info->manufacturerID));
  strncpy_pad(info->model, sizeof(info->label), TPM2_PK11_MODEL, sizeof(info->label));
  strncpy_pad(info->serialNumber, sizeof(info->serialNumber), TPM2_PK11_SERIAL, sizeof(info->serialNumber));
  strncpy_pad(info->utcTime, sizeof(info->utcTime), "", sizeof(info->utcTime));

  info->flags = CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;
  if (pk11_config.login_required)
    info->flags |= CKF_LOGIN_REQUIRED;

  TPMS_TAGGED_PROPERTY* max_sessions = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_ACTIVE_SESSIONS_MAX);
  info->ulMaxSessionCount = max_sessions ? max_sessions->value : CK_EFFECTIVELY_INFINITE;
  info->ulSessionCount = open_sessions;
  info->ulMaxRwSessionCount = max_sessions ? max_sessions->value : CK_EFFECTIVELY_INFINITE;
  info->ulRwSessionCount = 0;
  info->ulMaxPinLen = 64;
  info->ulMinPinLen = 0;
  info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  TPMS_TAGGED_PROPERTY* revision = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_REVISION);
  info->hardwareVersion.major = revision ? revision->value / 100 : 0;
  info->hardwareVersion.minor = revision ? revision->value % 100 : 0;
  TPMS_TAGGED_PROPERTY* major = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_FIRMWARE_VERSION_1);
  info->firmwareVersion.major = major ? major->value : 0;
  TPMS_TAGGED_PROPERTY* minor = tpm_info_get(props.tpmProperty, props.count, TPM2_PT_FIRMWARE_VERSION_2);
  info->firmwareVersion.minor = major ? major->value : 0;

  return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR reserved) {
  TSS2_TCTI_CONTEXT *tcti_ctx;

  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;  
  } 

  /* Must be set to NULL_PTR in this version of PKCS#11 */
  if (reserved != NULL_PTR) {
    return CKR_ARGUMENTS_BAD;
  }

  print_log(VERBOSE, "C_Finalize");

  setlogmask (LOG_UPTO (LOG_NOTICE));
  openlog ("tpm2-pk11", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog (LOG_NOTICE, "C_Finalize: User %d", getuid());
  closelog ();
  
  tcti_ctx = NULL;
  if (Tss2_Sys_GetTctiContext(main_session.context, &tcti_ctx) != TSS2_RC_SUCCESS) {
    tcti_ctx = NULL;
  }

  session_close(&main_session);

  object_free_list(main_session.objects);

  if (tcti_ctx) {
    Tss2_Tcti_Finalize(tcti_ctx);
    free(tcti_ctx);
    tcti_ctx = NULL;
  }

  tpm2_tcti_ldr_unload();

  is_initialised = false;

  return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session_handle, CK_ATTRIBUTE_PTR filters, CK_ULONG count) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_FindObjectsInit: session = %x, count = %d", session_handle, count);
  struct session *session = get_session(session_handle);
  session->find_cursor = session->objects;
  session->filters = filters;
  session->num_filters = count;
  return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE_PTR object_handle, CK_ULONG max_objects, CK_ULONG_PTR found) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_FindObjects: session = %x, max = %d", session_handle, max_objects);
  TPMS_CAPABILITY_DATA persistent;
  tpm_info(get_session(session_handle)->context, TPM2_HT_PERSISTENT, &persistent);
  struct session* session = get_session(session_handle);
  *found = 0;
  while (session->find_cursor != NULL && *found < max_objects) {
    pObject object = session->find_cursor->object;
    bool filtered = false;
    for (int j = 0; j < session->num_filters; j++) {
      size_t size = 0;
      void* value = object_attr_get(object, session->filters[j].type, &size);
      if (session->filters[j].ulValueLen != size || memcmp(session->filters[j].pValue, value, size) != 0) {
        filtered = true;
        break;
      }
    }
    if (!filtered) {
      object_handle[*found] = (CK_OBJECT_HANDLE) session->find_cursor->object;
      (*found)++;
    }
    session->find_cursor = session->find_cursor->next;
  }   

  return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session_handle) {
  print_log(VERBOSE, "C_FindObjectsFinal: session = %x", session_handle);
  return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object_handle, CK_ATTRIBUTE_PTR template, CK_ULONG count) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_GetAttributeValue: session = %x, object = %x, count = %d", session_handle, object_handle, count);
  pObject object = (pObject) object_handle;

  for (int i = 0; i < count; i++) {
    size_t size = 0;
    void *value = object_attr_get(object, template[i].type, (size_t*)&size);
    if (value) {
      print_log(DEBUG, "C_GetAttributeValue: template[i].pValue = 0x%x,template[i].ulValueLen = %d, value = 0x%x", template[i].pValue, template[i].ulValueLen, (int)value);
      retmem(template[i].pValue, (size_t*)&template[i].ulValueLen, value, size);  
    }
    else {
      print_log(DEBUG, "C_GetAttributeValue: attribute not found [type = 0x%x]!", template[i].type);
    }
  }

  return CKR_OK;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object_handle, CK_ATTRIBUTE_PTR template, CK_ULONG count) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_SetAttributeValue: session = %x, object = %x, count = %d", session_handle, object_handle, count);
  pObject object = (pObject) object_handle;

  if (get_session(session_handle)->have_write == false) {
    return CKR_SESSION_READ_ONLY;
  }

  for (int i = 0; i < count; i++) {
    object_attr_set(object, template[i].type, template[i].pValue, template[i].ulValueLen);
    if (!object->is_certificate) {
      object_attr_write(object, &pk11_config);
    }
    else {
      certificate_attr_write(object, &pk11_config);  
    }
  }

  return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_SignInit: session = %x, key = %x", session_handle, key);
  pObject object = (pObject) key;
  get_session(session_handle)->handle = object->tpm_handle;
  get_session(session_handle)->current_object = object;

  switch(mechanism->mechanism) {
    case CKM_RSA_X_509:
      get_session(session_handle)->mechanism = CKM_RSA_X_509;
      break;
    case CKM_RSA_PKCS:
      get_session(session_handle)->mechanism = CKM_RSA_PKCS;
      break;
    case CKM_ECDSA:
      get_session(session_handle)->mechanism = CKM_ECDSA;
      break;
    default:
      return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_Sign: session = %x, len = %d", session_handle, data_len);
  struct session* session = get_session(session_handle);
  TPM2_RC rc = CKR_GENERAL_ERROR;
  TPMT_SIGNATURE sign = {0};

  if (session->mechanism == CKM_RSA_PKCS) {
    rc = tpm_rsa_sign(session->context, session->handle, data, data_len, &sign);
    if (rc == TPM2_RC_SUCCESS) {
      retmem(signature, (size_t*)signature_len, sign.signature.rsassa.sig.buffer, sign.signature.rsassa.sig.size);
    } 
  }
  else if (session->mechanism == CKM_ECDSA) {
    rc = tpm_ecc_sign(session->context, session->handle, data, data_len, &sign);
    if (rc == TPM2_RC_SUCCESS) {
      memcpy(signature, sign.signature.ecdsa.signatureR.buffer, sign.signature.ecdsa.signatureR.size);
      memcpy(signature + sign.signature.ecdsa.signatureR.size, sign.signature.ecdsa.signatureS.buffer, sign.signature.ecdsa.signatureS.size);
      *signature_len = sign.signature.ecdsa.signatureR.size + sign.signature.ecdsa.signatureS.size;
    } 
  }
  
  return rc == TPM2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_DecryptInit: session = %x, key = %x", session_handle, key);
  pObject object = (pObject) key;
  get_session(session_handle)->handle = object->tpm_handle;

  switch(mechanism->mechanism) {
    case CKM_RSA_X_509:
      get_session(session_handle)->mechanism = CKM_RSA_X_509;
      break;
    case CKM_RSA_PKCS:
      get_session(session_handle)->mechanism = CKM_RSA_PKCS;
      break;
    default:
      return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR enc_data, CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_Decrypt: session = %x, len = %d", session_handle, enc_data_len);
  TPM2B_PUBLIC_KEY_RSA message = { .size = TPM2_MAX_RSA_KEY_BYTES };
  struct session* session = get_session(session_handle);
  TPM2_RC ret = tpm_rsa_decrypt(session->context, session->handle, enc_data, enc_data_len, &message);
  
  retmem(data, (size_t*)data_len, message.buffer, message.size);

  return ret == TPM2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  CK_C_INITIALIZE_ARGS_PTR args;
  size_t size = 0;
  TSS2_RC rc;
  char configfile_path[256];
  snprintf(configfile_path, sizeof(configfile_path), "%s/" TPM2_PK11_CONFIG_DIR "/" TPM2_PK11_CONFIG_FILE, "/etc");
  
  /* Check if PKCS#11 is already initialized */
  if (is_initialised)
  {
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  }

  /* Do we have any arguments? */
  if (pInitArgs != NULL_PTR) {
    args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;

    if (args->CreateMutex == NULL_PTR ||
        args->DestroyMutex == NULL_PTR ||
        args->LockMutex == NULL_PTR ||
        args->UnlockMutex == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
      }
  }

  memset(&main_session, 0, sizeof(struct session));

  if (config_load(configfile_path, &pk11_config) < 0) {
    return CKR_GENERAL_ERROR;
  }
  
  log_init(pk11_config.log_file, pk11_config.log_level);
  print_log(VERBOSE, "C_Initialize");
  
  setlogmask (LOG_UPTO (LOG_NOTICE));
  openlog ("tpm2-pk11", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog (LOG_NOTICE, "C_Initialize: User %d", getuid());
  closelog ();

  tcti = tpm2_tcti_ldr_load("tabrmd");
  if (!tcti) {
    print_log(VERBOSE, "C_Initialize: Failed!"); 
    return CKR_GENERAL_ERROR; 
  }

  main_session.have_write = true;
  size = Tss2_Sys_GetContextSize(0);
  main_session.context = (TSS2_SYS_CONTEXT*) calloc(1, size);
  if (main_session.context == NULL) {
    return CKR_GENERAL_ERROR;
  }

  TSS2_ABI_VERSION abi_version = TSS2_ABI_VERSION_CURRENT;
  
  rc = Tss2_Sys_Initialize(main_session.context, size, tcti, &abi_version);
  if (rc != TSS2_RC_SUCCESS) {
    free(main_session.context);
    return CKR_GENERAL_ERROR;
  }

  main_session.objects = object_load_list(main_session.context, &pk11_config);
  if (!main_session.objects) {
    free(main_session.context);
    return CKR_GENERAL_ERROR;
  }

  open_sessions++;

  /* Set the state to initialised */
  is_initialised = true;

  setlogmask (LOG_UPTO (LOG_NOTICE));
  openlog ("tpm2-pk11", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog (LOG_NOTICE, "C_Initialize: OK");
  closelog ();

  return CKR_OK;
}

/* Stubs for not yet supported functions*/
CK_RV C_GetMechanismList(CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_GetMechanismList: slot = %d", id);
  CK_ULONG nrSupportedMechanisms = 10;

  CK_MECHANISM_TYPE supportedMechanisms[] =
  {
    CKM_SHA_1,
    CKM_SHA256,
    CKM_SHA_1_HMAC,
    CKM_SHA256_HMAC,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS,
    CKM_RSA_X_509,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDH1_DERIVE
  };

  if (count == NULL_PTR) return CKR_ARGUMENTS_BAD;

  if (list == NULL_PTR)
  {
    *count = nrSupportedMechanisms;

    return CKR_OK;
  }

  if (*count < nrSupportedMechanisms)
  {
    *count = nrSupportedMechanisms;

    return CKR_BUFFER_TOO_SMALL;
  }

  *count = nrSupportedMechanisms;

  for (CK_ULONG i = 0; i < nrSupportedMechanisms; i ++)
  {
    list[i] = supportedMechanisms[i];
  }

  return CKR_OK;
}

CK_RV C_GetMechanismInfo (CK_SLOT_ID id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info) {
  print_log(VERBOSE, "C_GetMechanismInfo: slot = %d", id);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken (CK_SLOT_ID id, CK_CHAR_PTR pin, CK_ULONG pin_len, CK_CHAR_PTR label) {
  print_log(VERBOSE, "C_InitToken: slot = %d", id);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN (CK_SESSION_HANDLE session_handle, CK_CHAR_PTR pin, CK_ULONG pin_len) {
  print_log(VERBOSE, "C_InitPIN: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN (CK_SESSION_HANDLE session_handle, CK_CHAR_PTR old_pin, CK_ULONG old_pin_len, CK_CHAR_PTR new_pin, CK_ULONG new_pin_len) {
  print_log(VERBOSE, "C_SetPIN: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseAllSessions (CK_SLOT_ID id) {
  print_log(VERBOSE, "C_CloseAllSessions: slot = %d", id);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR state, CK_ULONG_PTR state_len) {
  print_log(VERBOSE, "C_GetOperationState: session = %x, len = %d", session_handle, state_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR state, CK_ULONG state_len, CK_OBJECT_HANDLE enc_key, CK_OBJECT_HANDLE auth_key) {
  print_log(VERBOSE, "C_SetOperationState: session = %x, len = %d, enc_key = %x, auth_key = %x", session_handle, state_len, enc_key, auth_key);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE session_handle, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_Login: session = %x", session_handle);
  struct session* session = get_session(session_handle);
  if (userType != CKU_USER)
    return CKR_USER_TYPE_INVALID;

  session->password = strndup(pin, pin_len);

  return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE session_handle) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_Logout: session = %x", session_handle);
  struct session* session = get_session(session_handle);
  if (session->password) {
    free(session->password);
    session->password = NULL;
  }

  return CKR_OK;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE session_handle, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR object) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_CreateObject: session = %x, count = %d", session_handle, count);
  struct session* session = get_session(session_handle);
  if (session->have_write == false) {
    return CKR_SESSION_READ_ONLY;
  }

  *object = CK_INVALID_HANDLE;
  
  void *id = NULL, *label = NULL, *value = NULL;
  size_t id_len = 0, label_len = 0, value_len = 0;

  for (CK_ULONG i = 0; i < count; ++i) {
    switch (template[i].type) {
      case CKA_CLASS:
        if (template[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
          CK_OBJECT_CLASS objClass = *(CK_OBJECT_CLASS_PTR)template[i].pValue;
          if (objClass != CKO_CERTIFICATE) {
            /* Currently only Certificates are supported! */
            return CKR_GENERAL_ERROR;  
          }
        }
        break;
      case CKA_CERTIFICATE_TYPE:
        if (template[i].ulValueLen == sizeof(CK_CERTIFICATE_TYPE)) {
          CK_CERTIFICATE_TYPE certType = *(CK_CERTIFICATE_TYPE*)template[i].pValue;
          if (certType != CKC_X_509) {
            /* Currently only X509 type is supported! */
            return CKR_GENERAL_ERROR;
          }
        }
        break;
      case CKA_ID:
        {
          id = (void*)template[i].pValue;
          id_len = (size_t)template[i].ulValueLen;    
        }
        break;
      case CKA_LABEL:
        {
          label = (void*)template[i].pValue;
          label_len = (size_t)template[i].ulValueLen;    
        }
        break;
      case CKA_VALUE:
        {
          value = (void*)template[i].pValue;
          value_len = (size_t)template[i].ulValueLen;
        }
        break;
      default:
        break;
    }
  }

  if (id && value) {
    pObject newobject = certificate_create(session->objects, &pk11_config, id, id_len, label, label_len, value, value_len);
    if (!newobject) {
      print_log(VERBOSE, "C_CreateObject: ERROR - Cannot create object");
      return CKR_GENERAL_ERROR;  
    }
    *object = (CK_OBJECT_HANDLE)newobject;
  }
  else {
    print_log(VERBOSE, "C_CreateObject: ERROR - Bad template!");
    return CKR_GENERAL_ERROR;  
  }

  return CKR_OK;
}


CK_RV C_CopyObject(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object_handle, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR new_object) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_CopyObject: session = %x, object = %x, count = %d", session_handle, object_handle, count);
  struct session* session = get_session(session_handle);
  pObject object = (pObject) object_handle;
  pObject newobject = object_copy(object);
  if (newobject == NULL) {
    return CKR_GENERAL_ERROR;
  }

  for (int i = 0; i < count; i++) {
    object_attr_set(newobject, template[i].type, template[i].pValue, template[i].ulValueLen);
  }

  //Add object to list
  object_add(session->objects, newobject);

  *new_object = (CK_OBJECT_HANDLE)newobject;

  return CKR_OK;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object_handle) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_DestroyObject: session = %x, object = %x", session_handle, object_handle);
  struct session* session = get_session(session_handle);
  pObject object = (pObject) object_handle;    

  if (session->have_write == false) {
    return CKR_SESSION_READ_ONLY;
  }

  if (object) {
    if (!object->is_copy && !object->is_certificate && object->tpm_handle) {
      TPM2_RC ret = tpm_evict_control(session->context, object->tpm_handle);
      object_delete(object, &pk11_config); 
      if (ret != TPM2_RC_SUCCESS) {
        return CKR_GENERAL_ERROR;
      } 
    }
    else if (object->is_certificate) {
      certificate_delete(object, &pk11_config);   
    }

    if (!object->is_copy && object->userdata) {
      free(object->userdata);
    }  
  }
  else {
    return CKR_GENERAL_ERROR;  
  }

  object_remove(&session->objects, object);

  free(object);

  return CKR_OK;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object_handle, CK_ULONG_PTR size) {
  print_log(VERBOSE, "C_GetObjectSize: session = %x, object = %x", session_handle, object_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE object_handle) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_EncryptInit: session = %x, object = %x", session_handle, object_handle);
  pObject object = (pObject) object_handle;
  get_session(session_handle)->handle = object->tpm_handle;

  switch(mechanism->mechanism) {
    case CKM_RSA_X_509:
      get_session(session_handle)->mechanism = CKM_RSA_X_509;
      break;
    case CKM_RSA_PKCS:
      get_session(session_handle)->mechanism = CKM_RSA_PKCS;
      break;
    default:
      return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR enc_data, CK_ULONG_PTR enc_data_len) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_Encrypt: session = %x, len = %x", session_handle, data_len);
  TPM2B_PUBLIC_KEY_RSA message = { .size = TPM2_MAX_RSA_KEY_BYTES };
  struct session* session = get_session(session_handle);

  TPM2_RC ret = tpm_rsa_encrypt(session->context, session->handle, data, data_len, &message);
  
  retmem(enc_data, (size_t*)enc_data_len, message.buffer, message.size);

  return ret == TPM2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR enc_data, CK_ULONG_PTR enc_data_len) {
  print_log(VERBOSE, "C_EncryptUpdate: session = %x, len = %x", session_handle, data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR enc_data, CK_ULONG_PTR enc_data_len) {
  print_log(VERBOSE, "C_EncryptFinal: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR enc_data, CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
  print_log(VERBOSE, "C_DecryptUpdate: session = %x, len = %x", session_handle, enc_data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
  print_log(VERBOSE, "C_DecryptFinal: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism) {
  print_log(VERBOSE, "C_DigestInit: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) {
  print_log(VERBOSE, "C_Digest: session = %x, len = %x", session_handle, data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len) {
  print_log(VERBOSE, "C_DigestUpdate: session = %x, len = %x", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE session_handle, CK_OBJECT_HANDLE object) {
  print_log(VERBOSE, "C_DigestKey: session = %x, object = %x", session_handle, object);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) {
  print_log(VERBOSE, "C_DigestFinal: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len) {
  print_log(VERBOSE, "C_SignUpdate: session = %x, len = %x", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
  print_log(VERBOSE, "C_SignFinal: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  print_log(VERBOSE, "C_SignRecoverInit: session = %x, key = %x", session_handle, key);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) {
  print_log(VERBOSE, "C_SignRecover: session = %x, len = %d", session_handle, data_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_VerifyInit: session = %x, key = %x", session_handle, key);
  pObject object = (pObject) key;
  get_session(session_handle)->handle = object->tpm_handle;
  get_session(session_handle)->current_object = object;

  switch(mechanism->mechanism) {
    case CKM_RSA_X_509:
      get_session(session_handle)->mechanism = CKM_RSA_X_509;
      break;
    case CKM_RSA_PKCS:
      get_session(session_handle)->mechanism = CKM_RSA_PKCS;
      break;
    case CKM_ECDSA:
      get_session(session_handle)->mechanism = CKM_ECDSA;
      break;
    default:
      return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

CK_RV C_Verify(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG signature_len) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_Verify: session = %x, len = %d", session_handle, data_len);
  struct session* session = get_session(session_handle);
  TPMT_SIGNATURE sign = {0};
  TPM2_RC rc;
  
  if (session->mechanism == CKM_RSA_PKCS) {
    memcpy(sign.signature.rsassa.sig.buffer, signature, (size_t)signature_len);
    sign.signature.rsassa.sig.size = signature_len;
  }
  else if (session->mechanism == CKM_ECDSA) {
    memcpy(sign.signature.ecdsa.signatureR.buffer, signature, (size_t)signature_len/2);
    sign.signature.ecdsa.signatureR.size = signature_len/2;
    memcpy(sign.signature.ecdsa.signatureS.buffer, signature + sign.signature.ecdsa.signatureR.size, (size_t)signature_len/2);
    sign.signature.ecdsa.signatureS.size = signature_len/2;  
  }
  else {
    return CKR_GENERAL_ERROR;  
  }

  rc = tpm_verify(session->context, session->handle, &sign, data, data_len);

  return rc == TPM2_RC_SUCCESS ? CKR_OK : CKR_SIGNATURE_INVALID;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len) {
  print_log(VERBOSE, "C_VerifyUpdate: session = %x, len = %d", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR signature, CK_ULONG signature_len) {
  print_log(VERBOSE, "C_VerifyFinal: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) {
  print_log(VERBOSE, "C_VerifyRecoverInit: session = %x, key = %x", session_handle, key);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR signature, CK_ULONG signature_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) {
  print_log(VERBOSE, "C_VerifyRecover: session = %x, len = %d", session_handle, signature_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR enc_part, CK_ULONG_PTR enc_part_len) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR dec_part, CK_ULONG_PTR dec_part_len) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR enc_part, CK_ULONG_PTR enc_part_len) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", session_handle, part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR enc_part, CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", session_handle, enc_part_len);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
  print_log(VERBOSE, "C_GenerateKey: session = %x, count = %d", session_handle, count);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR public_key_template, CK_ULONG public_key_attr_count, CK_ATTRIBUTE_PTR private_key_template, CK_ULONG private_key_attr_count, CK_OBJECT_HANDLE_PTR public_key, CK_OBJECT_HANDLE_PTR private_key) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_GenerateKeyPair: session = %x, public_count = %d, private_count = %d", session_handle, public_key_attr_count, private_key_attr_count);
  struct session* session = get_session(session_handle);
  TPM2_ALG_ID algorithm_type;

  if (mechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
  if (public_key == NULL_PTR) return CKR_ARGUMENTS_BAD;
  if (private_key == NULL_PTR) return CKR_ARGUMENTS_BAD;

  if (get_session(session_handle)->have_write == false) {
    return CKR_SESSION_READ_ONLY;
  }

  *public_key = CK_INVALID_HANDLE;
  *private_key = CK_INVALID_HANDLE;

  // Check the mechanism, only accept RSA, EC key pair generation.
  CK_KEY_TYPE keyType;
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
      keyType = CKK_RSA;
      algorithm_type = TPM2_ALG_RSA;
      break;
    case CKM_EC_KEY_PAIR_GEN:
      keyType = CKK_EC;
      algorithm_type = TPM2_ALG_ECC;
      break;
    default:
      return CKR_MECHANISM_INVALID;
  }

  CK_CERTIFICATE_TYPE dummy;

  // Extract information from the public key template that is needed to create the object.
  CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
  CK_BBOOL ispublicKeyToken = CK_FALSE;
  CK_BBOOL ispublicKeyPrivate = CK_FALSE;
  bool isPublicKeyImplicit = true;
  extractObjectInformation(public_key_template, public_key_attr_count, &publicKeyClass, &keyType, &dummy, &ispublicKeyToken, &ispublicKeyPrivate, isPublicKeyImplicit);

  // Report errors caused by accidental template mix-ups in the application using this lib.
  if (publicKeyClass != CKO_PUBLIC_KEY)
    return CKR_ATTRIBUTE_VALUE_INVALID;
  if (mechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
    return CKR_TEMPLATE_INCONSISTENT;
  if (mechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
    return CKR_TEMPLATE_INCONSISTENT;

  // Extract information from the private key template that is needed to create the object.
  CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
  CK_BBOOL isprivateKeyToken = CK_FALSE;
  CK_BBOOL isprivateKeyPrivate = CK_TRUE;
  bool isPrivateKeyImplicit = true;
  extractObjectInformation(private_key_template, private_key_attr_count, &privateKeyClass, &keyType, &dummy, &isprivateKeyToken, &isprivateKeyPrivate, isPrivateKeyImplicit);

  // Report errors caused by accidental template mix-ups in the application using this lib.
  if (privateKeyClass != CKO_PRIVATE_KEY)
    return CKR_ATTRIBUTE_VALUE_INVALID;
  if (mechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
    return CKR_TEMPLATE_INCONSISTENT;
  if (mechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
    return CKR_TEMPLATE_INCONSISTENT;

  pObject object = object_generate_pair(session->context, algorithm_type, session->objects, &pk11_config);
  if (object == NULL) {
    return CKR_FUNCTION_FAILED; 
  }
  //Add object to list
  object_add(session->objects, object);
  *public_key = (CK_OBJECT_HANDLE)object;
  object_add(session->objects, object->opposite);
  *private_key = (CK_OBJECT_HANDLE)object->opposite;

  print_log(VERBOSE, "C_GenerateKeyPair: Finished OK");
  return CKR_OK;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len) {
  print_log(VERBOSE, "C_WrapKey: session = %x, wrapping_key = %x, key = %x", session_handle, wrapping_key, key);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
  print_log(VERBOSE, "C_UnwrapKey: session = %x, unwrapping_key = %x, key = %x, count = %d", session_handle, unwrapping_key, key, count);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE session_handle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
  print_log(VERBOSE, "C_WrapKey: session = %x, base_key = %x, count = %d", session_handle, base_key, count);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR seed, CK_ULONG seed_len) {
  // jturnsek: N/A
  print_log(VERBOSE, "C_SeedRandom: session = %x, len = %d", session_handle, seed_len);
  return CKR_OK;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE session_handle, CK_BYTE_PTR random_data, CK_ULONG random_data_len) {
  if (!is_initialised) {
    return CKR_CRYPTOKI_NOT_INITIALIZED;
  }
  print_log(VERBOSE, "C_GenerateRandom: session = %x, len = %d", session_handle, random_data_len);
  struct session* session = get_session(session_handle);
  TPM2B_DIGEST random_bytes;

  TPM2_RC rval = Tss2_Sys_GetRandom(session->context, NULL, random_data_len, &random_bytes, NULL);
  if (rval != TPM2_RC_SUCCESS) {
    return CKR_GENERAL_ERROR;
  }

  retmem(random_data, (size_t*)&random_data_len, random_bytes.buffer, random_bytes.size);

  return CKR_OK;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE session_handle) {
  print_log(VERBOSE, "C_GetFunctionStatus: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE session_handle) {
  print_log(VERBOSE, "C_CancelFunction: session = %x", session_handle);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR slot, CK_VOID_PTR reserved) {
  print_log(VERBOSE, "C_WaitForSlotEvent: flags = %x", flags);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_FUNCTION_LIST function_list = {
  { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
  .C_Initialize = C_Initialize,
  .C_Finalize = C_Finalize,
  .C_GetInfo = C_GetInfo,
  .C_GetSlotList = C_GetSlotList,
  .C_GetSlotInfo = C_GetSlotInfo,
  .C_GetTokenInfo = C_GetTokenInfo,
  .C_GetMechanismList = C_GetMechanismList,
  .C_GetMechanismInfo = C_GetMechanismInfo,
  .C_InitToken = C_InitToken,
  .C_InitPIN = C_InitPIN,
  .C_SetPIN = C_SetPIN,
  .C_OpenSession = C_OpenSession,
  .C_CloseSession = C_CloseSession,
  .C_CloseAllSessions = C_CloseAllSessions,
  .C_GetSessionInfo = C_GetSessionInfo,
  .C_CloseAllSessions = C_CloseAllSessions,
  .C_GetOperationState = C_GetOperationState,
  .C_SetOperationState = C_SetOperationState,
  .C_Login = C_Login,
  .C_Logout = C_Logout,
  .C_CreateObject = C_CreateObject,
  .C_CopyObject = C_CopyObject,
  .C_DestroyObject = C_DestroyObject,
  .C_GetObjectSize = C_GetObjectSize,
  .C_GetAttributeValue = C_GetAttributeValue,
  .C_SetAttributeValue = C_SetAttributeValue,
  .C_FindObjectsInit = C_FindObjectsInit,
  .C_FindObjects = C_FindObjects,
  .C_FindObjectsFinal = C_FindObjectsFinal,
  .C_EncryptInit = C_EncryptInit,
  .C_Encrypt = C_Encrypt,
  .C_EncryptUpdate = C_EncryptUpdate,
  .C_EncryptFinal = C_EncryptFinal,
  .C_DecryptInit = C_DecryptInit,
  .C_Decrypt = C_Decrypt,
  .C_DecryptUpdate = C_DecryptUpdate,
  .C_DecryptFinal = C_DecryptFinal,
  .C_DigestInit = C_DigestInit,
  .C_Digest = C_Digest,
  .C_DigestUpdate = C_DigestUpdate,
  .C_DigestKey = C_DigestKey,
  .C_DigestFinal = C_DigestFinal,
  .C_SignInit = C_SignInit,
  .C_Sign = C_Sign,
  .C_SignUpdate = C_SignUpdate,
  .C_SignFinal = C_SignFinal,
  .C_SignRecoverInit = C_SignRecoverInit,
  .C_SignRecover = C_SignRecover,
  .C_VerifyInit = C_VerifyInit,
  .C_Verify = C_Verify,
  .C_VerifyUpdate = C_VerifyUpdate,
  .C_VerifyFinal = C_VerifyFinal,
  .C_VerifyRecoverInit = C_VerifyRecoverInit,
  .C_VerifyRecover = C_VerifyRecover,
  .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
  .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
  .C_SignEncryptUpdate = C_SignEncryptUpdate,
  .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
  .C_GenerateKey = C_GenerateKey,
  .C_GenerateKeyPair = C_GenerateKeyPair,
  .C_WrapKey = C_WrapKey,
  .C_UnwrapKey = C_UnwrapKey,
  .C_DeriveKey = C_DeriveKey,
  .C_SeedRandom = C_SeedRandom,
  .C_GenerateRandom = C_GenerateRandom,
  .C_GetFunctionStatus = C_GetFunctionStatus,
  .C_CancelFunction = C_CancelFunction,
  .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR list) {
  if (list == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  *list = &function_list;
  return CKR_OK;
}