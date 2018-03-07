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
#include "object.h"
#include "log.h"

#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

#define SLOT_ID 0x1234

#define get_session(x) ((struct session*) x)

static struct config pk11_config = {0};
static struct token pk11_token = {0};

static CK_RV extractObjectInformation(CK_ATTRIBUTE_PTR pTemplate,
              CK_ULONG ulCount,
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
  for (CK_ULONG i = 0; i < ulCount; ++i) {
    switch (pTemplate[i].type) {
      case CKA_CLASS:
        if (pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
          *objClass = *(CK_OBJECT_CLASS_PTR)pTemplate[i].pValue;
          bHasClass = true;
        }
        break;
      case CKA_KEY_TYPE:
        if (pTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE)) {
          *keyType = *(CK_KEY_TYPE*)pTemplate[i].pValue;
          bHasKeyType = true;
        }
        break;
      case CKA_CERTIFICATE_TYPE:
        if (pTemplate[i].ulValueLen == sizeof(CK_CERTIFICATE_TYPE)) {
          *certType = *(CK_CERTIFICATE_TYPE*)pTemplate[i].pValue;
          bHasCertType = true;
        }
        break;
      case CKA_TOKEN:
        if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          *isOnToken = *(CK_BBOOL*)pTemplate[i].pValue;
        }
        break;
      case CKA_PRIVATE:
        if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
          *isPrivate = *(CK_BBOOL*)pTemplate[i].pValue;
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


CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
  print_log(VERBOSE, "C_GetInfo");
  pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
  pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
  strncpy_pad(pInfo->manufacturerID, TPM2_PK11_MANUFACTURER, sizeof(pInfo->manufacturerID));
  strncpy_pad(pInfo->libraryDescription, TPM2_PK11_LIBRARY_DESCRIPTION, sizeof(pInfo->libraryDescription));
  pInfo->libraryVersion.major = LIBRARY_VERSION_MAJOR;
  pInfo->libraryVersion.minor = LIBRARY_VERSION_MINOR;
  pInfo->flags = 0;

  return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
  print_log(VERBOSE, "C_GetSlotList: present = %s", tokenPresent ? "true" : "false");
  if (*pulCount && pSlotList)
    *pSlotList = SLOT_ID;

  *pulCount = 1;

  return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
  print_log(VERBOSE, "C_OpenSession: id = %d, flags = %x", slotID, flags);
  *phSession = (unsigned long) malloc(sizeof(struct session));
  if ((void*) *phSession == NULL)
    return CKR_GENERAL_ERROR;

  int ret = session_init((struct session*) *phSession);
  print_log(VERBOSE, "C_OpenSession: ret = %d", ret);
  return ret != 0 ? CKR_GENERAL_ERROR : CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
  print_log(VERBOSE, "C_CloseSession: session = %x", hSession);
  session_close(get_session(hSession));

  free(get_session(hSession));
  return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo) {
  print_log(VERBOSE, "C_GetSessionInfo: session = %x", hSession);
  pInfo->slotID = 0;
  pInfo->state = CKS_RO_USER_FUNCTIONS;
  pInfo->flags = CKF_SERIAL_SESSION;
  pInfo->ulDeviceError = 0;
  return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  print_log(VERBOSE, "C_GetSlotInfo: id = %d", slotID);
  strncpy_pad(pInfo->manufacturerID, TPM2_PK11_MANUFACTURER, sizeof(pInfo->manufacturerID));
  strncpy_pad(pInfo->slotDescription, TPM2_PK11_SLOT_DESCRIPTION, sizeof(pInfo->slotDescription));
  pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
  pInfo->hardwareVersion.major = 0;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 0;
  return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  print_log(VERBOSE, "C_GetTokenInfo: id = %d", slotID);
  strncpy_pad(pInfo->label, TPM2_PK11_LABEL, sizeof(pInfo->label));
  strncpy_pad(pInfo->manufacturerID, TPM2_PK11_MANUFACTURER, sizeof(pInfo->manufacturerID));
  strncpy_pad(pInfo->model, TPM2_PK11_MODEL, sizeof(pInfo->label));
  strncpy_pad(pInfo->serialNumber, TPM2_PK11_SERIAL, sizeof(pInfo->serialNumber));
  strncpy_pad(pInfo->utcTime, "", sizeof(pInfo->utcTime));

  pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;
  pInfo->ulMaxSessionCount = 1;
  pInfo->ulSessionCount = 0;
  pInfo->ulMaxRwSessionCount = 1;
  pInfo->ulRwSessionCount = 0;
  pInfo->ulMaxPinLen = 64;
  pInfo->ulMinPinLen = 8;
  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->hardwareVersion.major = 0;
  pInfo->hardwareVersion.minor = 0;
  pInfo->firmwareVersion.major = 0;
  pInfo->firmwareVersion.minor = 0;

  return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
  print_log(VERBOSE, "C_Finalize");

  token_close(&pk11_token);

  return CKR_OK;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  print_log(VERBOSE, "C_FindObjectsInit: session = %x, template =%x, count = %d", hSession, pTemplate, ulCount);
  struct session *session = get_session(hSession);
  session->find_cursor = pk11_token.objects;
  session->filters = pTemplate;
  session->num_filters = ulCount;
  return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
  print_log(VERBOSE, "C_FindObjects: session = %x, max = %d", hSession, ulMaxObjectCount);
  TPMS_CAPABILITY_DATA persistent;
  tpm_list(pk11_token.sapi_context, &persistent);
  struct session* session = get_session(hSession);
  *pulObjectCount = 0;
  while (session->find_cursor != NULL && *pulObjectCount < ulMaxObjectCount) {
    pObject object = session->find_cursor->object;
    bool filtered = false;
    for (int j = 0; j < session->num_filters; j++) {
      size_t size = 0;
      void* value = attr_get(object, session->filters[j].type, &size);
      if (!value) {
        return CKR_GENERAL_ERROR;
      }
      if (session->filters[j].ulValueLen != size || memcmp(session->filters[j].pValue, value, size) != 0) {
        filtered = true;
        break;
      }
    }
    if (!filtered) {
      phObject[*pulObjectCount] = (CK_OBJECT_HANDLE) session->find_cursor->object;
      (*pulObjectCount)++;
    }
    session->find_cursor = session->find_cursor->next;
  }   

  return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  print_log(VERBOSE, "C_FindObjectsFinal: session = %x", hSession);
  return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  print_log(VERBOSE, "C_GetAttributeValue: session = %x, object = %x, count = %d", hSession, hObject, ulCount);
  pObject object = (pObject) hObject;

  for (int i = 0; i < ulCount; i++) {
    void* entry_obj = NULL;
    pAttrIndex entry = NULL;
    
    for (int j = 0; j < object->num_entries; j++) {
      void *obj = object->entries[j].object;
      pAttrIndex index = object->entries[j].indexes;
      for (int k = 0; k < object->entries[j].num_attrs; k++) {
        if (pTemplate[i].type == index[k].type) {
          entry = &index[k];
          entry_obj = obj;
          continue;
        }
      }
      if (entry)
        continue;
    }
    if (!entry) {
      print_log(DEBUG, " attribute not found: type = %x", pTemplate[i].type);
      pTemplate[i].ulValueLen = 0;
    } else if (entry->size_offset == 0) {
      print_log(DEBUG, " return attribute: type = %x, size = %d, buffer_size = %d", pTemplate[i].type, entry->size, pTemplate[i].ulValueLen);
      retmem(pTemplate[i].pValue, &pTemplate[i].ulValueLen, entry_obj + entry->offset, entry->size);
    } else {
      print_log(DEBUG, " return attribute: type = %x, size = %d, buffer_size = %d", pTemplate[i].type, *((size_t*) (entry_obj + entry->size_offset)), pTemplate[i].ulValueLen);
      retmem(pTemplate[i].pValue, &pTemplate[i].ulValueLen, *((void**) (entry_obj + entry->offset)), *((size_t*) (entry_obj + entry->size_offset)));
    }
  }

  return CKR_OK;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  print_log(VERBOSE, "C_SetAttributeValue: session = %x, object = %x, count = %d", hSession, hObject, ulCount);
  pObject object = (pObject) hObject;

  for (int i = 0; i < ulCount; i++) {
    void* entry_obj = NULL;
    pAttrIndex entry = NULL;
    for (int j = 0; j < object->num_entries; j++) {
      void *obj = object->entries[j].object;
      pAttrIndex index = object->entries[j].indexes;
      for (int k = 0; k < object->entries[j].num_attrs; k++) {
        if (pTemplate[i].type == index[k].type) {
          entry = &index[k];
          entry_obj = obj;
          continue;
        }
      }
      if (entry)
        continue;
    }
    if (!entry) {
      print_log(DEBUG, " attribute not found: type = %x", pTemplate[i].type);
      pTemplate[i].ulValueLen = 0;
    } else if (entry->size_offset == 0) {
      print_log(DEBUG, " return attribute: type = %x, size = %d, buffer_size = %d", pTemplate[i].type, entry->size, pTemplate[i].ulValueLen);
      if (pTemplate[i].ulValueLen <= entry->size) {
        memcpy(entry_obj + entry->offset, pTemplate[i].pValue, pTemplate[i].ulValueLen);
      }
    } else {
      print_log(DEBUG, " return attribute: type = %x, size = %d, buffer_size = %d", pTemplate[i].type, *((size_t*) (entry_obj + entry->size_offset)), pTemplate[i].ulValueLen);
      if (pTemplate[i].ulValueLen <= *((size_t*) (entry_obj + entry->size_offset))) {
        memcpy(*((void**) (entry_obj + entry->offset)), pTemplate[i].pValue, pTemplate[i].ulValueLen);
      }
    }
  }

  return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  print_log(VERBOSE, "C_SignInit: session = %x, key = %x", hSession, hKey);
  pObject object = (pObject) hKey;
  get_session(hSession)->handle = object->tpm_handle;
  get_session(hSession)->current_object = object;

  switch(pMechanism->mechanism) {
    case CKM_RSA_X_509:
      get_session(hSession)->mechanism = CKM_RSA_X_509;
      break;
    case CKM_RSA_PKCS:
      get_session(hSession)->mechanism = CKM_RSA_PKCS;
      break;
    case CKM_ECDSA:
      get_session(hSession)->mechanism = CKM_ECDSA;
      break;
    default:
      return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  print_log(VERBOSE, "C_Sign: session = %x, len = %d", hSession, ulDataLen);
  struct session* session = get_session(hSession);
  TPM2_RC rc = CKR_GENERAL_ERROR;
  TPMT_SIGNATURE signature = {0};

  if (session->mechanism == CKM_RSA_PKCS) {
    rc = tpm_rsa_sign(pk11_token.sapi_context, session->handle, pData, ulDataLen, &signature);
    if (rc == TPM2_RC_SUCCESS) {
      retmem(signature, (size_t*)pulSignatureLen, sign.signature.rsassa.sig.buffer, sign.signature.rsassa.sig.size);
    } 
  }
  else if (session->mechanism == CKM_ECDSA) {
    rc = tpm_ecc_sign(pk11_token.sapi_context, session->handle, pData, ulDataLen, &signature);
    if (rc == TPM2_RC_SUCCESS) {
      //TODO
    } 
  }
  
  return rc == TPM2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  print_log(VERBOSE, "C_DecryptInit: session = %x, key = %x", hSession, hKey);
  pObject object = (pObject) hKey;
  get_session(hSession)->handle = object->tpm_handle;

  switch(pMechanism->mechanism) {
    case CKM_RSA_X_509:
      get_session(hSession)->mechanism = CKM_RSA_X_509;
      break;
    case CKM_RSA_PKCS:
      get_session(hSession)->mechanism = CKM_RSA_PKCS;
      break;
    default:
      return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
  print_log(VERBOSE, "C_Decrypt: session = %x, len = %d", hSession, ulEncryptedDataLen);
  TPM2B_PUBLIC_KEY_RSA message = { .size = TPM2_MAX_RSA_KEY_BYTES };
  struct session* session = get_session(hSession);
  TPM2_RC ret = tpm_rsa_decrypt(pk11_token.sapi_context, session->handle, pEncryptedData, ulEncryptedDataLen, &message);
  
  retmem(pData, (size_t*)pulDataLen, message.buffer, message.size);

  return ret == TPM2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
  print_log(VERBOSE, "C_Initialize");
  char configfile_path[256];
  snprintf(configfile_path, sizeof(configfile_path), "%s/" TPM2_PK11_CONFIG_DIR "/" TPM2_PK11_CONFIG_FILE, getenv("HOME"));
  if (config_load(configfile_path, &pk11_config) < 0)
    return CKR_GENERAL_ERROR;

  if (token_init(&pk11_token, &pk11_config) < 0) {
    return CKR_GENERAL_ERROR; 
  }

  log_init(pk11_config.log_file, pk11_config.log_level);

  return CKR_OK;
}

/* Stubs for not yet supported functions*/
CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount) {
  print_log(VERBOSE, "C_GetMechanismList: slot = %d", slotID);
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

  if (pulCount == NULL_PTR) return CKR_ARGUMENTS_BAD;

  if (pMechanismList == NULL_PTR)
  {
    *pulCount = nrSupportedMechanisms;

    return CKR_OK;
  }

  if (*pulCount < nrSupportedMechanisms)
  {
    *pulCount = nrSupportedMechanisms;

    return CKR_BUFFER_TOO_SMALL;
  }

  *pulCount = nrSupportedMechanisms;

  for (CK_ULONG i = 0; i < nrSupportedMechanisms; i ++)
  {
    pMechanismList[i] = supportedMechanisms[i];
  }

  return CKR_OK;
}

CK_RV C_GetMechanismInfo (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo) {
  print_log(VERBOSE, "C_GetMechanismInfo: slot = %d", slotID);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken (CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_ULONG usPinLen, CK_CHAR_PTR pLabel) {
  print_log(VERBOSE, "C_InitToken: slot = %d", slotID);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG usPinLen) {
  print_log(VERBOSE, "C_InitPIN: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin, CK_ULONG usOldLen, CK_CHAR_PTR pNewPin, CK_ULONG usNewLen) {
  print_log(VERBOSE, "C_SetPIN: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseAllSessions (CK_SLOT_ID slotID) {
  print_log(VERBOSE, "C_CloseAllSessions: slot = %d", slotID);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen) {
  print_log(VERBOSE, "C_GetOperationState: session = %x, len = %d", hSession, pulOperationStateLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey) {
  print_log(VERBOSE, "C_SetOperationState: session = %x, len = %d, enc_key = %x, auth_key = %x", hSession, ulOperationStateLen, hEncryptionKey, hAuthenticationKey);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  print_log(VERBOSE, "C_Login: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
  print_log(VERBOSE, "C_Logout: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject) {
  print_log(VERBOSE, "C_CreateObject: session = %x, count = %d", hSession, ulCount);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject) {
  print_log(VERBOSE, "C_CopyObject: session = %x, object = %x, count = %d", hSession, hObject, ulCount);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  print_log(VERBOSE, "C_DestroyObject: session = %x, object = %x", hSession, hObject);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize) {
  print_log(VERBOSE, "C_GetObjectSize: session = %x, object = %x", hSession, hObject);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject) {
  print_log(VERBOSE, "C_EncryptInit: session = %x, object = %x", hSession, hObject);
  pObject object = (pObject) hObject;
  get_session(hSession)->handle = object->tpm_handle;

  switch(pMechanism->mechanism) {
    case CKM_RSA_X_509:
      get_session(hSession)->mechanism = CKM_RSA_X_509;
      break;
    case CKM_RSA_PKCS:
      get_session(hSession)->mechanism = CKM_RSA_PKCS;
      break;
    default:
      return CKR_MECHANISM_INVALID;
  }

  return CKR_OK;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
  print_log(VERBOSE, "C_Encrypt: session = %x, len = %x", hSession, ulDataLen);
  TPM2B_PUBLIC_KEY_RSA message = { .size = TPM2_MAX_RSA_KEY_BYTES };
  struct session* session = get_session(hSession);

  TPM2_RC ret = tpm_rsa_encrypt(pk11_token.sapi_context, session->handle, pData, ulDataLen, &message);
  
  retmem(pEncryptedData, (size_t*)pulEncryptedDataLen, message.buffer, message.size);

  return ret == TPM2_RC_SUCCESS ? CKR_OK : CKR_GENERAL_ERROR;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
  print_log(VERBOSE, "C_EncryptUpdate: session = %x, len = %x", hSession, ulDataLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
  print_log(VERBOSE, "C_EncryptFinal: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen) {
  print_log(VERBOSE, "C_DecryptUpdate: session = %x, len = %x", hSession, ulEncryptedDataLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen) {
  print_log(VERBOSE, "C_DecryptFinal: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism) {
  print_log(VERBOSE, "C_DigestInit: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  print_log(VERBOSE, "C_Digest: session = %x, len = %x", hSession, ulDataLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  print_log(VERBOSE, "C_DigestUpdate: session = %x, len = %x", hSession, ulPartLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
  print_log(VERBOSE, "C_DigestKey: session = %x, object = %x", hSession, hObject);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
  print_log(VERBOSE, "C_DigestFinal: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  print_log(VERBOSE, "C_SignUpdate: session = %x, len = %x", hSession, ulPartLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  print_log(VERBOSE, "C_SignFinal: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  print_log(VERBOSE, "C_SignRecoverInit: session = %x, key = %x", hSession, hKey);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
  print_log(VERBOSE, "C_SignRecover: session = %x, len = %d", hSession, ulDataLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  print_log(VERBOSE, "C_VerifyInit: session = %x, key = %x", hSession, hKey);
  pObject object = (pObject) hKey;
  get_session(hSession)->handle = object->tpm_handle;
  get_session(hSession)->current_object = object;

  return CKR_OK;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  print_log(VERBOSE, "C_Verify: session = %x, len = %d", hSession, ulDataLen);
  struct session* session = get_session(hSession);
  TPMT_SIGNATURE signature = {0};
  TPM2_RC rc;
  size_t offset = 0;
        
  rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(pSignature, ulSignatureLen, &offset, &signature); //jturnsek: should be in tpm file
  if (rc != TPM2_RC_SUCCESS) {
      return CKR_GENERAL_ERROR;
  }

  rc = tpm_verify(pk11_token.sapi_context, session->handle, &signature, pData, ulDataLen);

  return rc == TPM2_RC_SUCCESS ? CKR_OK : CKR_SIGNATURE_INVALID;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
  print_log(VERBOSE, "C_VerifyUpdate: session = %x, len = %d", hSession, ulPartLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
  print_log(VERBOSE, "C_VerifyFinal: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  print_log(VERBOSE, "C_VerifyRecoverInit: session = %x, key = %x", hSession, hKey);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen) {
  print_log(VERBOSE, "C_VerifyRecover: session = %x, len = %d", hSession, ulSignatureLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", hSession, ulPartLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", hSession, ulPartLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", hSession, ulPartLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen) {
  print_log(VERBOSE, "C_DigestEncryptUpdate: session = %x, len = %d", hSession, ulEncryptedPartLen);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  print_log(VERBOSE, "C_GenerateKey: session = %x, count = %d", hSession, ulCount);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
  print_log(VERBOSE, "C_GenerateKeyPair: session = %x, public_count = %d, private_count = %d", hSession, ulPublicKeyAttributeCount, ulPrivateKeyAttributeCount);
  struct session* session = get_session(hSession);
  TPM2_ALG_ID algorithm_type;

  if (pMechanism == NULL_PTR) return CKR_ARGUMENTS_BAD;
  if (phPublicKey == NULL_PTR) return CKR_ARGUMENTS_BAD;
  if (phPrivateKey == NULL_PTR) return CKR_ARGUMENTS_BAD;

  *phPublicKey = CK_INVALID_HANDLE;
  *phPrivateKey = CK_INVALID_HANDLE;

  // Check the mechanism, only accept RSA, EC key pair generation.
  CK_KEY_TYPE keyType;
  switch (pMechanism->mechanism) {
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
  extractObjectInformation(pPublicKeyTemplate, ulPublicKeyAttributeCount, &publicKeyClass, &keyType, &dummy, &ispublicKeyToken, &ispublicKeyPrivate, isPublicKeyImplicit);

  // Report errors caused by accidental template mix-ups in the application using this lib.
  if (publicKeyClass != CKO_PUBLIC_KEY)
    return CKR_ATTRIBUTE_VALUE_INVALID;
  if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
    return CKR_TEMPLATE_INCONSISTENT;
  if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
    return CKR_TEMPLATE_INCONSISTENT;

  // Extract information from the private key template that is needed to create the object.
  CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
  CK_BBOOL isprivateKeyToken = CK_FALSE;
  CK_BBOOL isprivateKeyPrivate = CK_TRUE;
  bool isPrivateKeyImplicit = true;
  extractObjectInformation(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, &privateKeyClass, &keyType, &dummy, &isprivateKeyToken, &isprivateKeyPrivate, isPrivateKeyImplicit);

  // Report errors caused by accidental template mix-ups in the application using this lib.
  if (privateKeyClass != CKO_PRIVATE_KEY)
    return CKR_ATTRIBUTE_VALUE_INVALID;
  if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN && keyType != CKK_RSA)
    return CKR_TEMPLATE_INCONSISTENT;
  if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN && keyType != CKK_EC)
    return CKR_TEMPLATE_INCONSISTENT;

  pObject object = object_generate_pair(pk11_token.sapi_context, algorithm_type);
  if (object == NULL) {
    return CKR_FUNCTION_FAILED; 
  }
  //Add object to list
  object_add(pk11_token.objects, object);
  *phPublicKey = (CK_OBJECT_HANDLE)object;
  object_add(pk11_token.objects, object->opposite);
  *phPrivateKey = (CK_OBJECT_HANDLE)object->opposite;

  print_log(VERBOSE, "C_GenerateKeyPair: Finished OK");
  return CKR_OK;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,  CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  print_log(VERBOSE, "C_WrapKey: session = %x, wrapping_key = %x, key = %x", hSession, hWrappingKey, hKey);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  print_log(VERBOSE, "C_UnwrapKey: session = %x, unwrapping_key = %x, key = %x, count = %d", hSession, hUnwrappingKey, phKey, ulCount);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey) {
  print_log(VERBOSE, "C_WrapKey: session = %x, base_key = %x, count = %d", hSession, hBaseKey, ulCount);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
  // jturnsek: N/A
  print_log(VERBOSE, "C_SeedRandom: session = %x, len = %d", hSession, ulSeedLen);
  return CKR_OK;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
  print_log(VERBOSE, "C_GenerateRandom: session = %x, len = %d", hSession, ulRandomLen);
  struct session* session = get_session(hSession);
  TPM2B_DIGEST random_bytes;

  TPM2_RC rval = Tss2_Sys_GetRandom(pk11_token.sapi_context, NULL, ulRandomLen, &random_bytes, NULL);
  if (rval != TPM2_RC_SUCCESS) {
    return CKR_GENERAL_ERROR;
  }

  retmem(pRandomData, (size_t*)&ulRandomLen, random_bytes.buffer, random_bytes.size);

  return CKR_OK;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) {
  print_log(VERBOSE, "C_GetFunctionStatus: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) {
  print_log(VERBOSE, "C_CancelFunction: session = %x", hSession);
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved) {
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

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  print_log(VERBOSE, "C_GetFunctionList");
  if (ppFunctionList == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  *ppFunctionList = &function_list;
  return CKR_OK;
}
