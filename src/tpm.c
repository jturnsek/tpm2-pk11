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

#include "tpm.h"

#include <endian.h>

const unsigned char oid_sha1[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
const unsigned char oid_sha256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

TPM_RC tpm_readpublic(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public, TPM2B_NAME *name) {
  TPMS_AUTH_RESPONSE sessionDataOut;
  TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = {&sessionDataOut};

  TSS2_SYS_RSP_AUTHS sessionsDataOut;
  sessionsDataOut.rspAuths = &sessionDataOutArray[0];
  sessionsDataOut.rspAuthsCount = 1;

  TPM2B_NAME qualifiedName = { .t.size = sizeof(TPMU_NAME) };

  return Tss2_Sys_ReadPublic(context, handle, 0, public, name, &qualifiedName, &sessionsDataOut);
}

TPM_RC tpm_rsa_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hashLength, TPMT_SIGNATURE *signature) {
  TPMS_AUTH_COMMAND sessionData = {0};
  sessionData.sessionHandle = TPM_RS_PW;

  TPMS_AUTH_RESPONSE sessionDataOut;
  TPMS_AUTH_COMMAND *sessionDataArray[1] = {&sessionData};
  TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = {&sessionDataOut};

  TSS2_SYS_CMD_AUTHS sessionsData;
  sessionsData.cmdAuths = &sessionDataArray[0];
  sessionsData.cmdAuthsCount = 1;

  TSS2_SYS_RSP_AUTHS sessionsDataOut;
  sessionsDataOut.rspAuths = &sessionDataOutArray[0];
  sessionsDataOut.rspAuthsCount = 1;

  TPMT_TK_HASHCHECK validation = {0};
  validation.tag = TPM_ST_HASHCHECK;
  validation.hierarchy = TPM_RH_NULL;

  TPMT_SIG_SCHEME scheme;
  scheme.scheme = TPM_ALG_RSASSA;

  int digestSize;
  if (memcmp(hash, oid_sha1, sizeof(oid_sha1)) == 0) {
    scheme.details.rsassa.hashAlg = TPM_ALG_SHA1;
    digestSize = SHA1_DIGEST_SIZE;
  } else if (memcmp(hash, oid_sha256, sizeof(oid_sha256)) == 0) {
    scheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    digestSize = SHA256_DIGEST_SIZE;
  } else
    return TPM_RC_FAILURE;

  TPM2B_DIGEST digest = { .t.size = digestSize };
  // Remove OID from hash if provided
  memcpy(digest.t.buffer, hash - digestSize + hashLength, hashLength);

  return Tss2_Sys_Sign(context, handle, &sessionsData, &digest, &scheme, &validation, signature, &sessionsDataOut);
}

TPM_RC tpm_ecc_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hashLength, TPMT_SIGNATURE *signature) {
  TPMS_AUTH_COMMAND sessionData = {0};
  sessionData.sessionHandle = TPM_RS_PW;

  TPMS_AUTH_RESPONSE sessionDataOut;
  TPMS_AUTH_COMMAND *sessionDataArray[1] = {&sessionData};
  TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = {&sessionDataOut};

  TSS2_SYS_CMD_AUTHS sessionsData;
  sessionsData.cmdAuths = &sessionDataArray[0];
  sessionsData.cmdAuthsCount = 1;

  TSS2_SYS_RSP_AUTHS sessionsDataOut;
  sessionsDataOut.rspAuths = &sessionDataOutArray[0];
  sessionsDataOut.rspAuthsCount = 1;

  TPMT_TK_HASHCHECK validation = {0};
  validation.tag = TPM_ST_HASHCHECK;
  validation.hierarchy = TPM_RH_NULL;

  TPMT_SIG_SCHEME scheme;
  scheme.scheme = TPM2_ALG_ECDSA;

  int digestSize;
  if (memcmp(hash, oid_sha1, sizeof(oid_sha1)) == 0) {
    scheme.details.ecdsa.hashAlg = TPM_ALG_SHA1;
    digestSize = SHA1_DIGEST_SIZE;
  } else if (memcmp(hash, oid_sha256, sizeof(oid_sha256)) == 0) {
    scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    digestSize = SHA256_DIGEST_SIZE;
  } else
    return TPM_RC_FAILURE;

  TPM2B_DIGEST digest = { .t.size = digestSize };
  // Remove OID from hash if provided
  memcpy(digest.t.buffer, hash - digestSize + hashLength, hashLength);

  return Tss2_Sys_Sign(context, handle, &sessionsData, &digest, &scheme, &validation, signature, &sessionsDataOut);
}

TPM_RC tpm_rsa_decrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *cipherText, unsigned long cipherLength, TPM2B_PUBLIC_KEY_RSA *message) {
  TPMS_AUTH_COMMAND sessionData = {0};
  sessionData.sessionHandle = TPM_RS_PW;

  TPMS_AUTH_RESPONSE sessionDataOut;
  TPMS_AUTH_COMMAND *sessionDataArray[1] = {&sessionData};
  TPMS_AUTH_RESPONSE *sessionDataOutArray[1] = {&sessionDataOut};

  TSS2_SYS_CMD_AUTHS sessionsData;
  sessionsData.cmdAuths = &sessionDataArray[0];
  sessionsData.cmdAuthsCount = 1;
  
  TSS2_SYS_RSP_AUTHS sessionsDataOut;
  sessionsDataOut.rspAuths = &sessionDataOutArray[0];
  sessionsDataOut.rspAuthsCount = 1;

  TPM2B_DATA label = {0};

  TPMT_RSA_DECRYPT scheme;
  scheme.scheme = TPM_ALG_RSAES;

  TPM2B_PUBLIC_KEY_RSA cipher = { .t.size = cipherLength };
  memcpy(cipher.t.buffer, cipherText, cipherLength);

  return Tss2_Sys_RSA_Decrypt(context, handle, &sessionsData, &cipher, &scheme, &label, message, &sessionsDataOut);
}

TPM_RC tpm_list(TSS2_SYS_CONTEXT *context, TPMS_CAPABILITY_DATA* capabilityData) {
  TPMI_YES_NO moreData;

  return Tss2_Sys_GetCapability(context, 0, TPM_CAP_HANDLES, htobe32(TPM_HT_PERSISTENT), TPM_PT_HR_PERSISTENT, &moreData, capabilityData, 0);
}
