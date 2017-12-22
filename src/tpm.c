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

#include "tpm.h"

#include <endian.h>

const unsigned char oid_sha1[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
const unsigned char oid_sha256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

TPM2_RC tpm_readpublic(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public, TPM2B_NAME *name) {
  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  TPM2B_NAME qualified_name = { .size = sizeof(TPMU_NAME) };

  return Tss2_Sys_ReadPublic(context, handle, 0, public, name, &qualified_name, &sessions_data_out);
}

TPM2_RC tpm_rsa_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hashLength, TPMT_SIGNATURE *signature) {
  TSS2L_SYS_AUTH_COMMAND sessions_data = {
    .count = 1,
    .auths[0] = { .sessionHandle = TPM2_RS_PW },
  };

  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  TPMT_TK_HASHCHECK validation = {0};
  validation.tag = TPM2_ST_HASHCHECK;
  validation.hierarchy = TPM2_RH_NULL;

  TPMT_SIG_SCHEME scheme;
  scheme.scheme = TPM2_ALG_RSASSA;

  int digestSize;
  if (memcmp(hash, oid_sha1, sizeof(oid_sha1)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA1;
    digestSize = TPM2_SHA1_DIGEST_SIZE;
  } else if (memcmp(hash, oid_sha256, sizeof(oid_sha256)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
    digestSize = TPM2_SHA256_DIGEST_SIZE;
  } else
    return TPM2_RC_FAILURE;

  TPM2B_DIGEST digest = { .size = digestSize };
  // Remove OID from hash if provided
  memcpy(digest.buffer, hash - digestSize + hash_length, hash_length);

  return Tss2_Sys_Sign(context, handle, &sessions_data, &digest, &scheme, &validation, signature, &sessions_data_out);
}

TPM2_RC tpm_ecc_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hashLength, TPMT_SIGNATURE *signature) {
  TSS2L_SYS_AUTH_COMMAND sessions_data = {
    .count = 1,
    .auths[0] = { .sessionHandle = TPM2_RS_PW },
  };

  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  TPMT_TK_HASHCHECK validation = {0};
  validation.tag = TPM2_ST_HASHCHECK;
  validation.hierarchy = TPM2_RH_NULL;

  TPMT_SIG_SCHEME scheme;
  scheme.scheme = TPM_ALG_ECDSA;

  int digestSize;
  if (memcmp(hash, oid_sha1, sizeof(oid_sha1)) == 0) {
    scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA1;
    digestSize = TPM2_SHA1_DIGEST_SIZE;
  } else if (memcmp(hash, oid_sha256, sizeof(oid_sha256)) == 0) {
    scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    digestSize = TPM2_SHA256_DIGEST_SIZE;
  } else
    return TPM2_RC_FAILURE;

  TPM2B_DIGEST digest = { .size = digestSize };
  // Remove OID from hash if provided
  memcpy(digest.buffer, hash - digestSize + hash_length, hash_length);

  return Tss2_Sys_Sign(context, handle, &sessions_data, &digest, &scheme, &validation, signature, &sessions_data_out);
}

TPM2_RC tpm_verify(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPMT_SIGNATURE *signature, unsigned char *hash, unsigned long hashLength) {
  TPM2B_DIGEST digest  = { .size = hashLength };
  TPMT_TK_VERIFIED validation;

  TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;

  memcpy(digest.buffer, hash, hashLength);

  return Tss2_Sys_VerifySignature(context, handle, NULL, &digest, signature, &validation, &sessionsDataOut);
}

TPM2_RC tpm_rsa_decrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *cipherText, unsigned long cipherLength, TPM2B_PUBLIC_KEY_RSA *message) {
  TSS2L_SYS_AUTH_COMMAND sessions_data = {
    .count = 1,
    .auths[0] = { .sessionHandle = TPM2_RS_PW },
  };

  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  TPM2B_DATA label = {0};

  TPMT_RSA_DECRYPT scheme;
  scheme.scheme = TPM2_ALG_RSAES;

  TPM2B_PUBLIC_KEY_RSA cipher = { .size = cipher_length };
  memcpy(cipher.buffer, cipher_text, cipher_length);

  return Tss2_Sys_RSA_Decrypt(context, handle, &sessions_data, &cipher, &scheme, &label, message, &sessions_data_out);
}

TPM2_RC tpm_rsa_encrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *data, unsigned long dataLength, TPM2B_PUBLIC_KEY_RSA *message) {
  TPMT_RSA_DECRYPT scheme;
  TPM2B_DATA label;

  TPM2B_PUBLIC_KEY_RSA in_data =  { .size = dataLength };

  TSS2L_SYS_AUTH_RESPONSE out_sessions_data;

  scheme.scheme = TPM_ALG_RSAES;
  label.size = 0;

  memcpy(in_data.buffer, data, dataLength);

  return Tss2_Sys_RSA_Encrypt(context, handle, NULL, &in_data, &scheme, &label, &message, &out_sessions_data);
}

TPM2_RC tpm_list(TSS2_SYS_CONTEXT *context, TPMS_CAPABILITY_DATA* capabilityData) {
  TPMI_YES_NO more_data;

  return Tss2_Sys_GetCapability(context, 0, TPM2_CAP_HANDLES, htobe32(TPM2_HT_PERSISTENT), TPM2_PT_TPM2_HR_PERSISTENT, &more_data, capability_data, 0);
}
