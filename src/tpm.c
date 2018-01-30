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

#include "tpm.h"

#include <endian.h>

#define TPM2_RC_MASK 0xfff
#define TPM2_RC_GET(code) (code & TPM2_RC_MASK)

/*
 * This macro is useful as a wrapper around SAPI functions to automatically
 * retry function calls when the RC is TPM2_RC_RETRY.
 */
#define TSS2_RETRY_EXP(expression)                         \
    ({                                                     \
        TSS2_RC __result = 0;                              \
        do {                                               \
            __result = (expression);                       \
        } while (TPM2_RC_GET(__result) == TPM2_RC_RETRY); \
        __result;                                          \
    })


const unsigned char oid_sha1[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
const unsigned char oid_sha256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
const unsigned char oid_sha384[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,0x00, 0x04, 0x30};
const unsigned char oid_sha512[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,0x00, 0x04, 0x40};

#if 0
typedef struct generate_key_context generate_key_context;
struct generate_key_context {
  struct {
    TPM2_HANDLE ek;
    TPM2_HANDLE ak;
  } persistent_handle;
  struct {
    TPM2B_AUTH endorse;
    TPM2B_AUTH ak;
    TPM2B_AUTH owner;
  } passwords;
  char *output_file;
  char *akname_file;
  TPM2_ALG_ID algorithm_type;
  TPM2_ALG_ID digest_alg;
  TPM2_ALG_ID sign_alg;
};

static generate_key_context ctx = {
  .algorithm_type = TPM2_ALG_RSA,
  .digest_alg = TPM2_ALG_SHA256,
  .sign_alg = TPM2_ALG_NULL,
  .passwords = {
    .endorse = TPM2B_EMPTY_INIT,
    .ak      = TPM2B_EMPTY_INIT,
    .owner   = TPM2B_EMPTY_INIT,
  },
};


static bool set_rsa_signing_algorithm(uint32_t sign_alg, uint32_t digest_alg, TPM2B_PUBLIC *in_public) 
{
  if (sign_alg == TPM2_ALG_NULL) {
    sign_alg = TPM2_ALG_RSASSA;
  }

  in_public->publicArea.parameters.rsaDetail.scheme.scheme = sign_alg;
  switch (sign_alg) {
  case TPM2_ALG_RSASSA :
  case TPM2_ALG_RSAPSS :
    in_public->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = digest_alg;
    break;
  default:
    return false;
  }

  return true;
}

static bool set_ecc_signing_algorithm(uint32_t sign_alg, uint32_t digest_alg, TPM2B_PUBLIC *in_public)
{
  if (sign_alg == TPM2_ALG_NULL) {
    sign_alg = TPM2_ALG_ECDSA;
  }

  in_public->publicArea.parameters.eccDetail.scheme.scheme = sign_alg;
  switch (sign_alg) {
  case TPM2_ALG_ECDSA :
    in_public->publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg = digest_alg;
    break;
  default:
    return false;
  }

  return true;
}

static bool set_key_algorithm(TPM2B_PUBLIC *in_public)
{
  in_public->publicArea.nameAlg = TPM2_ALG_SHA256;
  // First clear attributes bit field.
  in_public->publicArea.objectAttributes = 0;
  in_public->publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
  in_public->publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
  in_public->publicArea.objectAttributes |= TPMA_OBJECT_SIGN;
  in_public->publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
  in_public->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
  in_public->publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
  in_public->publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
  in_public->publicArea.authPolicy.size = 0;

  in_public->publicArea.type = ctx.algorithm_type;

  switch (ctx.algorithm_type) {
  case TPM2_ALG_RSA:
    in_public->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    in_public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
    in_public->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_NULL;
    in_public->publicArea.parameters.rsaDetail.keyBits = 2048;
    in_public->publicArea.parameters.rsaDetail.exponent = 0;
    in_public->publicArea.unique.rsa.size = 0;
    return set_rsa_signing_algorithm(ctx.sign_alg, ctx.digest_alg, in_public);
  case TPM2_ALG_ECC:
    in_public->publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    in_public->publicArea.parameters.eccDetail.symmetric.mode.sym = TPM2_ALG_NULL;
    in_public->publicArea.parameters.eccDetail.symmetric.keyBits.sym = 0;
    in_public->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    in_public->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    in_public->publicArea.unique.ecc.x.size = 0;
    in_public->publicArea.unique.ecc.y.size = 0;
    return set_ecc_signing_algorithm(ctx.sign_alg, ctx.digest_alg, in_public);
  default:
    return false;
  }

  return true;
}

static bool generate_key(TSS2_SYS_CONTEXT *sapi_context)
{
  TPML_PCR_SELECTION creation_pcr;
  TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
  TSS2L_SYS_AUTH_COMMAND sessions_data = {
    1, 
    {
      {
        .sessionHandle = TPM2_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = 0,
      }
    }
  };

  TPM2B_DATA outsideInfo = TPM2B_EMPTY_INIT;
  TPM2B_PUBLIC out_public = TPM2B_EMPTY_INIT;
  TPMT_TK_CREATION creation_ticket = TPMT_TK_CREATION_EMPTY_INIT;
  TPM2B_CREATION_DATA creation_data = TPM2B_EMPTY_INIT;

  TPM2B_SENSITIVE_CREATE inSensitive = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);

  TPM2B_PUBLIC inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);

  TPM2B_NAME name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

  TPM2B_PRIVATE out_private = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

  TPM2B_DIGEST creation_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

  TPM2_HANDLE handle_ek = ctx.persistent_handle.ek;

  inSensitive.sensitive.data.size = 0;
  inSensitive.size = inSensitive.sensitive.userAuth.size + 2;
  creation_pcr.count = 0;

  memcpy(&inSensitive.sensitive.userAuth, &ctx.passwords.ak, sizeof(ctx.passwords.ak));

  bool result = set_key_algorithm(&inPublic);
  if (!result) {
    return false;
  }

  memcpy(&sessions_data.auths[0].hmac, &ctx.passwords.endorse, sizeof(ctx.passwords.endorse));

  tpm2_session_data *data = tpm2_session_data_new(TPM2_SE_POLICY);
  if (!data) {
    return false;
  }

  tpm2_session *session = tpm2_session_new(sapi_context, data);
  if (!session) {
    return false;
  }

  TPMI_SH_AUTH_SESSION handle = tpm2_session_get_session_handle(session);
  tpm2_session_free(&session);

  TPM2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(
    sapi_context,
    TPM2_RH_ENDORSEMENT,
    handle,
    &sessions_data,
    NULL,
    NULL,
    NULL,
    0,
    NULL,
    NULL,
    NULL));

  if (rval != TPM2_RC_SUCCESS) {
    return false;
  }

  sessions_data.auths[0].sessionHandle = handle;
  sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
  sessions_data.auths[0].hmac.size = 0;

  rval = TSS2_RETRY_EXP(Tss2_Sys_Create(sapi_context, handle_ek, &sessions_data,
          &inSensitive, &inPublic, &outsideInfo, &creation_pcr, &out_private,
          &out_public, &creation_data, &creation_hash, &creation_ticket,
          &sessions_data_out));
  if (rval != TPM2_RC_SUCCESS) {
    return false;
  }
  
  // Need to flush the session here.
  rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
  if (rval != TPM2_RC_SUCCESS) {
    return false;
  }
  // And remove the session from sessions table.
  sessions_data.auths[0].sessionHandle = TPM2_RS_PW;
  sessions_data.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;
  sessions_data.auths[0].hmac.size = 0;

  memcpy(&sessions_data.auths[0].hmac, &ctx.passwords.endorse, sizeof(ctx.passwords.endorse));

  data = tpm2_session_data_new(TPM2_SE_POLICY);
  if (!data) {
    return false;
  }

  session = tpm2_session_new(sapi_context, data);
  if (!session) {
    return false;
  }

  handle = tpm2_session_get_session_handle(session);
  tpm2_session_free(&session);

  rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(sapi_context, TPM2_RH_ENDORSEMENT,
          handle, &sessions_data, 0, 0, 0, 0, 0, 0, 0));
  if (rval != TPM2_RC_SUCCESS) {
    return false;
  }

  sessions_data.auths[0].sessionHandle = handle;
  sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
  sessions_data.auths[0].hmac.size = 0;

  TPM2_HANDLE loaded_sha1_key_handle;
  rval = TSS2_RETRY_EXP(Tss2_Sys_Load(sapi_context, handle_ek, &sessions_data, &out_private,
          &out_public, &loaded_sha1_key_handle, &name, &sessions_data_out));
  if (rval != TPM2_RC_SUCCESS) {
    return false;
  }

  /* Output in YAML format */
  tpm2_tool_output("loaded-key:\n");
  tpm2_tool_output("  handle: %8.8x\n  name: ", loaded_sha1_key_handle);
  tpm2_util_print_tpm2b((TPM2B *)&name);
  tpm2_tool_output("\n");

  // write name to ak.name file
  if (ctx.akname_file) {
    result = files_save_bytes_to_file(ctx.akname_file, &name.name[0], name.size);
    if (!result) {
      return false;
    }
  }

  // Need to flush the session here.
  rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
  if (rval != TPM2_RC_SUCCESS) {
    return false;
  }
  sessions_data.auths[0].sessionHandle = TPM2_RS_PW;
  sessions_data.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;
  sessions_data.auths[0].hmac.size = 0;

  // use the owner auth here.
  memcpy(&sessions_data.auths[0].hmac, &ctx.passwords.owner, sizeof(ctx.passwords.owner));

  rval = TSS2_RETRY_EXP(Tss2_Sys_EvictControl(sapi_context, TPM2_RH_OWNER, loaded_sha1_key_handle,
          &sessions_data, ctx.persistent_handle.ak, &sessions_data_out));
  if (rval != TPM2_RC_SUCCESS) {
    return false;
  }
  
  rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, loaded_sha1_key_handle));
  if (rval != TPM2_RC_SUCCESS) {
    return false;
  }

  return tpm2_convert_pubkey(&out_public, pubkey_format_tss, ctx.output_file);
}
#endif


TPM2_RC tpm_readpublic(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public, TPM2B_NAME *name) {
  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  TPM2B_NAME qualified_name = { .size = sizeof(TPMU_NAME) };

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_ReadPublic(context, handle, 0, public, name, &qualified_name, &sessions_data_out));

  return rval;
}

TPM2_RC tpm_rsa_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature) {
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
  if (sizeof(oid_sha1) < hash_length && memcmp(hash, oid_sha1, sizeof(oid_sha1)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA1;
    digestSize = TPM2_SHA1_DIGEST_SIZE;
  } else if (sizeof(oid_sha256) < hash_length && memcmp(hash, oid_sha256, sizeof(oid_sha256)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
    digestSize = TPM2_SHA256_DIGEST_SIZE;
  } else if (sizeof(oid_sha384) < hash_length && memcmp(hash, oid_sha384, sizeof(oid_sha384)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA384;
    digestSize = TPM2_SHA384_DIGEST_SIZE;
  } else if (sizeof(oid_sha512) < hash_length && memcmp(hash, oid_sha512, sizeof(oid_sha512)) == 0) {
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA512;
    digestSize = TPM2_SHA512_DIGEST_SIZE;
  } else
    return TPM2_RC_FAILURE;

  TPM2B_DIGEST digest = { .size = digestSize };
  // Remove OID from hash if provided
  memcpy(digest.buffer, hash - digestSize + hash_length, hash_length);

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Sign(context, handle, &sessions_data, &digest, &scheme, &validation, signature, &sessions_data_out));

  return rval;
}

TPM2_RC tpm_ecc_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature) {
  TSS2L_SYS_AUTH_COMMAND sessions_data = {
    .count = 1,
    .auths[0] = { .sessionHandle = TPM2_RS_PW },
  };

  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  TPMT_TK_HASHCHECK validation = {0};
  validation.tag = TPM2_ST_HASHCHECK;
  validation.hierarchy = TPM2_RH_NULL;

  TPMT_SIG_SCHEME scheme;
  scheme.scheme = TPM2_ALG_ECDSA;

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

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Sign(context, handle, &sessions_data, &digest, &scheme, &validation, signature, &sessions_data_out));

  return rval;
}

TPM2_RC tpm_verify(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPMT_SIGNATURE *signature, unsigned char *hash, unsigned long hash_length) {
  TPM2B_DIGEST digest  = { .size = hash_length };
  TPMT_TK_VERIFIED validation;

  TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

  memcpy(digest.buffer, hash, hash_length);

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_VerifySignature(context, handle, NULL, &digest, signature, &validation, &sessions_data_out));

  return rval;
}

TPM2_RC tpm_rsa_decrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *cipher_text, unsigned long cipher_length, TPM2B_PUBLIC_KEY_RSA *message) {
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

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_RSA_Decrypt(context, handle, &sessions_data, &cipher, &scheme, &label, message, &sessions_data_out));

  return rval;
}

TPM2_RC tpm_rsa_encrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *data, unsigned long data_length, TPM2B_PUBLIC_KEY_RSA *message) {
  TPMT_RSA_DECRYPT scheme;
  TPM2B_DATA label;

  TPM2B_PUBLIC_KEY_RSA in_data =  { .size = data_length };

  TSS2L_SYS_AUTH_RESPONSE out_sessions_data;

  scheme.scheme = TPM2_ALG_RSAES;
  label.size = 0;

  memcpy(in_data.buffer, data, data_length);

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_RSA_Encrypt(context, handle, NULL, &in_data, &scheme, &label, message, &out_sessions_data));

  return rval;
}

TPM2_RC tpm_list(TSS2_SYS_CONTEXT *context, TPMS_CAPABILITY_DATA* capability_data) {
  TPMI_YES_NO more_data;

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_GetCapability(context, 0, TPM2_CAP_HANDLES, htobe32(TPM2_HT_PERSISTENT), TPM2_PT_TPM2_HR_PERSISTENT, &more_data, capability_data, 0));

  return rval;
}
