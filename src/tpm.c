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

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <endian.h>

#define TPM2_RC_MASK 0xfff
#define TPM2_RC_GET(code) (code & TPM2_RC_MASK)

#define UNUSED(x) (void)x

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))

#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }
#define TPM2B_INIT(xsize) { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)
#define TPM2B_SENSITIVE_CREATE_EMPTY_INIT { \
           .sensitive = { \
                .data = {   \
                    .size = 0 \
                }, \
                .userAuth = {   \
                    .size = 0 \
                } \
            } \
    }

#define TPMS_AUTH_COMMAND_INIT(session_handle) { \
        .sessionHandle = session_handle,\
      .nonce = TPM2B_EMPTY_INIT, \
      .sessionAttributes = 0, \
      .hmac = TPM2B_EMPTY_INIT \
    }

#define TPMS_AUTH_COMMAND_EMPTY_INIT TPMS_AUTH_COMMAND_INIT(0)

#define TPMT_TK_CREATION_EMPTY_INIT { \
        .tag = 0, \
    .hierarchy = 0, \
    .digest = TPM2B_EMPTY_INIT \
    }

#define TPML_PCR_SELECTION_EMPTY_INIT { \
        .count = 0, \
    } //ignore pcrSelections since count is 0.

#define TPMS_CAPABILITY_DATA_EMPTY_INIT { \
        .capability = 0, \
    } // ignore data since capability is 0.

#define TPMT_TK_HASHCHECK_EMPTY_INIT { \
    .tag = 0, \
    .hierarchy = 0, \
    .digest = TPM2B_EMPTY_INIT \
    }

#define TSS2L_SYS_AUTH_COMMAND_INIT(cnt, array) { \
        .count = cnt, \
        .auths = array, \
    }

/*
 * This macro is useful as a wrapper around SAPI functions to automatically
 * retry function calls when the RC is TPM2_RC_RETRY.
 */
#define TSS2_RETRY_EXP(expression)                         \
    ({                                                     \
        TSS2_RC __result = 0;                              \
        do {                                               \
            __result = (expression);                       \
        } while (TPM2_RC_GET(__result) == TPM2_RC_RETRY);  \
        __result;                                          \
    })




const unsigned char oid_sha1[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
const unsigned char oid_sha256[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
const unsigned char oid_sha384[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,0x00, 0x04, 0x30};
const unsigned char oid_sha512[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,0x00, 0x04, 0x40};

typedef struct tpm2_session_data {
  TPMI_DH_OBJECT key;
  TPMI_DH_ENTITY bind;
  TPM2B_ENCRYPTED_SECRET encrypted_salt;
  TPM2_SE session_type;
  TPMT_SYM_DEF symmetric;
  TPMI_ALG_HASH authHash;
  TPM2B_NONCE nonce_caller;
} tpm2_session_data;

typedef struct tpm2_session {
  tpm2_session_data* input;
  struct {
    TPMI_SH_AUTH_SESSION session_handle;
    TPM2B_NONCE nonceTPM;
  } output;
  struct {
    TPM2B_NONCE nonceNewer;
  } internal;
} tpm2_session;

uint16_t tpm2_alg_util_get_hash_size(TPMI_ALG_HASH id)
{
    switch (id) {
    case TPM2_ALG_SHA1 :
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256 :
        return TPM2_SHA256_DIGEST_SIZE;
        /* no default */
    }

    return 0;
}

tpm2_session_data *tpm2_session_data_new(TPM2_SE type)
{
  tpm2_session_data * d = calloc(1, sizeof(tpm2_session_data));
  if (d) {
    d->symmetric.algorithm = TPM2_ALG_NULL;
    d->key = TPM2_RH_NULL;
    d->bind = TPM2_RH_NULL;
    d->session_type = type;
    d->authHash = TPM2_ALG_SHA1; //TPM2_ALG_SHA256;
    d->nonce_caller.size = tpm2_alg_util_get_hash_size(TPM2_ALG_SHA1);
  }
  return d;
}

TPMI_SH_AUTH_SESSION tpm2_session_get_session_handle(tpm2_session *session) {
    return session->output.session_handle;
}

//
// This is a wrapper function around the TPM2_StartAuthSession command.
// It performs the command, calculates the session key, and updates a
// SESSION structure.
//
static bool start_auth_session(TSS2_SYS_CONTEXT *sapi_context, tpm2_session *session)
{
  tpm2_session_data *d = session->input;

  TSS2_RC rval = Tss2_Sys_StartAuthSession(sapi_context, d->key, d->bind,
                  NULL, &session->input->nonce_caller, &d->encrypted_salt,
                  d->session_type, &d->symmetric, d->authHash,
                  &session->output.session_handle, &session->internal.nonceNewer,
                  NULL);

  return rval == TPM2_RC_SUCCESS;
}

void tpm2_session_free(tpm2_session **session)
{
  tpm2_session *s = *session;
  free(s->input);
  free(s);
  *session = NULL;
}

tpm2_session *tpm2_session_new(TSS2_SYS_CONTEXT *sapi_context, tpm2_session_data *data)
{
  tpm2_session *session = calloc(1, sizeof(tpm2_session));
  if (!session) {
    free(data);
    return NULL;
  }

  session->input = data;

  session->internal.nonceNewer.size = session->input->nonce_caller.size;

  bool result = start_auth_session(sapi_context, session);
  if (!result) {
    tpm2_session_free(&session);
    return NULL;
  }

  return session;
}

#define MAX_PERSISTENT_HANDLES  4

typedef struct generate_key_context generate_key_context;
struct generate_key_context {
  struct {
    TPM2_HANDLE ek;
    TPM2_HANDLE ak;/*[MAX_PERSISTENT_HANDLES];*/
  } persistent_handle;
  struct {
    TPM2B_AUTH endorse;
    TPM2B_AUTH ak;
    TPM2B_AUTH owner;
  } passwords;
  TPM2_ALG_ID algorithm_type;
  TPM2_ALG_ID digest_alg;
  TPM2_ALG_ID sign_alg;
};

static generate_key_context ctx = {
  .persistent_handle = {
    .ek = 0x81010000, // default EK handle
    .ak = 0x81010001,
  },
  .passwords = {
    .endorse = TPM2B_EMPTY_INIT,
    .ak      = TPM2B_EMPTY_INIT,
    .owner   = TPM2B_EMPTY_INIT,
  },
  .algorithm_type = TPM2_ALG_RSA,
  .digest_alg = TPM2_ALG_SHA1, //TPM2_ALG_SHA256,
  .sign_alg = TPM2_ALG_NULL,
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
  in_public->publicArea.nameAlg = TPM2_ALG_SHA1; //TPM2_ALG_SHA256;
  // First clear attributes bit field.
  in_public->publicArea.objectAttributes = 0;
  /*in_public->publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;*//* jturnsek: no need to use tickets */ 
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

TPM2_RC tpm_generate_key_pair(TSS2_SYS_CONTEXT *sapi_context, TPM2_ALG_ID algorithm, TPM2B_PUBLIC *public, TPM2B_NAME *name, TPMI_DH_OBJECT *persistent)
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

  TPM2B_PRIVATE out_private = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);

  TPM2B_DIGEST creation_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

  TPM2_HANDLE handle_ek = ctx.persistent_handle.ek;

  inSensitive.sensitive.data.size = 0;
  inSensitive.size = inSensitive.sensitive.userAuth.size + 2;
  creation_pcr.count = 0;

  ctx.algorithm_type = algorithm;

  memcpy(&inSensitive.sensitive.userAuth, &ctx.passwords.ak, sizeof(ctx.passwords.ak));

  bool result = set_key_algorithm(&inPublic);
  if (!result) {
    return TPM2_RC_FAILURE;
  }

  memcpy(&sessions_data.auths[0].hmac, &ctx.passwords.endorse, sizeof(ctx.passwords.endorse));

  tpm2_session_data *data = tpm2_session_data_new(TPM2_SE_POLICY);
  if (!data) {
    return TPM2_RC_FAILURE;
  }

  tpm2_session *session = tpm2_session_new(sapi_context, data);
  if (!session) {
    return TPM2_RC_FAILURE;
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
    return rval;
  }

  sessions_data.auths[0].sessionHandle = handle;
  sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
  sessions_data.auths[0].hmac.size = 0;

  rval = TSS2_RETRY_EXP(Tss2_Sys_Create(sapi_context, handle_ek, &sessions_data,
          &inSensitive, &inPublic, &outsideInfo, &creation_pcr, &out_private,
          &out_public, &creation_data, &creation_hash, &creation_ticket,
          &sessions_data_out));
  if (rval != TPM2_RC_SUCCESS) {
    return rval;
  }
  
  // Need to flush the session here.
  rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
  if (rval != TPM2_RC_SUCCESS) {
    return rval;
  }
  // And remove the session from sessions table.
  sessions_data.auths[0].sessionHandle = TPM2_RS_PW;
  sessions_data.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;
  sessions_data.auths[0].hmac.size = 0;

  memcpy(&sessions_data.auths[0].hmac, &ctx.passwords.endorse, sizeof(ctx.passwords.endorse));

  data = tpm2_session_data_new(TPM2_SE_POLICY);
  if (!data) {
    return TPM2_RC_FAILURE;
  }

  session = tpm2_session_new(sapi_context, data);
  if (!session) {
    return TPM2_RC_FAILURE;
  }

  handle = tpm2_session_get_session_handle(session);
  tpm2_session_free(&session);

  rval = TSS2_RETRY_EXP(Tss2_Sys_PolicySecret(sapi_context, TPM2_RH_ENDORSEMENT,
          handle, &sessions_data, 0, 0, 0, 0, 0, 0, 0));
  if (rval != TPM2_RC_SUCCESS) {
    return rval;
  }

  sessions_data.auths[0].sessionHandle = handle;
  sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
  sessions_data.auths[0].hmac.size = 0;

  TPM2_HANDLE loaded_key_handle;
  rval = TSS2_RETRY_EXP(Tss2_Sys_Load(sapi_context, handle_ek, &sessions_data, &out_private,
          &out_public, &loaded_key_handle, name, &sessions_data_out));
  if (rval != TPM2_RC_SUCCESS) {
    return rval;
  }

  // Need to flush the session here.
  rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, handle));
  if (rval != TPM2_RC_SUCCESS) {
    return rval;
  }
  sessions_data.auths[0].sessionHandle = TPM2_RS_PW;
  sessions_data.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;
  sessions_data.auths[0].hmac.size = 0;

  // use the owner auth here.
  memcpy(&sessions_data.auths[0].hmac, &ctx.passwords.owner, sizeof(ctx.passwords.owner));

  rval = TSS2_RETRY_EXP(Tss2_Sys_EvictControl(sapi_context, TPM2_RH_OWNER, loaded_key_handle,
          &sessions_data, ctx.persistent_handle.ak, &sessions_data_out));
  if (rval != TPM2_RC_SUCCESS) {
    return rval;
  }
  
  rval = TSS2_RETRY_EXP(Tss2_Sys_FlushContext(sapi_context, loaded_key_handle));
  if (rval != TPM2_RC_SUCCESS) {
    return rval;
  }

  *public = out_public;
  *persistent = ctx.persistent_handle.ak;

  return TPM2_RC_SUCCESS;
}

TPM2_RC tpm_read_public(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public, TPM2B_NAME *name) {
  TSS2L_SYS_AUTH_RESPONSE sessions_data_out = { .count = 1 };

  TPM2B_NAME qualified_name = { .size = sizeof(TPMU_NAME) };

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_ReadPublic(sapi_context, handle, 0, public, name, &qualified_name, &sessions_data_out));

  return rval;
}

TPM2_RC tpm_rsa_sign(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature) {
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
  memcpy(digest.buffer, hash - digestSize + hash_length, digestSize);

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Sign(sapi_context, handle, &sessions_data, &digest, &scheme, &validation, signature, &sessions_data_out));

  return rval;
}

TPM2_RC tpm_ecc_sign(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature) {
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
  //if (memcmp(hash, oid_sha1, sizeof(oid_sha1)) == 0) {
    scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA1;
    digestSize = TPM2_SHA1_DIGEST_SIZE;
  //} else if (memcmp(hash, oid_sha256, sizeof(oid_sha256)) == 0) {
  //  scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
  //  digestSize = TPM2_SHA256_DIGEST_SIZE;
  //} else
  //  return TPM2_RC_FAILURE;

  TPM2B_DIGEST digest = { .size = digestSize };
  // Remove OID from hash if provided
  //memcpy(digest.buffer, hash - digestSize + hash_length, digestSize);
  memcpy(digest.buffer, hash, digestSize);

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_Sign(sapi_context, handle, &sessions_data, &digest, &scheme, &validation, signature, &sessions_data_out));

  return rval;
}

TPM2_RC tpm_verify(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, TPMT_SIGNATURE *signature, unsigned char *hash, unsigned long hash_length) {
  TPM2B_DIGEST digest  = { .size = hash_length };
  TPMT_TK_VERIFIED validation;

  TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

  memcpy(digest.buffer, hash, hash_length);

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_VerifySignature(sapi_context, handle, NULL, &digest, signature, &validation, &sessions_data_out));

  return rval;
}

TPM2_RC tpm_rsa_decrypt(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, unsigned char *cipher_text, unsigned long cipher_length, TPM2B_PUBLIC_KEY_RSA *message) {
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

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_RSA_Decrypt(sapi_context, handle, &sessions_data, &cipher, &scheme, &label, message, &sessions_data_out));

  return rval;
}

TPM2_RC tpm_rsa_encrypt(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, unsigned char *data, unsigned long data_length, TPM2B_PUBLIC_KEY_RSA *message) {
  TPMT_RSA_DECRYPT scheme;
  TPM2B_DATA label;

  TPM2B_PUBLIC_KEY_RSA in_data =  { .size = data_length };

  TSS2L_SYS_AUTH_RESPONSE out_sessions_data;

  scheme.scheme = TPM2_ALG_RSAES;
  label.size = 0;

  memcpy(in_data.buffer, data, data_length);

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_RSA_Encrypt(sapi_context, handle, NULL, &in_data, &scheme, &label, message, &out_sessions_data));

  return rval;
}

TPM2_RC tpm_list(TSS2_SYS_CONTEXT *sapi_context, TPMS_CAPABILITY_DATA* capability_data) {
  TPMI_YES_NO more_data;

  TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_GetCapability(sapi_context, 0, TPM2_CAP_HANDLES, htobe32(TPM2_HT_PERSISTENT), TPM2_PT_TPM2_HR_PERSISTENT, &more_data, capability_data, 0));

  return rval;
}
