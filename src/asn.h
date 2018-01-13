/*
 * This file is part of tpm2-pk11.
 * Copyright (C) 2018 Jernej Turnsek
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

#ifndef ASN_H_
#define ASN_H_

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"


/**
 * Definition of some primitive ASN1 types
 */
typedef enum {
  ASN1_EOC =              0x00,
  ASN1_BOOLEAN =          0x01,
  ASN1_INTEGER =          0x02,
  ASN1_BIT_STRING =       0x03,
  ASN1_OCTET_STRING =     0x04,
  ASN1_NULL =             0x05,
  ASN1_OID =              0x06,
  ASN1_ENUMERATED =       0x0A,
  ASN1_UTF8STRING =       0x0C,
  ASN1_NUMERICSTRING =    0x12,
  ASN1_PRINTABLESTRING =  0x13,
  ASN1_T61STRING =        0x14,
  ASN1_VIDEOTEXSTRING =   0x15,
  ASN1_IA5STRING =        0x16,
  ASN1_UTCTIME =          0x17,
  ASN1_GENERALIZEDTIME =  0x18,
  ASN1_GRAPHICSTRING =    0x19,
  ASN1_VISIBLESTRING =    0x1A,
  ASN1_GENERALSTRING =    0x1B,
  ASN1_UNIVERSALSTRING =  0x1C,
  ASN1_BMPSTRING =        0x1E,

  ASN1_CONSTRUCTED =      0x20,

  ASN1_SEQUENCE =         0x30,
  ASN1_SET =              0x31,

  ASN1_CONTEXT_S_0 =      0x80,
  ASN1_CONTEXT_S_1 =      0x81,
  ASN1_CONTEXT_S_2 =      0x82,
  ASN1_CONTEXT_S_3 =      0x83,
  ASN1_CONTEXT_S_4 =      0x84,
  ASN1_CONTEXT_S_5 =      0x85,
  ASN1_CONTEXT_S_6 =      0x86,
  ASN1_CONTEXT_S_7 =      0x87,
  ASN1_CONTEXT_S_8 =      0x88,

  ASN1_CONTEXT_C_0 =      0xA0,
  ASN1_CONTEXT_C_1 =      0xA1,
  ASN1_CONTEXT_C_2 =      0xA2,
  ASN1_CONTEXT_C_3 =      0xA3,
  ASN1_CONTEXT_C_4 =      0xA4,
  ASN1_CONTEXT_C_5 =      0xA5,

  ASN1_INVALID =          0x100,
} asn_t;

/**
 * General purpose pointer/length abstraction.
 */
struct asn_buf_t {
  /** Pointer to start of data */
  unsigned char *ptr;
  /** Length of data in bytes */
  size_t len;
};

typedef struct asn_buf_t asn_buf_t;

extern asn_buf_t asn_buf_empty;

/**
 * Create a new asn_buf_t pointing to "ptr" with length "len"
 */
static inline asn_buf_t asn_buf_create(unsigned char *ptr, size_t len)
{
  asn_buf_t buf = {ptr, len};
  return buf;
}

/**
 * Allocate a asn_buf_t on the heap
 */
#define asn_buf_alloc(bytes) ({size_t x = (bytes); asn_buf_create(x ? malloc(x) : NULL, x);})

/**
 * Overwrite the contents of a asn_buf_t and free it
 */
static inline void asn_buf_clear(asn_buf_t *buf)
{
  if (buf->ptr)
  {
    memset(buf->ptr, 0, buf->len);
    free(buf->ptr);
  	*buf = asn_buf_empty;
  }
}

/**
 * Build an empty ASN.1 object with tag and length fields already filled in
 *
 * @param object  returned object - memory is allocated by function
 * @param type    ASN.1 type to be created
 * @param datalen size of the body to be created
 * @return        points to the first position in the body
 */
unsigned char* asn_build_object(asn_buf_t *object, asn_t type, size_t datalen)

/**
 * Build an ASN.1 object from a variable number of individual asn bufs
 *
 * The mode string specifies the number of asn bufs, and how to handle each of
 * them with a single character: 'c' for copy (allocate new asn_buf), 'm' for move
 * (free given asn_buf) or 's' for sensitive-copy (clear given asn_buf, then free).
 *
 * @param type    ASN.1 type to be created
 * @param mode    for each list member: 'c', 'm' or 's'
 * @return        asn_buf containing the ASN.1 coded object
 */
asn_buf_t asn_wrap(asn_t type, const char *mode, ...);

/**
 * Converts a known OID index to an ASN.1 OID
 *
 * @param n     index into the oid_names[] table
 * @return      allocated OID asn_buf, asn_buf_empty if index out of range
 */
asn_buf_t asn_build_known_oid(int n);

struct asn_oid_t {
  unsigned char octet;
  uint32_t  next;
  uint32_t  down;
  uint32_t  level;
  const unsigned char *name;
};

typedef struct asn_oid_t asn_oid_t;


#define OID_UNKNOWN              		     -1
#define OID_NAME_DISTINGUISHER            6
#define OID_PILOT_USERID                  16
#define OID_PILOT_DOMAIN_COMPONENT        17
#define OID_COMMON_NAME                   20
#define OID_SURNAME                       21
#define OID_SERIAL_NUMBER                 22
#define OID_COUNTRY                       23
#define OID_LOCALITY                      24
#define OID_STATE_OR_PROVINCE             25
#define OID_STREET_ADDRESS                26
#define OID_ORGANIZATION                  27
#define OID_ORGANIZATION_UNIT             28
#define OID_TITLE                         29
#define OID_DESCRIPTION                   30
#define OID_POSTAL_ADDRESS                31
#define OID_POSTAL_CODE                   32
#define OID_USER_CERTIFICATE              33
#define OID_NAME                          34
#define OID_GIVEN_NAME                    35
#define OID_INITIALS                      36
#define OID_UNIQUE_IDENTIFIER             37
#define OID_DN_QUALIFIER                  38
#define OID_DMD_NAME                      39
#define OID_PSEUDONYM                     40
#define OID_ROLE                          41
#define OID_SUBJECT_KEY_ID                44
#define OID_KEY_USAGE                     45
#define OID_SUBJECT_ALT_NAME              47
#define OID_BASIC_CONSTRAINTS             49
#define OID_CRL_NUMBER                    50
#define OID_CRL_REASON_CODE               51
#define OID_DELTA_CRL_INDICATOR           54
#define OID_ISSUING_DIST_POINT            55
#define OID_NAME_CONSTRAINTS              57
#define OID_CRL_DISTRIBUTION_POINTS       58
#define OID_CERTIFICATE_POLICIES          59
#define OID_ANY_POLICY                    60
#define OID_POLICY_MAPPINGS               61
#define OID_AUTHORITY_KEY_ID              62
#define OID_POLICY_CONSTRAINTS            63
#define OID_EXTENDED_KEY_USAGE            64
#define OID_FRESHEST_CRL                  66
#define OID_INHIBIT_ANY_POLICY            67
#define OID_TARGET_INFORMATION            68
#define OID_NO_REV_AVAIL                  69
#define OID_CAMELLIA128_CBC               80
#define OID_CAMELLIA192_CBC               81
#define OID_CAMELLIA256_CBC               82
#define OID_RSA_ENCRYPTION                95
#define OID_MD2_WITH_RSA                  96
#define OID_MD5_WITH_RSA                  97
#define OID_SHA1_WITH_RSA                 98
#define OID_RSAES_OAEP                    99
#define OID_MGF1                          100
#define OID_RSASSA_PSS                    102
#define OID_SHA256_WITH_RSA               103
#define OID_SHA384_WITH_RSA               104
#define OID_SHA512_WITH_RSA               105
#define OID_SHA224_WITH_RSA               106
#define OID_PBE_MD5_DES_CBC               108
#define OID_PBE_SHA1_DES_CBC              109
#define OID_PBKDF2                        110
#define OID_PBES2                         111
#define OID_PKCS7_DATA                    113
#define OID_PKCS7_SIGNED_DATA             114
#define OID_PKCS7_ENVELOPED_DATA          115
#define OID_PKCS7_SIGNED_ENVELOPED_DATA   116
#define OID_PKCS7_DIGESTED_DATA           117
#define OID_PKCS7_ENCRYPTED_DATA          118
#define OID_EMAIL_ADDRESS                 120
#define OID_UNSTRUCTURED_NAME             121
#define OID_PKCS9_CONTENT_TYPE            122
#define OID_PKCS9_MESSAGE_DIGEST          123
#define OID_PKCS9_SIGNING_TIME            124
#define OID_CHALLENGE_PASSWORD            126
#define OID_UNSTRUCTURED_ADDRESS          127
#define OID_EXTENSION_REQUEST             128
#define OID_X509_CERTIFICATE              131
#define OID_PBE_SHA1_RC4_128              135
#define OID_PBE_SHA1_RC4_40               136
#define OID_PBE_SHA1_3DES_CBC             137
#define OID_PBE_SHA1_3DES_2KEY_CBC        138
#define OID_PBE_SHA1_RC2_CBC_128          139
#define OID_PBE_SHA1_RC2_CBC_40           140
#define OID_P12_KEY_BAG                   143
#define OID_P12_PKCS8_KEY_BAG             144
#define OID_P12_CERT_BAG                  145
#define OID_P12_CRL_BAG                   146
#define OID_MD2                           150
#define OID_MD5                           151
#define OID_3DES_EDE_CBC                  153
#define OID_EC_PUBLICKEY                  157
#define OID_C2PNB163V1                    160
#define OID_C2PNB163V2                    161
#define OID_C2PNB163V3                    162
#define OID_C2PNB176W1                    163
#define OID_C2PNB191V1                    164
#define OID_C2PNB191V2                    165
#define OID_C2PNB191V3                    166
#define OID_C2PNB191V4                    167
#define OID_C2PNB191V5                    168
#define OID_C2PNB208W1                    169
#define OID_C2PNB239V1                    170
#define OID_C2PNB239V2                    171
#define OID_C2PNB239V3                    172
#define OID_C2PNB239V4                    173
#define OID_C2PNB239V5                    174
#define OID_C2PNB272W1                    175
#define OID_C2PNB304W1                    176
#define OID_C2PNB359V1                    177
#define OID_C2PNB368W1                    178
#define OID_C2PNB431R1                    179
#define OID_PRIME192V1                    181
#define OID_PRIME192V2                    182
#define OID_PRIME192V3                    183
#define OID_PRIME239V1                    184
#define OID_PRIME239V2                    185
#define OID_PRIME239V3                    186
#define OID_PRIME256V1                    187
#define OID_ECDSA_WITH_SHA1               189
#define OID_ECDSA_WITH_SHA224             191
#define OID_ECDSA_WITH_SHA256             192
#define OID_ECDSA_WITH_SHA384             193
#define OID_ECDSA_WITH_SHA512             194
#define OID_MS_SMARTCARD_LOGON            208
#define OID_USER_PRINCIPAL_NAME           209
#define OID_STRONGSWAN                    215
#define OID_BLISS_PUBLICKEY               220
#define OID_BLISS_I                       222
#define OID_BLISS_II                      223
#define OID_BLISS_III                     224
#define OID_BLISS_IV                      225
#define OID_BLISS_B_I                     226
#define OID_BLISS_B_II                    227
#define OID_BLISS_B_III                   228
#define OID_BLISS_B_IV                    229
#define OID_BLISS_WITH_SHA2_512           231
#define OID_BLISS_WITH_SHA2_384           232
#define OID_BLISS_WITH_SHA2_256           233
#define OID_BLISS_WITH_SHA3_512           234
#define OID_BLISS_WITH_SHA3_384           235
#define OID_BLISS_WITH_SHA3_256           236
#define OID_TCGID                         243
#define OID_BLOWFISH_CBC                  247
#define OID_AUTHORITY_INFO_ACCESS         291
#define OID_IP_ADDR_BLOCKS                293
#define OID_POLICY_QUALIFIER_CPS          296
#define OID_POLICY_QUALIFIER_UNOTICE      297
#define OID_SERVER_AUTH                   299
#define OID_CLIENT_AUTH                   300
#define OID_OCSP_SIGNING                  307
#define OID_XMPP_ADDR                     313
#define OID_AUTHENTICATION_INFO           317
#define OID_ACCESS_IDENTITY               318
#define OID_CHARGING_IDENTITY             319
#define OID_GROUP                         320
#define OID_OCSP                          323
#define OID_BASIC                         324
#define OID_NONCE                         325
#define OID_CRL                           326
#define OID_RESPONSE                      327
#define OID_NO_CHECK                      328
#define OID_ARCHIVE_CUTOFF                329
#define OID_SERVICE_LOCATOR               330
#define OID_CA_ISSUERS                    331
#define OID_IKE_INTERMEDIATE              336
#define OID_DES_CBC                       340
#define OID_SHA1                          341
#define OID_SHA1_WITH_RSA_OIW             342
#define OID_ECGDSA_PUBKEY                 361
#define OID_ECGDSA_SIG_WITH_RIPEMD160     364
#define OID_ECGDSA_SIG_WITH_SHA1          365
#define OID_ECGDSA_SIG_WITH_SHA224        366
#define OID_ECGDSA_SIG_WITH_SHA256        367
#define OID_ECGDSA_SIG_WITH_SHA384        368
#define OID_ECGDSA_SIG_WITH_SHA512        369
#define OID_ED25519                       390
#define OID_ED448                         391
#define OID_SECT163K1                     395
#define OID_SECT163R1                     396
#define OID_SECT239K1                     397
#define OID_SECT113R1                     398
#define OID_SECT113R2                     399
#define OID_SECT112R1                     400
#define OID_SECT112R2                     401
#define OID_SECT160R1                     402
#define OID_SECT160K1                     403
#define OID_SECT256K1                     404
#define OID_SECT163R2                     405
#define OID_SECT283K1                     406
#define OID_SECT283R1                     407
#define OID_SECT131R1                     408
#define OID_SECT131R2                     409
#define OID_SECT193R1                     410
#define OID_SECT193R2                     411
#define OID_SECT233K1                     412
#define OID_SECT233R1                     413
#define OID_SECT128R1                     414
#define OID_SECT128R2                     415
#define OID_SECT160R2                     416
#define OID_SECT192K1                     417
#define OID_SECT224K1                     418
#define OID_SECT224R1                     419
#define OID_SECT384R1                     420
#define OID_SECT521R1                     421
#define OID_SECT409K1                     422
#define OID_SECT409R1                     423
#define OID_SECT571K1                     424
#define OID_SECT571R1                     425
#define OID_AES128_CBC                    434
#define OID_AES128_GCM                    435
#define OID_AES128_CCM                    436
#define OID_AES192_CBC                    437
#define OID_AES192_GCM                    438
#define OID_AES192_CCM                    439
#define OID_AES256_CBC                    440
#define OID_AES256_GCM                    441
#define OID_AES256_CCM                    442
#define OID_SHA256                        444
#define OID_SHA384                        445
#define OID_SHA512                        446
#define OID_SHA224                        447
#define OID_SHA3_224                      450
#define OID_SHA3_256                      451
#define OID_SHA3_384                      452
#define OID_SHA3_512                      453
#define OID_ECDSA_WITH_SHA3_224           457
#define OID_ECDSA_WITH_SHA3_256           458
#define OID_ECDSA_WITH_SHA3_384           459
#define OID_ECDSA_WITH_SHA3_512           460
#define OID_RSASSA_PKCS1V15_WITH_SHA3_224 461
#define OID_RSASSA_PKCS1V15_WITH_SHA3_256 462
#define OID_RSASSA_PKCS1V15_WITH_SHA3_384 463
#define OID_RSASSA_PKCS1V15_WITH_SHA3_512 464
#define OID_NS_REVOCATION_URL             470
#define OID_NS_CA_REVOCATION_URL          471
#define OID_NS_CA_POLICY_URL              472
#define OID_NS_COMMENT                    473
#define OID_EMPLOYEE_NUMBER               476
#define OID_PKI_MESSAGE_TYPE              482
#define OID_PKI_STATUS                    483
#define OID_PKI_FAIL_INFO                 484
#define OID_PKI_SENDER_NONCE              485
#define OID_PKI_RECIPIENT_NONCE           486
#define OID_PKI_TRANS_ID                  487
#define OID_TPM_MANUFACTURER              493
#define OID_TPM_MODEL                     494
#define OID_TPM_VERSION                   495
#define OID_TPM_ID_LABEL                  496
#define OID_MAX                           497

#endif /** ASN_H_ */
