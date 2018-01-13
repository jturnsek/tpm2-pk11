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

#include "asn.h"

/**
 * Empty asn_buf.
 */
asn_buf_t asn_buf_empty = { NULL, 0 };


static void asn_code_length(size_t length, asn_buf_t *code)
{
  if (length < 128) {
    code->ptr[0] = length;
    code->len = 1;
  }
  else if (length < 256) {
    code->ptr[0] = 0x81;
    code->ptr[1] = (unsigned char) length;
    code->len = 2;
  }
  else if (length < 65536) {
    code->ptr[0] = 0x82;
    code->ptr[1] = length >> 8;
    code->ptr[2] = length & 0x00ff;
    code->len = 3;
  }
  else {
    code->ptr[0] = 0x83;
    code->ptr[1] = length >> 16;
    code->ptr[2] = (length >> 8) & 0x00ff;
    code->ptr[3] = length & 0x0000ff;
    code->len = 4;
  }
}

/**
 * build an empty asn.1 object with tag and length fields already filled in
 */
unsigned char* asn_build_object(asn_buf_t *object, asn_t type, size_t datalen)
{
  unsigned char length_buf[4];
  asn_buf_t length = { length_buf, 0 };
  unsigned char *pos;

  /* code the asn.1 length field */
  asn_code_length(datalen, &length);

  /* allocate memory for the asn.1 TLV object */
  object->len = 1 + length.len + datalen;
  object->ptr = malloc(object->len);

  /* set position pointer at the start of the object */
  pos = object->ptr;

  /* copy the asn.1 tag field and advance the pointer */
  *pos++ = type;

  /* copy the asn.1 length field and advance the pointer */
  memcpy(pos, length.ptr, length.len);
  pos += length.len;

  return pos;
}

/**
 * Build an ASN.1 object from a variable number of individual buffers.
 * Depending on the mode, buffers either are moved ('m') or copied ('c').
 */
asn_buf_t asn_wrap(asn_t type, const char *mode, ...)
{
  asn_buf_t construct;
  va_list bufs;
  unsigned char *pos;
  int i;
  int count = strlen(mode);

  /* sum up lengths of individual bufs */
  va_start(bufs, mode);
  construct.len = 0;
  for (i = 0; i < count; i++) {
    asn_buf_t ch = va_arg(bufs, asn_buf_t);
    construct.len += ch.len;
  }
  va_end(bufs);

  /* allocate needed memory for construct */
  pos = asn_build_object(&construct, type, construct.len);

  /* copy or move the bufs */
  va_start(bufs, mode);
  for (i = 0; i < count; i++) {
    asn_buf_t ch = va_arg(bufs, asn_buf_t);

    memcpy(pos, ch.ptr, ch.len);
    pos += ch.len;

    switch (*mode++) {
      case 's':
        asn_buf_clear(&ch);
        break;
      case 'm':
        free(ch.ptr);
        break;
      default:
        break;
    }
  }
  va_end(bufs);

  return construct;
}

asn_buf_t asn_build_known_oid(int n)
{
  asn_buf_t oid;
  int i;

  if (n < 0 || n >= OID_MAX) {
    return asn_buf_empty;
  }

  i = asn_oid_names[n].level + 1;
  oid = asn_buf_alloc(2 + i);
  oid.ptr[0] = ASN1_OID;
  oid.ptr[1] = i;

  do {
    if (asn_oid_names[n].level >= i) {
      n--;
      continue;
    }
    oid.ptr[--i + 2] = asn_oid_names[n--].octet;
  }
  while (i > 0);

  return oid;
}


/**
 * OID names
 */
const asn_oid_t asn_oid_names[] = {
  {0x02,                         7, 1,  0, "ITU-T Administration"            }, /*   0 */
  {  0x82,                       0, 1,  1, ""                                }, /*   1 */
  {    0x06,                     0, 1,  2, "Germany ITU-T member"            }, /*   2 */
  {      0x01,                   0, 1,  3, "Deutsche Telekom AG"             }, /*   3 */
  {        0x0A,                 0, 1,  4, ""                                }, /*   4 */
  {          0x07,               0, 1,  5, ""                                }, /*   5 */
  {            0x14,             0, 0,  6, "ND"                              }, /*   6 */
  {0x09,                        18, 1,  0, "data"                            }, /*   7 */
  {  0x92,                       0, 1,  1, ""                                }, /*   8 */
  {    0x26,                     0, 1,  2, ""                                }, /*   9 */
  {      0x89,                   0, 1,  3, ""                                }, /*  10 */
  {        0x93,                 0, 1,  4, ""                                }, /*  11 */
  {          0xF2,               0, 1,  5, ""                                }, /*  12 */
  {            0x2C,             0, 1,  6, ""                                }, /*  13 */
  {              0x64,           0, 1,  7, "pilot"                           }, /*  14 */
  {                0x01,         0, 1,  8, "pilotAttributeType"              }, /*  15 */
  {                  0x01,      17, 0,  9, "UID"                             }, /*  16 */
  {                  0x19,       0, 0,  9, "DC"                              }, /*  17 */
  {0x55,                        70, 1,  0, "X.500"                           }, /*  18 */
  {  0x04,                      42, 1,  1, "X.509"                           }, /*  19 */
  {    0x03,                    21, 0,  2, "CN"                              }, /*  20 */
  {    0x04,                    22, 0,  2, "S"                               }, /*  21 */
  {    0x05,                    23, 0,  2, "SN"                              }, /*  22 */
  {    0x06,                    24, 0,  2, "C"                               }, /*  23 */
  {    0x07,                    25, 0,  2, "L"                               }, /*  24 */
  {    0x08,                    26, 0,  2, "ST"                              }, /*  25 */
  {    0x09,                    27, 0,  2, "STREET"                          }, /*  26 */
  {    0x0A,                    28, 0,  2, "O"                               }, /*  27 */
  {    0x0B,                    29, 0,  2, "OU"                              }, /*  28 */
  {    0x0C,                    30, 0,  2, "T"                               }, /*  29 */
  {    0x0D,                    31, 0,  2, "D"                               }, /*  30 */
  {    0x10,                    32, 0,  2, "postalAddress"                   }, /*  31 */
  {    0x11,                    33, 0,  2, "postalCode"                      }, /*  32 */
  {    0x24,                    34, 0,  2, "userCertificate"                 }, /*  33 */
  {    0x29,                    35, 0,  2, "N"                               }, /*  34 */
  {    0x2A,                    36, 0,  2, "G"                               }, /*  35 */
  {    0x2B,                    37, 0,  2, "I"                               }, /*  36 */
  {    0x2D,                    38, 0,  2, "ID"                              }, /*  37 */
  {    0x2E,                    39, 0,  2, "dnQualifier"                     }, /*  38 */
  {    0x36,                    40, 0,  2, "dmdName"                         }, /*  39 */
  {    0x41,                    41, 0,  2, "pseudonym"                       }, /*  40 */
  {    0x48,                     0, 0,  2, "role"                            }, /*  41 */
  {  0x1D,                       0, 1,  1, "id-ce"                           }, /*  42 */
  {    0x09,                    44, 0,  2, "subjectDirectoryAttrs"           }, /*  43 */
  {    0x0E,                    45, 0,  2, "subjectKeyIdentifier"            }, /*  44 */
  {    0x0F,                    46, 0,  2, "keyUsage"                        }, /*  45 */
  {    0x10,                    47, 0,  2, "privateKeyUsagePeriod"           }, /*  46 */
  {    0x11,                    48, 0,  2, "subjectAltName"                  }, /*  47 */
  {    0x12,                    49, 0,  2, "issuerAltName"                   }, /*  48 */
  {    0x13,                    50, 0,  2, "basicConstraints"                }, /*  49 */
  {    0x14,                    51, 0,  2, "crlNumber"                       }, /*  50 */
  {    0x15,                    52, 0,  2, "reasonCode"                      }, /*  51 */
  {    0x17,                    53, 0,  2, "holdInstructionCode"             }, /*  52 */
  {    0x18,                    54, 0,  2, "invalidityDate"                  }, /*  53 */
  {    0x1B,                    55, 0,  2, "deltaCrlIndicator"               }, /*  54 */
  {    0x1C,                    56, 0,  2, "issuingDistributionPoint"        }, /*  55 */
  {    0x1D,                    57, 0,  2, "certificateIssuer"               }, /*  56 */
  {    0x1E,                    58, 0,  2, "nameConstraints"                 }, /*  57 */
  {    0x1F,                    59, 0,  2, "crlDistributionPoints"           }, /*  58 */
  {    0x20,                    61, 1,  2, "certificatePolicies"             }, /*  59 */
  {      0x00,                   0, 0,  3, "anyPolicy"                       }, /*  60 */
  {    0x21,                    62, 0,  2, "policyMappings"                  }, /*  61 */
  {    0x23,                    63, 0,  2, "authorityKeyIdentifier"          }, /*  62 */
  {    0x24,                    64, 0,  2, "policyConstraints"               }, /*  63 */
  {    0x25,                    66, 1,  2, "extendedKeyUsage"                }, /*  64 */
  {      0x00,                   0, 0,  3, "anyExtendedKeyUsage"             }, /*  65 */
  {    0x2E,                    67, 0,  2, "freshestCRL"                     }, /*  66 */
  {    0x36,                    68, 0,  2, "inhibitAnyPolicy"                }, /*  67 */
  {    0x37,                    69, 0,  2, "targetInformation"               }, /*  68 */
  {    0x38,                     0, 0,  2, "noRevAvail"                      }, /*  69 */
  {0x2A,                       195, 1,  0, ""                                }, /*  70 */
  {  0x83,                      83, 1,  1, ""                                }, /*  71 */
  {    0x08,                     0, 1,  2, "jp"                              }, /*  72 */
  {      0x8C,                   0, 1,  3, ""                                }, /*  73 */
  {        0x9A,                 0, 1,  4, ""                                }, /*  74 */
  {          0x4B,               0, 1,  5, ""                                }, /*  75 */
  {            0x3D,             0, 1,  6, ""                                }, /*  76 */
  {              0x01,           0, 1,  7, "security"                        }, /*  77 */
  {                0x01,         0, 1,  8, "algorithm"                       }, /*  78 */
  {                  0x01,       0, 1,  9, "symm-encryption-alg"             }, /*  79 */
  {                    0x02,    81, 0, 10, "camellia128-cbc"                 }, /*  80 */
  {                    0x03,    82, 0, 10, "camellia192-cbc"                 }, /*  81 */
  {                    0x04,     0, 0, 10, "camellia256-cbc"                 }, /*  82 */
  {  0x86,                       0, 1,  1, ""                                }, /*  83 */
  {    0x48,                     0, 1,  2, "us"                              }, /*  84 */
  {      0x86,                 154, 1,  3, ""                                }, /*  85 */
  {        0xF6,                91, 1,  4, ""                                }, /*  86 */
  {          0x7D,               0, 1,  5, "NortelNetworks"                  }, /*  87 */
  {            0x07,             0, 1,  6, "Entrust"                         }, /*  88 */
  {              0x41,           0, 1,  7, "nsn-ce"                          }, /*  89 */
  {                0x00,         0, 0,  8, "entrustVersInfo"                 }, /*  90 */
  {        0xF7,                 0, 1,  4, ""                                }, /*  91 */
  {          0x0D,               0, 1,  5, "RSADSI"                          }, /*  92 */
  {            0x01,           149, 1,  6, "PKCS"                            }, /*  93 */
  {              0x01,         107, 1,  7, "PKCS-1"                          }, /*  94 */
  {                0x01,        96, 0,  8, "rsaEncryption"                   }, /*  95 */
  {                0x02,        97, 0,  8, "md2WithRSAEncryption"            }, /*  96 */
  {                0x04,        98, 0,  8, "md5WithRSAEncryption"            }, /*  97 */
  {                0x05,        99, 0,  8, "sha-1WithRSAEncryption"          }, /*  98 */
  {                0x07,       100, 0,  8, "id-RSAES-OAEP"                   }, /*  99 */
  {                0x08,       101, 0,  8, "id-mgf1"                         }, /* 100 */
  {                0x09,       102, 0,  8, "id-pSpecified"                   }, /* 101 */
  {                0x0A,       103, 0,  8, "RSASSA-PSS"                      }, /* 102 */
  {                0x0B,       104, 0,  8, "sha256WithRSAEncryption"         }, /* 103 */
  {                0x0C,       105, 0,  8, "sha384WithRSAEncryption"         }, /* 104 */
  {                0x0D,       106, 0,  8, "sha512WithRSAEncryption"         }, /* 105 */
  {                0x0E,         0, 0,  8, "sha224WithRSAEncryption"         }, /* 106 */
  {              0x05,         112, 1,  7, "PKCS-5"                          }, /* 107 */
  {                0x03,       109, 0,  8, "pbeWithMD5AndDES-CBC"            }, /* 108 */
  {                0x0A,       110, 0,  8, "pbeWithSHA1AndDES-CBC"           }, /* 109 */
  {                0x0C,       111, 0,  8, "id-PBKDF2"                       }, /* 110 */
  {                0x0D,         0, 0,  8, "id-PBES2"                        }, /* 111 */
  {              0x07,         119, 1,  7, "PKCS-7"                          }, /* 112 */
  {                0x01,       114, 0,  8, "data"                            }, /* 113 */
  {                0x02,       115, 0,  8, "signedData"                      }, /* 114 */
  {                0x03,       116, 0,  8, "envelopedData"                   }, /* 115 */
  {                0x04,       117, 0,  8, "signedAndEnvelopedData"          }, /* 116 */
  {                0x05,       118, 0,  8, "digestedData"                    }, /* 117 */
  {                0x06,         0, 0,  8, "encryptedData"                   }, /* 118 */
  {              0x09,         133, 1,  7, "PKCS-9"                          }, /* 119 */
  {                0x01,       121, 0,  8, "E"                               }, /* 120 */
  {                0x02,       122, 0,  8, "unstructuredName"                }, /* 121 */
  {                0x03,       123, 0,  8, "contentType"                     }, /* 122 */
  {                0x04,       124, 0,  8, "messageDigest"                   }, /* 123 */
  {                0x05,       125, 0,  8, "signingTime"                     }, /* 124 */
  {                0x06,       126, 0,  8, "counterSignature"                }, /* 125 */
  {                0x07,       127, 0,  8, "challengePassword"               }, /* 126 */
  {                0x08,       128, 0,  8, "unstructuredAddress"             }, /* 127 */
  {                0x0E,       129, 0,  8, "extensionRequest"                }, /* 128 */
  {                0x0F,       130, 0,  8, "S/MIME Capabilities"             }, /* 129 */
  {                0x16,         0, 1,  8, "certTypes"                       }, /* 130 */
  {                  0x01,     132, 0,  9, "X.509"                           }, /* 131 */
  {                  0x02,       0, 0,  9, "SDSI"                            }, /* 132 */
  {              0x0c,           0, 1,  7, "PKCS-12"                         }, /* 133 */
  {                0x01,       141, 1,  8, "pbeIds"                          }, /* 134 */
  {                  0x01,     136, 0,  9, "pbeWithSHAAnd128BitRC4"          }, /* 135 */
  {                  0x02,     137, 0,  9, "pbeWithSHAAnd40BitRC4"           }, /* 136 */
  {                  0x03,     138, 0,  9, "pbeWithSHAAnd3-KeyTripleDES-CBC" }, /* 137 */
  {                  0x04,     139, 0,  9, "pbeWithSHAAnd2-KeyTripleDES-CBC" }, /* 138 */
  {                  0x05,     140, 0,  9, "pbeWithSHAAnd128BitRC2-CBC"      }, /* 139 */
  {                  0x06,       0, 0,  9, "pbeWithSHAAnd40BitRC2-CBC"       }, /* 140 */
  {                0x0a,         0, 1,  8, "PKCS-12v1"                       }, /* 141 */
  {                  0x01,       0, 1,  9, "bagIds"                          }, /* 142 */
  {                    0x01,   144, 0, 10, "keyBag"                          }, /* 143 */
  {                    0x02,   145, 0, 10, "pkcs8ShroudedKeyBag"             }, /* 144 */
  {                    0x03,   146, 0, 10, "certBag"                         }, /* 145 */
  {                    0x04,   147, 0, 10, "crlBag"                          }, /* 146 */
  {                    0x05,   148, 0, 10, "secretBag"                       }, /* 147 */
  {                    0x06,     0, 0, 10, "safeContentsBag"                 }, /* 148 */
  {            0x02,           152, 1,  6, "digestAlgorithm"                 }, /* 149 */
  {              0x02,         151, 0,  7, "md2"                             }, /* 150 */
  {              0x05,           0, 0,  7, "md5"                             }, /* 151 */
  {            0x03,             0, 1,  6, "encryptionAlgorithm"             }, /* 152 */
  {              0x07,           0, 0,  7, "3des-ede-cbc"                    }, /* 153 */
  {      0xCE,                   0, 1,  3, ""                                }, /* 154 */
  {        0x3D,                 0, 1,  4, "ansi-X9-62"                      }, /* 155 */
  {          0x02,             158, 1,  5, "id-publicKeyType"                }, /* 156 */
  {            0x01,             0, 0,  6, "id-ecPublicKey"                  }, /* 157 */
  {          0x03,             188, 1,  5, "ellipticCurve"                   }, /* 158 */
  {            0x00,           180, 1,  6, "c-TwoCurve"                      }, /* 159 */
  {              0x01,         161, 0,  7, "c2pnb163v1"                      }, /* 160 */
  {              0x02,         162, 0,  7, "c2pnb163v2"                      }, /* 161 */
  {              0x03,         163, 0,  7, "c2pnb163v3"                      }, /* 162 */
  {              0x04,         164, 0,  7, "c2pnb176w1"                      }, /* 163 */
  {              0x05,         165, 0,  7, "c2tnb191v1"                      }, /* 164 */
  {              0x06,         166, 0,  7, "c2tnb191v2"                      }, /* 165 */
  {              0x07,         167, 0,  7, "c2tnb191v3"                      }, /* 166 */
  {              0x08,         168, 0,  7, "c2onb191v4"                      }, /* 167 */
  {              0x09,         169, 0,  7, "c2onb191v5"                      }, /* 168 */
  {              0x0A,         170, 0,  7, "c2pnb208w1"                      }, /* 169 */
  {              0x0B,         171, 0,  7, "c2tnb239v1"                      }, /* 170 */
  {              0x0C,         172, 0,  7, "c2tnb239v2"                      }, /* 171 */
  {              0x0D,         173, 0,  7, "c2tnb239v3"                      }, /* 172 */
  {              0x0E,         174, 0,  7, "c2onb239v4"                      }, /* 173 */
  {              0x0F,         175, 0,  7, "c2onb239v5"                      }, /* 174 */
  {              0x10,         176, 0,  7, "c2pnb272w1"                      }, /* 175 */
  {              0x11,         177, 0,  7, "c2pnb304w1"                      }, /* 176 */
  {              0x12,         178, 0,  7, "c2tnb359v1"                      }, /* 177 */
  {              0x13,         179, 0,  7, "c2pnb368w1"                      }, /* 178 */
  {              0x14,           0, 0,  7, "c2tnb431r1"                      }, /* 179 */
  {            0x01,             0, 1,  6, "primeCurve"                      }, /* 180 */
  {              0x01,         182, 0,  7, "prime192v1"                      }, /* 181 */
  {              0x02,         183, 0,  7, "prime192v2"                      }, /* 182 */
  {              0x03,         184, 0,  7, "prime192v3"                      }, /* 183 */
  {              0x04,         185, 0,  7, "prime239v1"                      }, /* 184 */
  {              0x05,         186, 0,  7, "prime239v2"                      }, /* 185 */
  {              0x06,         187, 0,  7, "prime239v3"                      }, /* 186 */
  {              0x07,           0, 0,  7, "prime256v1"                      }, /* 187 */
  {          0x04,               0, 1,  5, "id-ecSigType"                    }, /* 188 */
  {            0x01,           190, 0,  6, "ecdsa-with-SHA1"                 }, /* 189 */
  {            0x03,             0, 1,  6, "ecdsa-with-Specified"            }, /* 190 */
  {              0x01,         192, 0,  7, "ecdsa-with-SHA224"               }, /* 191 */
  {              0x02,         193, 0,  7, "ecdsa-with-SHA256"               }, /* 192 */
  {              0x03,         194, 0,  7, "ecdsa-with-SHA384"               }, /* 193 */
  {              0x04,           0, 0,  7, "ecdsa-with-SHA512"               }, /* 194 */
  {0x2B,                       426, 1,  0, ""                                }, /* 195 */
  {  0x06,                     337, 1,  1, "dod"                             }, /* 196 */
  {    0x01,                     0, 1,  2, "internet"                        }, /* 197 */
  {      0x04,                 287, 1,  3, "private"                         }, /* 198 */
  {        0x01,                 0, 1,  4, "enterprise"                      }, /* 199 */
  {          0x82,             237, 1,  5, ""                                }, /* 200 */
  {            0x37,           213, 1,  6, "Microsoft"                       }, /* 201 */
  {              0x0A,         206, 1,  7, ""                                }, /* 202 */
  {                0x03,         0, 1,  8, ""                                }, /* 203 */
  {                  0x03,     205, 0,  9, "msSGC"                           }, /* 204 */
  {                  0x04,       0, 0,  9, "msEncryptingFileSystem"          }, /* 205 */
  {              0x14,         210, 1,  7, "msEnrollmentInfrastructure"      }, /* 206 */
  {                0x02,         0, 1,  8, "msCertificateTypeExtension"      }, /* 207 */
  {                  0x02,     209, 0,  9, "msSmartcardLogon"                }, /* 208 */
  {                  0x03,       0, 0,  9, "msUPN"                           }, /* 209 */
  {              0x15,           0, 1,  7, "msCertSrvInfrastructure"         }, /* 210 */
  {                0x07,       212, 0,  8, "msCertTemplate"                  }, /* 211 */
  {                0x0A,         0, 0,  8, "msApplicationCertPolicies"       }, /* 212 */
  {            0xA0,             0, 1,  6, ""                                }, /* 213 */
  {              0x2A,           0, 1,  7, "ITA"                             }, /* 214 */
  {                0x01,       216, 0,  8, "strongSwan"                      }, /* 215 */
  {                0x02,       217, 0,  8, "cps"                             }, /* 216 */
  {                0x03,       218, 0,  8, "e-voting"                        }, /* 217 */
  {                0x05,         0, 1,  8, "BLISS"                           }, /* 218 */
  {                  0x01,     221, 1,  9, "keyType"                         }, /* 219 */
  {                    0x01,     0, 0, 10, "blissPublicKey"                  }, /* 220 */
  {                  0x02,     230, 1,  9, "parameters"                      }, /* 221 */
  {                    0x01,   223, 0, 10, "BLISS-I"                         }, /* 222 */
  {                    0x02,   224, 0, 10, "BLISS-II"                        }, /* 223 */
  {                    0x03,   225, 0, 10, "BLISS-III"                       }, /* 224 */
  {                    0x04,   226, 0, 10, "BLISS-IV"                        }, /* 225 */
  {                    0x05,   227, 0, 10, "BLISS-B-I"                       }, /* 226 */
  {                    0x06,   228, 0, 10, "BLISS-B-II"                      }, /* 227 */
  {                    0x07,   229, 0, 10, "BLISS-B-III"                     }, /* 228 */
  {                    0x08,     0, 0, 10, "BLISS-B-IV"                      }, /* 229 */
  {                  0x03,       0, 1,  9, "blissSigType"                    }, /* 230 */
  {                    0x01,   232, 0, 10, "BLISS-with-SHA2-512"             }, /* 231 */
  {                    0x02,   233, 0, 10, "BLISS-with-SHA2-384"             }, /* 232 */
  {                    0x03,   234, 0, 10, "BLISS-with-SHA2-256"             }, /* 233 */
  {                    0x04,   235, 0, 10, "BLISS-with-SHA3-512"             }, /* 234 */
  {                    0x05,   236, 0, 10, "BLISS-with-SHA3-384"             }, /* 235 */
  {                    0x06,     0, 0, 10, "BLISS-with-SHA3-256"             }, /* 236 */
  {          0x89,             244, 1,  5, ""                                }, /* 237 */
  {            0x31,             0, 1,  6, ""                                }, /* 238 */
  {              0x01,           0, 1,  7, ""                                }, /* 239 */
  {                0x01,         0, 1,  8, ""                                }, /* 240 */
  {                  0x02,       0, 1,  9, ""                                }, /* 241 */
  {                    0x02,     0, 1, 10, ""                                }, /* 242 */
  {                      0x4B,   0, 0, 11, "TCGID"                           }, /* 243 */
  {          0x97,             248, 1,  5, ""                                }, /* 244 */
  {            0x55,             0, 1,  6, ""                                }, /* 245 */
  {              0x01,           0, 1,  7, ""                                }, /* 246 */
  {                0x02,         0, 0,  8, "blowfish-cbc"                    }, /* 247 */
  {          0xC1,               0, 1,  5, ""                                }, /* 248 */
  {            0x16,             0, 1,  6, "ntruCryptosystems"               }, /* 249 */
  {              0x01,           0, 1,  7, "eess"                            }, /* 250 */
  {                0x01,         0, 1,  8, "eess1"                           }, /* 251 */
  {                  0x01,     256, 1,  9, "eess1-algs"                      }, /* 252 */
  {                    0x01,   254, 0, 10, "ntru-EESS1v1-SVES"               }, /* 253 */
  {                    0x02,   255, 0, 10, "ntru-EESS1v1-SVSSA"              }, /* 254 */
  {                    0x03,     0, 0, 10, "ntru-EESS1v1-NTRUSign"           }, /* 255 */
  {                  0x02,     286, 1,  9, "eess1-params"                    }, /* 256 */
  {                    0x01,   258, 0, 10, "ees251ep1"                       }, /* 257 */
  {                    0x02,   259, 0, 10, "ees347ep1"                       }, /* 258 */
  {                    0x03,   260, 0, 10, "ees503ep1"                       }, /* 259 */
  {                    0x07,   261, 0, 10, "ees251sp2"                       }, /* 260 */
  {                    0x0C,   262, 0, 10, "ees251ep4"                       }, /* 261 */
  {                    0x0D,   263, 0, 10, "ees251ep5"                       }, /* 262 */
  {                    0x0E,   264, 0, 10, "ees251sp3"                       }, /* 263 */
  {                    0x0F,   265, 0, 10, "ees251sp4"                       }, /* 264 */
  {                    0x10,   266, 0, 10, "ees251sp5"                       }, /* 265 */
  {                    0x11,   267, 0, 10, "ees251sp6"                       }, /* 266 */
  {                    0x12,   268, 0, 10, "ees251sp7"                       }, /* 267 */
  {                    0x13,   269, 0, 10, "ees251sp8"                       }, /* 268 */
  {                    0x14,   270, 0, 10, "ees251sp9"                       }, /* 269 */
  {                    0x22,   271, 0, 10, "ees401ep1"                       }, /* 270 */
  {                    0x23,   272, 0, 10, "ees449ep1"                       }, /* 271 */
  {                    0x24,   273, 0, 10, "ees677ep1"                       }, /* 272 */
  {                    0x25,   274, 0, 10, "ees1087ep2"                      }, /* 273 */
  {                    0x26,   275, 0, 10, "ees541ep1"                       }, /* 274 */
  {                    0x27,   276, 0, 10, "ees613ep1"                       }, /* 275 */
  {                    0x28,   277, 0, 10, "ees887ep1"                       }, /* 276 */
  {                    0x29,   278, 0, 10, "ees1171ep1"                      }, /* 277 */
  {                    0x2A,   279, 0, 10, "ees659ep1"                       }, /* 278 */
  {                    0x2B,   280, 0, 10, "ees761ep1"                       }, /* 279 */
  {                    0x2C,   281, 0, 10, "ees1087ep1"                      }, /* 280 */
  {                    0x2D,   282, 0, 10, "ees1499ep1"                      }, /* 281 */
  {                    0x2E,   283, 0, 10, "ees401ep2"                       }, /* 282 */
  {                    0x2F,   284, 0, 10, "ees439ep1"                       }, /* 283 */
  {                    0x30,   285, 0, 10, "ees593ep1"                       }, /* 284 */
  {                    0x31,     0, 0, 10, "ees743ep1"                       }, /* 285 */
  {                  0x03,       0, 0,  9, "eess1-encodingMethods"           }, /* 286 */
  {      0x05,                   0, 1,  3, "security"                        }, /* 287 */
  {        0x05,                 0, 1,  4, "mechanisms"                      }, /* 288 */
  {          0x07,             334, 1,  5, "id-pkix"                         }, /* 289 */
  {            0x01,           295, 1,  6, "id-pe"                           }, /* 290 */
  {              0x01,         292, 0,  7, "authorityInfoAccess"             }, /* 291 */
  {              0x03,         293, 0,  7, "qcStatements"                    }, /* 292 */
  {              0x07,         294, 0,  7, "ipAddrBlocks"                    }, /* 293 */
  {              0x18,           0, 0,  7, "tlsfeature"                      }, /* 294 */
  {            0x02,           298, 1,  6, "id-qt"                           }, /* 295 */
  {              0x01,         297, 0,  7, "cps"                             }, /* 296 */
  {              0x02,           0, 0,  7, "unotice"                         }, /* 297 */
  {            0x03,           308, 1,  6, "id-kp"                           }, /* 298 */
  {              0x01,         300, 0,  7, "serverAuth"                      }, /* 299 */
  {              0x02,         301, 0,  7, "clientAuth"                      }, /* 300 */
  {              0x03,         302, 0,  7, "codeSigning"                     }, /* 301 */
  {              0x04,         303, 0,  7, "emailProtection"                 }, /* 302 */
  {              0x05,         304, 0,  7, "ipsecEndSystem"                  }, /* 303 */
  {              0x06,         305, 0,  7, "ipsecTunnel"                     }, /* 304 */
  {              0x07,         306, 0,  7, "ipsecUser"                       }, /* 305 */
  {              0x08,         307, 0,  7, "timeStamping"                    }, /* 306 */
  {              0x09,           0, 0,  7, "ocspSigning"                     }, /* 307 */
  {            0x08,           316, 1,  6, "id-otherNames"                   }, /* 308 */
  {              0x01,         310, 0,  7, "personalData"                    }, /* 309 */
  {              0x02,         311, 0,  7, "userGroup"                       }, /* 310 */
  {              0x03,         312, 0,  7, "id-on-permanentIdentifier"       }, /* 311 */
  {              0x04,         313, 0,  7, "id-on-hardwareModuleName"        }, /* 312 */
  {              0x05,         314, 0,  7, "xmppAddr"                        }, /* 313 */
  {              0x06,         315, 0,  7, "id-on-SIM"                       }, /* 314 */
  {              0x07,           0, 0,  7, "id-on-dnsSRV"                    }, /* 315 */
  {            0x0A,           321, 1,  6, "id-aca"                          }, /* 316 */
  {              0x01,         318, 0,  7, "authenticationInfo"              }, /* 317 */
  {              0x02,         319, 0,  7, "accessIdentity"                  }, /* 318 */
  {              0x03,         320, 0,  7, "chargingIdentity"                }, /* 319 */
  {              0x04,           0, 0,  7, "group"                           }, /* 320 */
  {            0x0B,           322, 0,  6, "subjectInfoAccess"               }, /* 321 */
  {            0x30,             0, 1,  6, "id-ad"                           }, /* 322 */
  {              0x01,         331, 1,  7, "ocsp"                            }, /* 323 */
  {                0x01,       325, 0,  8, "basic"                           }, /* 324 */
  {                0x02,       326, 0,  8, "nonce"                           }, /* 325 */
  {                0x03,       327, 0,  8, "crl"                             }, /* 326 */
  {                0x04,       328, 0,  8, "response"                        }, /* 327 */
  {                0x05,       329, 0,  8, "noCheck"                         }, /* 328 */
  {                0x06,       330, 0,  8, "archiveCutoff"                   }, /* 329 */
  {                0x07,         0, 0,  8, "serviceLocator"                  }, /* 330 */
  {              0x02,         332, 0,  7, "caIssuers"                       }, /* 331 */
  {              0x03,         333, 0,  7, "timeStamping"                    }, /* 332 */
  {              0x05,           0, 0,  7, "caRepository"                    }, /* 333 */
  {          0x08,               0, 1,  5, "ipsec"                           }, /* 334 */
  {            0x02,             0, 1,  6, "certificate"                     }, /* 335 */
  {              0x02,           0, 0,  7, "iKEIntermediate"                 }, /* 336 */
  {  0x0E,                     343, 1,  1, "oiw"                             }, /* 337 */
  {    0x03,                     0, 1,  2, "secsig"                          }, /* 338 */
  {      0x02,                   0, 1,  3, "algorithms"                      }, /* 339 */
  {        0x07,               341, 0,  4, "des-cbc"                         }, /* 340 */
  {        0x1A,               342, 0,  4, "sha-1"                           }, /* 341 */
  {        0x1D,                 0, 0,  4, "sha-1WithRSASignature"           }, /* 342 */
  {  0x24,                     389, 1,  1, "TeleTrusT"                       }, /* 343 */
  {    0x03,                     0, 1,  2, "algorithm"                       }, /* 344 */
  {      0x03,                   0, 1,  3, "signatureAlgorithm"              }, /* 345 */
  {        0x01,               350, 1,  4, "rsaSignature"                    }, /* 346 */
  {          0x02,             348, 0,  5, "rsaSigWithripemd160"             }, /* 347 */
  {          0x03,             349, 0,  5, "rsaSigWithripemd128"             }, /* 348 */
  {          0x04,               0, 0,  5, "rsaSigWithripemd256"             }, /* 349 */
  {        0x02,                 0, 1,  4, "ecSign"                          }, /* 350 */
  {          0x01,             352, 0,  5, "ecSignWithsha1"                  }, /* 351 */
  {          0x02,             353, 0,  5, "ecSignWithripemd160"             }, /* 352 */
  {          0x03,             354, 0,  5, "ecSignWithmd2"                   }, /* 353 */
  {          0x04,             355, 0,  5, "ecSignWithmd5"                   }, /* 354 */
  {          0x05,             372, 1,  5, "ttt-ecg"                         }, /* 355 */
  {            0x01,           360, 1,  6, "fieldType"                       }, /* 356 */
  {              0x01,           0, 1,  7, "characteristictwoField"          }, /* 357 */
  {                0x01,         0, 1,  8, "basisType"                       }, /* 358 */
  {                  0x01,       0, 0,  9, "ipBasis"                         }, /* 359 */
  {            0x02,           362, 1,  6, "keyType"                         }, /* 360 */
  {              0x01,           0, 0,  7, "ecgPublicKey"                    }, /* 361 */
  {            0x03,           363, 0,  6, "curve"                           }, /* 362 */
  {            0x04,           370, 1,  6, "signatures"                      }, /* 363 */
  {              0x01,         365, 0,  7, "ecgdsa-with-RIPEMD160"           }, /* 364 */
  {              0x02,         366, 0,  7, "ecgdsa-with-SHA1"                }, /* 365 */
  {              0x03,         367, 0,  7, "ecgdsa-with-SHA224"              }, /* 366 */
  {              0x04,         368, 0,  7, "ecgdsa-with-SHA256"              }, /* 367 */
  {              0x05,         369, 0,  7, "ecgdsa-with-SHA384"              }, /* 368 */
  {              0x06,           0, 0,  7, "ecgdsa-with-SHA512"              }, /* 369 */
  {            0x05,             0, 1,  6, "module"                          }, /* 370 */
  {              0x01,           0, 0,  7, "1"                               }, /* 371 */
  {          0x08,               0, 1,  5, "ecStdCurvesAndGeneration"        }, /* 372 */
  {            0x01,             0, 1,  6, "ellipticCurve"                   }, /* 373 */
  {              0x01,           0, 1,  7, "versionOne"                      }, /* 374 */
  {                0x01,       376, 0,  8, "brainpoolP160r1"                 }, /* 375 */
  {                0x02,       377, 0,  8, "brainpoolP160t1"                 }, /* 376 */
  {                0x03,       378, 0,  8, "brainpoolP192r1"                 }, /* 377 */
  {                0x04,       379, 0,  8, "brainpoolP192t1"                 }, /* 378 */
  {                0x05,       380, 0,  8, "brainpoolP224r1"                 }, /* 379 */
  {                0x06,       381, 0,  8, "brainpoolP224t1"                 }, /* 380 */
  {                0x07,       382, 0,  8, "brainpoolP256r1"                 }, /* 381 */
  {                0x08,       383, 0,  8, "brainpoolP256t1"                 }, /* 382 */
  {                0x09,       384, 0,  8, "brainpoolP320r1"                 }, /* 383 */
  {                0x0A,       385, 0,  8, "brainpoolP320t1"                 }, /* 384 */
  {                0x0B,       386, 0,  8, "brainpoolP384r1"                 }, /* 385 */
  {                0x0C,       387, 0,  8, "brainpoolP384t1"                 }, /* 386 */
  {                0x0D,       388, 0,  8, "brainpoolP512r1"                 }, /* 387 */
  {                0x0E,         0, 0,  8, "brainpoolP512t1"                 }, /* 388 */
  {  0x65,                     392, 1,  1, "Thawte"                          }, /* 389 */
  {    0x70,                   391, 0,  2, "id-Ed25519"                      }, /* 390 */
  {    0x71,                     0, 0,  2, "id-Ed448"                        }, /* 391 */
  {  0x81,                       0, 1,  1, ""                                }, /* 392 */
  {    0x04,                     0, 1,  2, "Certicom"                        }, /* 393 */
  {      0x00,                   0, 1,  3, "curve"                           }, /* 394 */
  {        0x01,               396, 0,  4, "sect163k1"                       }, /* 395 */
  {        0x02,               397, 0,  4, "sect163r1"                       }, /* 396 */
  {        0x03,               398, 0,  4, "sect239k1"                       }, /* 397 */
  {        0x04,               399, 0,  4, "sect113r1"                       }, /* 398 */
  {        0x05,               400, 0,  4, "sect113r2"                       }, /* 399 */
  {        0x06,               401, 0,  4, "secp112r1"                       }, /* 400 */
  {        0x07,               402, 0,  4, "secp112r2"                       }, /* 401 */
  {        0x08,               403, 0,  4, "secp160r1"                       }, /* 402 */
  {        0x09,               404, 0,  4, "secp160k1"                       }, /* 403 */
  {        0x0A,               405, 0,  4, "secp256k1"                       }, /* 404 */
  {        0x0F,               406, 0,  4, "sect163r2"                       }, /* 405 */
  {        0x10,               407, 0,  4, "sect283k1"                       }, /* 406 */
  {        0x11,               408, 0,  4, "sect283r1"                       }, /* 407 */
  {        0x16,               409, 0,  4, "sect131r1"                       }, /* 408 */
  {        0x17,               410, 0,  4, "sect131r2"                       }, /* 409 */
  {        0x18,               411, 0,  4, "sect193r1"                       }, /* 410 */
  {        0x19,               412, 0,  4, "sect193r2"                       }, /* 411 */
  {        0x1A,               413, 0,  4, "sect233k1"                       }, /* 412 */
  {        0x1B,               414, 0,  4, "sect233r1"                       }, /* 413 */
  {        0x1C,               415, 0,  4, "secp128r1"                       }, /* 414 */
  {        0x1D,               416, 0,  4, "secp128r2"                       }, /* 415 */
  {        0x1E,               417, 0,  4, "secp160r2"                       }, /* 416 */
  {        0x1F,               418, 0,  4, "secp192k1"                       }, /* 417 */
  {        0x20,               419, 0,  4, "secp224k1"                       }, /* 418 */
  {        0x21,               420, 0,  4, "secp224r1"                       }, /* 419 */
  {        0x22,               421, 0,  4, "secp384r1"                       }, /* 420 */
  {        0x23,               422, 0,  4, "secp521r1"                       }, /* 421 */
  {        0x24,               423, 0,  4, "sect409k1"                       }, /* 422 */
  {        0x25,               424, 0,  4, "sect409r1"                       }, /* 423 */
  {        0x26,               425, 0,  4, "sect571k1"                       }, /* 424 */
  {        0x27,                 0, 0,  4, "sect571r1"                       }, /* 425 */
  {0x60,                       489, 1,  0, ""                                }, /* 426 */
  {  0x86,                       0, 1,  1, ""                                }, /* 427 */
  {    0x48,                     0, 1,  2, ""                                }, /* 428 */
  {      0x01,                   0, 1,  3, "organization"                    }, /* 429 */
  {        0x65,               465, 1,  4, "gov"                             }, /* 430 */
  {          0x03,               0, 1,  5, "csor"                            }, /* 431 */
  {            0x04,             0, 1,  6, "nistalgorithm"                   }, /* 432 */
  {              0x01,         443, 1,  7, "aes"                             }, /* 433 */
  {                0x02,       435, 0,  8, "id-aes128-CBC"                   }, /* 434 */
  {                0x06,       436, 0,  8, "id-aes128-GCM"                   }, /* 435 */
  {                0x07,       437, 0,  8, "id-aes128-CCM"                   }, /* 436 */
  {                0x16,       438, 0,  8, "id-aes192-CBC"                   }, /* 437 */
  {                0x1A,       439, 0,  8, "id-aes192-GCM"                   }, /* 438 */
  {                0x1B,       440, 0,  8, "id-aes192-CCM"                   }, /* 439 */
  {                0x2A,       441, 0,  8, "id-aes256-CBC"                   }, /* 440 */
  {                0x2E,       442, 0,  8, "id-aes256-GCM"                   }, /* 441 */
  {                0x2F,         0, 0,  8, "id-aes256-CCM"                   }, /* 442 */
  {              0x02,         456, 1,  7, "hashAlgs"                        }, /* 443 */
  {                0x01,       445, 0,  8, "id-sha256"                       }, /* 444 */
  {                0x02,       446, 0,  8, "id-sha384"                       }, /* 445 */
  {                0x03,       447, 0,  8, "id-sha512"                       }, /* 446 */
  {                0x04,       448, 0,  8, "id-sha224"                       }, /* 447 */
  {                0x05,       449, 0,  8, "id-sha512-224"                   }, /* 448 */
  {                0x06,       450, 0,  8, "id-sha512-256"                   }, /* 449 */
  {                0x07,       451, 0,  8, "id-sha3-224"                     }, /* 450 */
  {                0x08,       452, 0,  8, "id-sha3-256"                     }, /* 451 */
  {                0x09,       453, 0,  8, "id-sha3-384"                     }, /* 452 */
  {                0x0A,       454, 0,  8, "id-sha3-512"                     }, /* 453 */
  {                0x0B,       455, 0,  8, "id-shake128"                     }, /* 454 */
  {                0x0C,         0, 0,  8, "id-shake256"                     }, /* 455 */
  {              0x03,           0, 1,  7, "sigAlgs"                         }, /* 456 */
  {                0x09,       458, 0,  8, "id-ecdsa-with-sha3-224"          }, /* 457 */
  {                0x0A,       459, 0,  8, "id-ecdsa-with-sha3-256"          }, /* 458 */
  {                0x0B,       460, 0,  8, "id-ecdsa-with-sha3-384"          }, /* 459 */
  {                0x0C,       461, 0,  8, "id-ecdsa-with-sha3-512"          }, /* 460 */
  {                0x0D,       462, 0,  8, "id-rsassa-pkcs1v15-with-sha3-224"}, /* 461 */
  {                0x0E,       463, 0,  8, "id-rsassa-pkcs1v15-with-sha3-256"}, /* 462 */
  {                0x0F,       464, 0,  8, "id-rsassa-pkcs1v15-with-sha3-384"}, /* 463 */
  {                0x10,         0, 0,  8, "id-rsassa-pkcs1v15-with-sha3-512"}, /* 464 */
  {        0x86,                 0, 1,  4, ""                                }, /* 465 */
  {          0xf8,               0, 1,  5, ""                                }, /* 466 */
  {            0x42,           479, 1,  6, "netscape"                        }, /* 467 */
  {              0x01,         474, 1,  7, ""                                }, /* 468 */
  {                0x01,       470, 0,  8, "nsCertType"                      }, /* 469 */
  {                0x03,       471, 0,  8, "nsRevocationUrl"                 }, /* 470 */
  {                0x04,       472, 0,  8, "nsCaRevocationUrl"               }, /* 471 */
  {                0x08,       473, 0,  8, "nsCaPolicyUrl"                   }, /* 472 */
  {                0x0d,         0, 0,  8, "nsComment"                       }, /* 473 */
  {              0x03,         477, 1,  7, "directory"                       }, /* 474 */
  {                0x01,         0, 1,  8, ""                                }, /* 475 */
  {                  0x03,       0, 0,  9, "employeeNumber"                  }, /* 476 */
  {              0x04,           0, 1,  7, "policy"                          }, /* 477 */
  {                0x01,         0, 0,  8, "nsSGC"                           }, /* 478 */
  {            0x45,             0, 1,  6, "verisign"                        }, /* 479 */
  {              0x01,           0, 1,  7, "pki"                             }, /* 480 */
  {                0x09,         0, 1,  8, "attributes"                      }, /* 481 */
  {                  0x02,     483, 0,  9, "messageType"                     }, /* 482 */
  {                  0x03,     484, 0,  9, "pkiStatus"                       }, /* 483 */
  {                  0x04,     485, 0,  9, "failInfo"                        }, /* 484 */
  {                  0x05,     486, 0,  9, "senderNonce"                     }, /* 485 */
  {                  0x06,     487, 0,  9, "recipientNonce"                  }, /* 486 */
  {                  0x07,     488, 0,  9, "transID"                         }, /* 487 */
  {                  0x08,       0, 0,  9, "extensionReq"                    }, /* 488 */
  {0x67,                         0, 1,  0, ""                                }, /* 489 */
  {  0x81,                       0, 1,  1, ""                                }, /* 490 */
  {    0x05,                     0, 1,  2, ""                                }, /* 491 */
  {      0x02,                   0, 1,  3, "tcg-attribute"                   }, /* 492 */
  {        0x01,               494, 0,  4, "tcg-at-tpmManufacturer"          }, /* 493 */
  {        0x02,               495, 0,  4, "tcg-at-tpmModel"                 }, /* 494 */
  {        0x03,               496, 0,  4, "tcg-at-tpmVersion"               }, /* 495 */
  {        0x0F,                 0, 0,  4, "tcg-at-tpmIdLabel"               }  /* 496 */
};