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

#include <sapi/tpm20.h>

TPM2_RC tpm_readpublic(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public, TPM2B_NAME *name);
TPM2_RC tpm_rsa_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hashLength, TPMT_SIGNATURE *signature);
TPM2_RC tpm_ecc_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hashLength, TPMT_SIGNATURE *signature);
TPM2_RC tpm_verify(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPMT_SIGNATURE *signature, unsigned char *hash, unsigned long hashLength);
TPM2_RC tpm_rsa_decrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *cipherText, unsigned long cipherLength, TPM2B_PUBLIC_KEY_RSA *message);
TPM2_RC tpm_rsa_encrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *data, unsigned long dataLength, TPM2B_PUBLIC_KEY_RSA *message);
TPM2_RC tpm_list(TSS2_SYS_CONTEXT *context, TPMS_CAPABILITY_DATA* capabilityData);
