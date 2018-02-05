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

#ifndef TPM_H_
#define TPM_H_

#include <sapi/tpm20.h>

TPM2_RC tpm_generate_key_pair(TSS2_SYS_CONTEXT *sapi_context, TPM2B_PUBLIC *public, TPM2B_NAME *name, TPMI_DH_OBJECT *persistent);
TPM2_RC tpm_read_public(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public, TPM2B_NAME *name);
TPM2_RC tpm_rsa_sign(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature);
TPM2_RC tpm_ecc_sign(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature);
TPM2_RC tpm_verify(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, TPMT_SIGNATURE *signature, unsigned char *hash, unsigned long hash_length);
TPM2_RC tpm_rsa_decrypt(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, unsigned char *cipher_text, unsigned long cipher_length, TPM2B_PUBLIC_KEY_RSA *message);
TPM2_RC tpm_rsa_encrypt(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT handle, unsigned char *data, unsigned long data_length, TPM2B_PUBLIC_KEY_RSA *message);
TPM2_RC tpm_list(TSS2_SYS_CONTEXT *sapi_context, TPMS_CAPABILITY_DATA* capability_data);

#endif /** TPM_H_ */
