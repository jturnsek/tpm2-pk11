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

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti.h>
#ifdef TCTI_DEVICE_ENABLED
#include <tss2/tss2_tcti_device.h>
#endif
#ifdef TCTI_MSSIM_ENABLED
#include <tss2/tss2_tcti_mssim.h>
#endif
#ifdef TCTI_TABRMD_ENABLED
#include <tss2/tss2-tcti-tabrmd.h>
#endif

#define TPM_DEFAULT_EK_HANDLE 		0x81010000
#define TPM_MAX_NUM_OF_AK_HANDLES	8

TPM2_RC tpm_generate_key_pair(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle_ak, TPM2_ALG_ID algorithm, TPM2B_PUBLIC *public, TPM2B_NAME *name);
TPM2_RC tpm_read_public(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPM2B_PUBLIC *public, TPM2B_NAME *name);
TPM2_RC tpm_rsa_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature);
TPM2_RC tpm_ecc_sign(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *hash, unsigned long hash_length, TPMT_SIGNATURE *signature);
TPM2_RC tpm_verify(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, TPMT_SIGNATURE *signature, unsigned char *hash, unsigned long hash_length);
TPM2_RC tpm_rsa_decrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *cipher_text, unsigned long cipher_length, TPM2B_PUBLIC_KEY_RSA *message);
TPM2_RC tpm_rsa_encrypt(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT handle, unsigned char *data, unsigned long data_length, TPM2B_PUBLIC_KEY_RSA *message);
TPM2_RC tpm_evict_control(TSS2_SYS_CONTEXT *context, TPMI_DH_OBJECT object);
TPM2_RC tpm_info(TSS2_SYS_CONTEXT *context, UINT32 property, TPMS_CAPABILITY_DATA* capability_data);
TPMS_TAGGED_PROPERTY* tpm_info_get(TPMS_TAGGED_PROPERTY properties[], size_t count, TPM2_PT key);

#endif /** TPM_H_ */
