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

#ifndef SESSIONS_H_
#define SESSIONS_H_

#include "config.h"
#include "objects.h"

#include <stdbool.h>
#include <sapi/tpm20.h>
#include <p11-kit/pkcs11.h>


struct token {
	TSS2_SYS_CONTEXT *sapi_context;
  pObjectList objects;
};

struct session {
  TPMI_DH_OBJECT handle;
  pObjectList find_cursor;
  CK_ATTRIBUTE_PTR filters;
  size_t num_filters;
  pObject current_object;
  CK_MECHANISM_TYPE mechanism;
};

int token_init(struct token* token, struct config *config);
void token_close(struct token* token);
int session_init(struct session* session);
void session_close(struct session* session);

#endif /** SESSIONS_H_ */
