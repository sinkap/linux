/*
 * Kernel Runtime Security Instrumentation (KRSI) LSM
 *
 * Author: KP Singh <kpsingh@google.com>
 *
 * Copyright (C) 2019 Google Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * Description:
 *
 * The hooks for the KRSI LSM are declared in this file.
 *
 * This header MUST NOT be included directly and should
 * be only used to initialize the hooks lists.
 *
 * Format:
 *
 *   KRSI_HOOK_INIT(TYPE, LSM_HOOK, KRSI_HOOK_FN)
 */
KRSI_HOOK_INIT(BPRM_CHECK_SECURITY, bprm_check_security,
	       krsi_bprm_check_security)
