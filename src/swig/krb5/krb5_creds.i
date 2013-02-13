/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5_creds.i - Kerberos SWIG Java wrapper interface file */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This file should not be processed by SWIG directly, but should be
 * included from the top-level krb5.i interface definition file.
 */

/*
 * Ticket flags
 */
#define TKT_FLG_FORWARDABLE             0x40000000
#define TKT_FLG_FORWARDED               0x20000000
#define TKT_FLG_PROXIABLE               0x10000000
#define TKT_FLG_PROXY                   0x08000000
#define TKT_FLG_MAY_POSTDATE            0x04000000
#define TKT_FLG_POSTDATED               0x02000000
#define TKT_FLG_INVALID                 0x01000000
#define TKT_FLG_RENEWABLE               0x00800000
#define TKT_FLG_INITIAL                 0x00400000
#define TKT_FLG_PRE_AUTH                0x00200000
#define TKT_FLG_HW_AUTH                 0x00100000
#define TKT_FLG_TRANSIT_POLICY_CHECKED  0x00080000
#define TKT_FLG_OK_AS_DELEGATE          0x00040000
#define TKT_FLG_ENC_PA_REP              0x00010000
#define TKT_FLG_ANONYMOUS               0x00008000

/*
 * Credentials type
 */
typedef krb5_int32 krb5_flags;
typedef struct _krb5_creds {
    krb5_magic magic;
    krb5_principal client;              /**< client's principal identifier */
    krb5_principal server;              /**< server's principal identifier */
    krb5_keyblock keyblock;             /**< session encryption key info */
    krb5_ticket_times times;            /**< lifetime info */
    krb5_boolean is_skey;               /**< true if ticket is encrypted in
                                           another ticket's skey */
    krb5_flags ticket_flags;            /**< flags in ticket */
    krb5_address **addresses;           /**< addrs in ticket */
    krb5_data ticket;                   /**< ticket string itself */
    krb5_data second_ticket;            /**< second ticket, if related to
                                           ticket (via DUPLICATE-SKEY or
                                           ENC-TKT-IN-SKEY) */
    krb5_authdata **authdata;           /**< authorization data */
} krb5_creds;
