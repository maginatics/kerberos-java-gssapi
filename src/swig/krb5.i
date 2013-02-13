/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5.i - Kerberos SWIG Java wrapper interface file */
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
 * Partial interface definitions for MIT Kerberos, pulled in from krb5.h
 *
 * Original source developed by Maginatics (http://www.maginatics.com)
 */

typedef int krb5_int32;
typedef krb5_int32 krb5_error_code;
typedef krb5_int32 krb5_deltat;

/*
 * Type definitions and typemaps
 */
%include "src/swig/krb5/krb5_ccache.i"
%include "src/swig/krb5/krb5_context.i"
%include "src/swig/krb5/krb5_creds.i"
%include "src/swig/krb5/krb5_creds_opt.i"
%include "src/swig/krb5/krb5_data.i"
%include "src/swig/krb5/krb5_enctype.i"
%include "src/swig/krb5/krb5_keyblock.i"
%include "src/swig/krb5/krb5_keytab.i"
%include "src/swig/krb5/krb5_ticket_times.i"
%include "src/swig/krb5/krb5_principal.i"
%include "src/swig/krb5/krb5_prompter.i"

/*
 * Interface methods that throw exceptions on failure
 */

%javaexception("edu.mit.jgss.krb5.LibKrb5Exception") {
    $action
    if (result != 0) {
        jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/krb5/LibKrb5Exception");
        jmethodID constructor = (*jenv)->GetMethodID(jenv, clazz, "<init>",
                "(I)V");
        jobject ex = (*jenv)->NewObject(jenv, clazz, constructor, result);
        (*jenv)->Throw(jenv, ex);
        return $null;
    }
}

/* Import the exception definition */
%pragma(java) moduleimports=%{
import edu.mit.jgss.krb5.LibKrb5Exception;
%}

krb5_error_code KRB5_CALLCONV
krb5_init_context(krb5_context *);

krb5_error_code KRB5_CALLCONV
krb5_parse_name(krb5_context,
                const char *INPUT,
                krb5_principal *);

krb5_error_code KRB5_CALLCONV
krb5_kt_resolve(krb5_context,
                const char *INPUT,
                krb5_keytab *);

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_keytab(krb5_context,
                           krb5_creds *,
                           krb5_principal,
                           krb5_keytab,
                           krb5_deltat,
                           char *INPUT,
                           krb5_get_init_creds_opt *);

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_password(krb5_context,
                             krb5_creds *,
                             krb5_principal client,
                             char *INPUT,
                             krb5_prompter_fct,
                             void *,
                             krb5_deltat,
                             char *,
                             krb5_get_init_creds_opt *);

krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_opt_alloc(krb5_context context,
                              krb5_get_init_creds_opt **opt);

krb5_error_code KRB5_CALLCONV
krb5_cc_new_unique(krb5_context,
                   const char *INPUT,
                   const char *INPUT,
                   krb5_ccache *);

krb5_error_code KRB5_CALLCONV
krb5_cc_initialize(krb5_context,
                   krb5_ccache,
                   krb5_principal);

krb5_error_code KRB5_CALLCONV
krb5_cc_store_cred(krb5_context,
                   krb5_ccache,
                   krb5_creds *);

/*
 * Clear the above handler
 */
%clearjavaexception;

/*
 * Interface methods that cannot fail (and consequently don't throw
 * exceptions). Note that it is an artifact of the way that SWIG allows
 * exception specifications (as far as I can tell, anyway) that forces
 * us to separate these).
 */

void KRB5_CALLCONV
krb5_free_context(krb5_context);

void KRB5_CALLCONV
krb5_free_principal(krb5_context,
                    krb5_principal);

void KRB5_CALLCONV
krb5_get_init_creds_opt_free(krb5_context context,
                             krb5_get_init_creds_opt *opt);

void KRB5_CALLCONV
krb5_get_init_creds_opt_set_renew_life(krb5_get_init_creds_opt *opt,
                                       krb5_deltat renew_life);

/* Not interested in exceptions being thrown here. */
krb5_error_code KRB5_CALLCONV
krb5_kt_close(krb5_context context,
              krb5_keytab keytab);

/* Likewise */
krb5_error_code KRB5_CALLCONV
krb5_cc_destroy(krb5_context,
                krb5_ccache);
