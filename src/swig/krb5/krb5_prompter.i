/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5_prompter.i - Kerberos keytab SWIG Java wrapper interface file */
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
 * Infuriatingly, we need a type here for this unused callback,
 * because Swig doesn't treat function pointers the same way
 * it does other pointers.
 */

/* Prevent memory allocation */
%nodefaultctor krb5_dummy_prompter;
%nodefaultdtor krb5_dummy_prompter;
%typemap(javacode) struct krb5_dummy_prompter %{
    public krb5_dummy_prompter() {
        this(0, false);
    }
%}

%inline %{
typedef struct krb5_dummy_prompter {} krb5_dummy_prompter;
%}

/*
 * Input typemap
 */
%typemap(jni) krb5_prompter_fct "jobject"
%typemap(jtype) krb5_prompter_fct "krb5_dummy_prompter"
%typemap(jstype) krb5_prompter_fct "krb5_dummy_prompter"
%typemap(in) krb5_prompter_fct {
    /* Just pass null */
    $1 = 0;
}
%typemap(javain) krb5_prompter_fct "$javainput"
%typemap(javaout) krb5_prompter_fct {
    return $jnicall;
}
