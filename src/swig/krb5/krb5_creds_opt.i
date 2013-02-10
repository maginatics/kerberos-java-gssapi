/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5_creds_opt.i - Kerberos SWIG Java wrapper interface file */
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
 * Init creds options types.
 */

/*
 * Even though this type is fully defined, it must be allocated
 * using a krb5 method, so we use our standard handle trick.
 */

%nodefaultctor _krb5_get_init_creds_opt;
%nodefaultdtor _krb5_get_init_creds_opt;
%typemap(javacode) struct _krb5_get_init_creds_opt %{
    public krb5_get_init_creds_opt() {
        this(0, false);
    }
%}

typedef struct _krb5_get_init_creds_opt {
    krb5_flags flags;
    krb5_deltat tkt_life;
    krb5_deltat renew_life;
    int forwardable;
    int proxiable;
    krb5_enctype *etype_list;
    int etype_list_length;
    krb5_address **address_list;
    krb5_preauthtype *preauth_list;
    int preauth_list_length;
    krb5_data *salt;
} krb5_get_init_creds_opt;

/*
 * Helpers for marshalling
 */

%{

/*
 * Get a krb5_get_init_creds_opt * from the Java struct
 */
static krb5_get_init_creds_opt *java_ico_to_icop(JNIEnv *jenv,
        jobject java_ico) {
    jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/swig/krb5_get_init_creds_opt");
    jfieldID fid = (*jenv)->GetFieldID(jenv, clazz, "swigCPtr", "J");
    jlong cPtr = (*jenv)->GetLongField(jenv, java_ico, fid);
    return (krb5_get_init_creds_opt *)*(&cPtr);
}

/*
 * Stores the creds_opt pointer into the java creds opt object
 */
static void icop_to_java_ico(JNIEnv *jenv, jobject java_ico,
        krb5_get_init_creds_opt *icop) {
    jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/swig/krb5_get_init_creds_opt");
    jfieldID fid = (*jenv)->GetFieldID(jenv, clazz, "swigCPtr", "J");
    (*jenv)->SetLongField(jenv, java_ico, fid, (jlong)icop);
}

%}

/*
 * Typemaps
 */

/*
 * TYPEMAP:     (krb5_init_creds_opt **) (native) <-->
 *              (krb5_init_creds_handle) (Java)
 * -----------------------------------------------------------------
 * Marshalls krb5_init_creds_opt **, for output arguments
 */
%typemap(jni) krb5_get_init_creds_opt ** "jobject"
%typemap(jtype) krb5_get_init_creds_opt ** "krb5_get_init_creds_opt"
%typemap(jstype) krb5_get_init_creds_opt ** "krb5_get_init_creds_opt"
%typemap(in) krb5_get_init_creds_opt ** (krb5_get_init_creds_opt *tmp_ptr) {
    /* Convert incomming krb5_get_init_creds_opt into a native pointer */
    if ($input != NULL) {
        tmp_ptr = java_ico_to_icop(jenv, $input);
        $1 = &tmp_ptr;
    }
}
%typemap(argout) krb5_get_init_creds_opt ** {
    /* Output argument conversion back into Java krb5_get_init_creds_opt */
    if ($input != NULL) {
        icop_to_java_ico(jenv, $input, *$1);
    }
}
%typemap(javain) krb5_get_init_creds_opt ** "$javainput"
%typemap(javaout) krb5_get_init_creds_opt ** {
    return $jnicall;
}
