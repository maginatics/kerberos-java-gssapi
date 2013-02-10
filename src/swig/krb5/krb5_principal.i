/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5_principal.i - Kerberos SWIG Java wrapper interface file */
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
 * Principal types, from krb5.h
 */

/*
 * Even though this is a complete type, it is allocated via a krb5 routine,
 * so we do not allocate memory for it here.
 */
%nodefaultctor krb5_principal_data;
%nodefaultdtor krb5_principal_data;
%typemap(javacode) struct krb5_principal_data %{
    public krb5_principal_data() {
        this(0, false);
    }
%}

typedef struct krb5_principal_data {
    krb5_magic magic;
    krb5_data realm;
    krb5_data *data;            /**< An array of strings */
    krb5_int32 length;
    krb5_int32 type;
} krb5_principal_data, *krb5_principal;

/*
 * Helpers for marshalling
 */

%{

/*
 * Retrieves principal from java principal handle
 */
static krb5_principal java_principal_to_principal(JNIEnv *jenv,
        jobject java_princ) {
    jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/swig/krb5_principal_data");
    jfieldID fid = (*jenv)->GetFieldID(jenv, clazz, "swigCPtr", "J");
    jlong cPtr = (*jenv)->GetLongField(jenv, java_princ, fid);
    return (krb5_principal)*(&cPtr);
}

/*
 * Stores the principal into the java principal handle
 */
static void principal_to_java_principal(JNIEnv *jenv, jobject java_princ,
        krb5_principal princ) {
    jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/swig/krb5_principal_data");
    jfieldID fid = (*jenv)->GetFieldID(jenv, clazz, "swigCPtr", "J");
    (*jenv)->SetLongField(jenv, java_princ, fid, (jlong)princ);
}

%}

/*
 * Typemaps
 */

/*
 * TYPEMAP:     (krb5_principal *) (native) <--> (krb5_principal_data) (Java)
 * -----------------------------------------------------------------
 * Marshalls krb5_principal *, for output arguments
 */
%typemap(jni) krb5_principal * "jobject"
%typemap(jtype) krb5_principal * "krb5_principal_data"
%typemap(jstype) krb5_principal * "krb5_principal_data"
%typemap(in) krb5_principal * (krb5_principal tmp_pr) {
    /* Convert incomming krb5_principal_data into a native pointer */
    if ($input != NULL) {
        tmp_pr = java_principal_to_principal(jenv, $input);
        $1 = &tmp_pr;
    }
}
%typemap(argout) krb5_principal * {
    /* Output argument conversion back into Java krb5_principal_data */
    if ($input != NULL) {
        principal_to_java_principal(jenv, $input, *$1);
    }
}
%typemap(javain) krb5_principal * "$javainput"
%typemap(javaout) krb5_principal * {
    return $jnicall;
}
