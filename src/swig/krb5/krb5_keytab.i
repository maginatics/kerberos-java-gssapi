/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5_keytab.i - Kerberos keytab SWIG Java wrapper interface file */
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
 * Keytab types
 *
 * The keytab is an opaque structure. We define krb5_keytab_handle
 * as a dummy structure to facilitate marshalling output parameters.
 */
typedef struct _krb5_kt *krb5_keytab;

/* Prevent memory allocation */
%nodefaultctor krb5_keytab_handle;
%nodefaultdtor krb5_keytab_handle;
%typemap(javacode) struct krb5_keytab_handle %{
    public krb5_keytab_handle() {
        this(0, false);
    }
%}

%inline %{
typedef struct krb5_keytab_handle {
} krb5_keytab_handle;
%}

/* Needed for keytab iteration */
#define KRB5_KT_END (-1765328202L)

/*
 * Helper for krb5_keytab typemaps
 */
%{
/*
 * Retrieves the keytab stored in the java keytab descriptor and returns it.
 */
static krb5_keytab java_keytab_to_keytab(JNIEnv *jenv, jobject java_keytab) {
    jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/swig/krb5_keytab_handle");
    jfieldID fid = (*jenv)->GetFieldID(jenv, clazz, "swigCPtr", "J");
    /* Get pointer to krb5_keytab */
    jlong cPtr = (*jenv)->GetLongField(jenv, java_keytab, fid);
    return (krb5_keytab)*(&cPtr);
}

/*
 * Stores the keytab into the java keytab descriptor.
 */
static void keytab_to_java_keytab(JNIEnv *jenv, jobject java_keytab,
        krb5_keytab kt) {
    jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/swig/krb5_keytab_handle");
    jfieldID fid = (*jenv)->GetFieldID(jenv, clazz, "swigCPtr", "J");
    (*jenv)->SetLongField(jenv, java_keytab, fid, (jlong)kt);
}
%}

/*
 * TYPEMAP:     (krb5_keytab *) (native) <--> (krb5_keytab_handle) (Java)
 * -----------------------------------------------------------------·
 * Marshalls krb5_keytab *, for output arguments
 */
%typemap(jni) krb5_keytab * "jobject"
%typemap(jtype) krb5_keytab * "krb5_keytab_handle"
%typemap(jstype) krb5_keytab * "krb5_keytab_handle"
%typemap(in) krb5_keytab * (krb5_keytab tmp_kt) {
    /* Convert incomming Java krb5_keytab_handle to a native krb5_keytab ptr */
    if ($input != NULL) {
        tmp_kt = java_keytab_to_keytab(jenv, $input);
        $1 = &tmp_kt;
    }
}
%typemap(argout) krb5_keytab * {
    /* Output argument conversion back into Java krb5_keytab_handle */
    if ($input != NULL) {
        keytab_to_java_keytab(jenv, $input, *$1);
    }
}
%typemap(javain) krb5_keytab * "$javainput"
%typemap(javaout) krb5_keytab * {
    return $jnicall;
}

/*
 * TYPEMAP:     (krb5_keytab) (native) <--> (krb5_keytab_handle) (Java)
 * -----------------------------------------------------------------
 * Marhalls krb5_keytab, for input arguments
 */
%typemap(jni) krb5_keytab "jobject"
%typemap(jtype) krb5_keytab "krb5_keytab_handle"
%typemap(jstype) krb5_keytab "krb5_keytab_handle"
%typemap(in) krb5_keytab {
    if ($input != NULL) {
        $1 = java_keytab_to_keytab(jenv, $input);
    }
}
%typemap(javain) krb5_keytab "$javainput"
%typemap(javaout) krb5_keytab {
    return $jnicall;
}

/* Some secondary types */
%include "src/swig/krb5/krb5_keytab_cursor.i"
%include "src/swig/krb5/krb5_keytab_entry.i"
