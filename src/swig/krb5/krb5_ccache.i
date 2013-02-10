/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5_ccache.i - Kerberos SWIG Java wrapper interface file */
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
 * Credentials cache types
 *
 * The ccache is an opaque structure. We define krb5_ccache_handle
 * as a dummy structure to facilitate marshalling output parameters.
 */

typedef struct _krb5_ccache *krb5_ccache;

/* Prevent memory allocation */
%nodefaultctor krb5_ccache_handle;
%nodefaultdtor krb5_ccache_handle;
%typemap(javacode) struct krb5_ccache_handle %{
    public krb5_ccache_handle() {
        this(0, false);
    }
%}

%inline %{
typedef struct krb5_ccache_handle {
} krb5_ccache_handle;
%}

/*
 * Helpers for marshalling
 */

%{

/*
 * Retrieves ccache from java ccache handle
 */
static krb5_ccache java_ccache_to_ccache(JNIEnv *jenv, jobject java_ccache) {
    jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/swig/krb5_ccache_handle");
    jfieldID fid = (*jenv)->GetFieldID(jenv, clazz, "swigCPtr", "J");
    jlong cPtr = (*jenv)->GetLongField(jenv, java_ccache, fid);
    return (krb5_ccache)*(&cPtr);
}

/*
 * Stores the ccache into the java ccache handle
 */
static void ccache_to_java_ccache(JNIEnv *jenv, jobject java_ccache,
        krb5_ccache ccache) {
    jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/swig/krb5_ccache_handle");
    jfieldID fid = (*jenv)->GetFieldID(jenv, clazz, "swigCPtr", "J");
    (*jenv)->SetLongField(jenv, java_ccache, fid, (jlong)ccache);
}

%}

/*
 * Typemaps
 */

/*
 * TYPEMAP:     (krb5_ccache) (native) <- (krb5_ccache_handle) (Java)
 * -----------------------------------------------------------------
 * Input typemap for passing krb5_ccache_handle into the native code
 */
%typemap(jni) krb5_ccache "jobject"
%typemap(jtype) krb5_ccache "krb5_ccache_handle"
%typemap(jstype) krb5_ccache "krb5_ccache_handle"
%typemap(in) krb5_ccache {
    if ($input != NULL) {
        $1 = java_ccache_to_ccache(jenv, $input);
    }
}
%typemap(javain) krb5_ccache "$javainput"
%typemap(javaout) krb5_ccache {
    return $jnicall;
}

/*
 * TYPEMAP:     (krb5_ccache *) (native) <--> (krb5_ccache_handle) (Java)
 * -----------------------------------------------------------------
 * Marshalls krb5_ccache *, for output arguments
 */
%typemap(jni) krb5_ccache * "jobject"
%typemap(jtype) krb5_ccache * "krb5_ccache_handle"
%typemap(jstype) krb5_ccache * "krb5_ccache_handle"
%typemap(in) krb5_ccache * (krb5_ccache tmp_cc) {
    /* Convert incomming krb5_ccache_handle into a native pointer */
    if ($input != NULL) {
        tmp_cc = java_ccache_to_ccache(jenv, $input);
        $1 = &tmp_cc;
    }
}
%typemap(argout) krb5_ccache * {
    /* Output argument conversion back into Java krb5_ccache_handle */
    if ($input != NULL) {
        ccache_to_java_ccache(jenv, $input, *$1);
    }
}
%typemap(javain) krb5_ccache * "$javainput"
%typemap(javaout) krb5_ccache * {
    return $jnicall;
}
