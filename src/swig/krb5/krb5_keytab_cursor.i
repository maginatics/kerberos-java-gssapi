/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5_kt_cursor.i - Kerberos cursor SWIG Java wrapper interface file */
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
 * cursor cursor. Man, this is starting to get repetetive for these
 * output pointer types. Perhaps a macro is in order (TODO).
 */
typedef void * krb5_kt_cursor;

/* Prevent memory allocation */
%nodefaultctor krb5_kt_cursor_handle;
%nodefaultdtor krb5_kt_cursor_handle;
%typemap(javacode) struct krb5_kt_cursor_handle %{
    public krb5_kt_cursor_handle() {
        this(0, false);
    }
%}

%inline %{
typedef struct krb5_kt_cursor_handle {
} krb5_kt_cursor_handle;
%}

/*
 * Helper for krb5_kt_cursor typemaps
 */
%{
/*
 * Retrieves the cursor stored in the java cursor descriptor and returns it.
 */
static krb5_kt_cursor java_cursor_to_cursor(JNIEnv *jenv, jobject java_cursor) {
    jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/swig/krb5_kt_cursor_handle");
    jfieldID fid = (*jenv)->GetFieldID(jenv, clazz, "swigCPtr", "J");
    /* Get pointer to krb5_kt_cursor */
    jlong cPtr = (*jenv)->GetLongField(jenv, java_cursor, fid);
    return (krb5_kt_cursor)*(&cPtr);
}

/*
 * Stores the cursor into the java cursor descriptor.
 */
static void cursor_to_java_cursor(JNIEnv *jenv, jobject java_cursor,
        krb5_kt_cursor kt) {
    jclass clazz = (*jenv)->FindClass(jenv,
            "edu/mit/jgss/swig/krb5_kt_cursor_handle");
    jfieldID fid = (*jenv)->GetFieldID(jenv, clazz, "swigCPtr", "J");
    (*jenv)->SetLongField(jenv, java_cursor, fid, (jlong)kt);
}
%}

/*
 * TYPEMAP:     (krb5_kt_cursor *) (native) <--> (krb5_kt_cursor_handle) (Java)
 * -----------------------------------------------------------------·
 * Marshalls krb5_kt_cursor *, for output arguments
 */
%typemap(jni) krb5_kt_cursor * "jobject"
%typemap(jtype) krb5_kt_cursor * "krb5_kt_cursor_handle"
%typemap(jstype) krb5_kt_cursor * "krb5_kt_cursor_handle"
%typemap(in) krb5_kt_cursor * (krb5_kt_cursor tmp_kt) {
    /* Convert incomming Java krb5_kt_cursor_handle to a native krb5_kt_cursor ptr */
    if ($input != NULL) {
        tmp_kt = java_cursor_to_cursor(jenv, $input);
        $1 = &tmp_kt;
    }
}
%typemap(argout) krb5_kt_cursor * {
    /* Output argument conversion back into Java krb5_kt_cursor_handle */
    if ($input != NULL) {
        cursor_to_java_cursor(jenv, $input, *$1);
    }
}
%typemap(javain) krb5_kt_cursor * "$javainput"
%typemap(javaout) krb5_kt_cursor * {
    return $jnicall;
}

/*
 * TYPEMAP:     (krb5_kt_cursor) (native) <--> (krb5_kt_cursor_handle) (Java)
 * -----------------------------------------------------------------
 * Marhalls krb5_kt_cursor, for input arguments
 */
%typemap(jni) krb5_kt_cursor "jobject"
%typemap(jtype) krb5_kt_cursor "krb5_kt_cursor_handle"
%typemap(jstype) krb5_kt_cursor "krb5_kt_cursor_handle"
%typemap(in) krb5_kt_cursor {
    if ($input != NULL) {
        $1 = java_cursor_to_cursor(jenv, $input);
    }
}
%typemap(javain) krb5_kt_cursor "$javainput"
%typemap(javaout) krb5_kt_cursor {
    return $jnicall;
}
