/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5_keyblock.i - Kerberos SWIG Java wrapper interface file */
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
 * Keyblock types
 */

/*
 * Extreme contortions: get keyblock contents as a byte[] via extend
 * and convoluted typemap
 */

%typemap(jni) krb5_octet* getKey "jbyteArray"
%typemap(jtype) krb5_octet* getKey "byte[]"
%typemap(jstype) krb5_octet* getKey "byte[]"
%typemap(javaout) krb5_octet* getKey {
    return $jnicall;
}
%typemap(in, numinputs=0, noblock=1) (unsigned int *outlen) {
    unsigned int tmplen = 0;
    $1 = &tmplen;
}
%typemap(out) krb5_octet* getKey {
    $result = (*jenv)->NewByteArray(jenv, tmplen);
    (*jenv)->SetByteArrayRegion(jenv, $result, 0, tmplen, $1);
}

/* Hide the original getContents */
%javamethodmodifiers _krb5_keyblock::contents "private";

typedef unsigned char krb5_octet;
typedef struct _krb5_keyblock {
    krb5_magic magic;
    krb5_enctype enctype;
    unsigned int length;
    krb5_octet *contents;
} krb5_keyblock;

/* Key accessor as a byte[] */
%extend krb5_keyblock {
    krb5_octet *getKey(unsigned int *outlen) {
        *outlen = $self->length;
        return $self->contents;
    }
}
