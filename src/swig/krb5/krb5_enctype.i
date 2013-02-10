/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* krb5_enctype.i - Kerberos SWIG Java wrapper interface file */
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
 * Enctype types.
 */

typedef int32_t krb5_enctype;

/*
 * Enctypes defined in krb5.h
 */

%javaconst(1);
#define ENCTYPE_NULL            0x0000
#define ENCTYPE_DES_CBC_CRC     0x0001  /**< DES cbc mode with CRC-32 */
#define ENCTYPE_DES_CBC_MD4     0x0002  /**< DES cbc mode with RSA-MD4 */
#define ENCTYPE_DES_CBC_MD5     0x0003  /**< DES cbc mode with RSA-MD5 */
#define ENCTYPE_DES_CBC_RAW     0x0004  /**< @deprecated DES cbc mode raw */
#define ENCTYPE_DES3_CBC_SHA    0x0005  /**< @deprecated DES-3 cbc with SHA1 */
#define ENCTYPE_DES3_CBC_RAW    0x0006  /**< @deprecated DES-3 cbc mode raw */
#define ENCTYPE_DES_HMAC_SHA1   0x0008  /**< @deprecated */
#define ENCTYPE_DSA_SHA1_CMS    0x0009  /**< DSA with SHA1, CMS signature */
#define ENCTYPE_MD5_RSA_CMS     0x000a  /**< MD5 with RSA, CMS signature */
#define ENCTYPE_SHA1_RSA_CMS    0x000b  /**< SHA1 with RSA, CMS signature */
#define ENCTYPE_RC2_CBC_ENV     0x000c  /**< RC2 cbc mode, CMS enveloped data */
#define ENCTYPE_RSA_ENV         0x000d  /**< RSA encryption, CMS enveloped data */
#define ENCTYPE_RSA_ES_OAEP_ENV 0x000e  /**< RSA w/OEAP encryption, CMS enveloped data */
#define ENCTYPE_DES3_CBC_ENV    0x000f  /**< DES-3 cbc mode, CMS enveloped data */
#define ENCTYPE_DES3_CBC_SHA1           0x0010
#define ENCTYPE_AES128_CTS_HMAC_SHA1_96 0x0011 /**< RFC 3962 */
#define ENCTYPE_AES256_CTS_HMAC_SHA1_96 0x0012 /**< RFC 3962 */
#define ENCTYPE_ARCFOUR_HMAC            0x0017
#define ENCTYPE_ARCFOUR_HMAC_EXP        0x0018
#define ENCTYPE_UNKNOWN                 0x01ff
%javaconst(0);

/*
 * TYPEMAP:     (int len, krb5_enctype *) (native) <--> int[] (Java)
 * -----------------------------------------------------------------·
 * Marshalls krb5_enctype arrays
 */
%typemap(in) (int LENGTH, krb5_enctype *VALUES) {
    /* Convert incomming Java int[] to a native krb5_enctype array */
    $2 = NULL;
    if ($input != NULL) {
        int i;
        /* Get the Java array's internal memory */
        const int* nativeArray = (int *)
            (*jenv)->GetIntArrayElements(jenv, $input, NULL);
        /* Length */
        $1 = (*jenv)->GetArrayLength(jenv, $input);
        if ($1 > 0) {
            /* Allocate and copy */
            $2 = (krb5_enctype *) malloc($1 * sizeof(krb5_enctype));
            for (i = 0; i < $1; ++i) {
                $2[i] = nativeArray[i];
            }
        }
        /* Release the Java int[] */
        (*jenv)->ReleaseIntArrayElements(jenv, $input, nativeArray, JNI_ABORT);
    }
}
%typemap(freearg) (int LENGTH, krb5_enctype *VALUES) {
    /* Release memory allocated while marshalling a Java array */
    free($2);
}
%typemap(jni) (int LENGTH, krb5_enctype *VALUES) "jintArray"
%typemap(jtype) (int LENGTH, krb5_enctype *VALUES) "int[]"
%typemap(jstype) (int LENGTH, krb5_enctype *VALUES) "int[]"
%typemap(javain) (int LENGTH, krb5_enctype *VALUES) "$javainput"
/* Apply to methods that match this signature */
%apply (int LENGTH, krb5_enctype *VALUES) {
    (OM_uint32 nEnctypes, krb5_enctype *enctypes) }
