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

package edu.mit.jgss.krb5;

import edu.mit.jgss.swig.gsswrapper;
import edu.mit.jgss.swig.krb5_context_handle;
import edu.mit.jgss.swig.krb5_ccache_handle;
import edu.mit.jgss.swig.krb5_keytab_handle;

/**
 * Container for libkrb5 credentials (library context, ccache, etc.)
 */
public final class KerberosCredentials {
    /** Library context. */
    private final krb5_context_handle context;

    /** Credentials cache. */
    private final krb5_ccache_handle ccache;

    /** Keytab handle. */
    private final krb5_keytab_handle keytab;

    /**
     * Create a credentials object.
     *
     * @param context the libkrb5 context
     * @param ccache the credentials cache
     */
    public KerberosCredentials(krb5_context_handle context,
            krb5_ccache_handle ccache, krb5_keytab_handle keytab) {
        this.context = context;
        this.ccache = ccache;
        this.keytab = keytab;
    }

    public krb5_context_handle getContext() {
        return context;
    }

    public krb5_ccache_handle getCcache() {
        return ccache;
    }

    public krb5_keytab_handle getKeytab() {
        return keytab;
    }

    /*
     * Release JNI resources.
     */
    protected void finalize() throws Throwable {
        if (ccache != null && context != null) {
            gsswrapper.krb5_cc_destroy(context, ccache);
        }
        if (keytab != null && context != null) {
            gsswrapper.krb5_kt_close(context, keytab);
        }
        if (context != null) {
            gsswrapper.krb5_free_context(context);
        }
    }
}
