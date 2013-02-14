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
package edu.mit.jgss;

import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.security.auth.Subject;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import org.ietf.jgss.GSSName;

import edu.mit.jgss.krb5.KerberosCredentials;
import edu.mit.jgss.swig.*;

public class GSSCredentialImpl implements GSSCredential {

    /* representing our underlying SWIG-wrapped gss_cred_id_t object */
    private gss_cred_id_t_desc internGSSCred = new gss_cred_id_t_desc();

    /* has this cred been destroyed? */
    private boolean invalid = false;

    public void dispose() throws GSSException {

        if (!invalid) {
            long[] min_status = {0};
            long ret = 0;

            ret = gsswrapper.gss_release_cred(min_status, this.internGSSCred);

            if (ret != gsswrapper.GSS_S_COMPLETE) {
                throw new GSSExceptionImpl(0, (int) min_status[0]);
            }
            this.invalid = true;
        }

    }

    public GSSName getName() throws GSSException {

        long maj_status = 0;
        long[] min_status = {0};
        long[] lifetime = {0};
        int[] cred_usage = {0};
        int ret = 0;
        gss_name_t_desc name = new gss_name_t_desc();
        gss_OID_set_desc temp_mech_set = new gss_OID_set_desc();

        if(invalid) {
            throw new GSSException((int) gsswrapper.GSS_S_DEFECTIVE_CREDENTIAL,
                    0, "credential has been disposed, no longer valid");
        }

        GSSNameImpl tmpName = new GSSNameImpl();

        maj_status = gsswrapper.gss_inquire_cred(min_status,
                this.internGSSCred, name, lifetime, cred_usage,
                temp_mech_set);

        if (maj_status != gsswrapper.GSS_S_COMPLETE) {
            throw new GSSExceptionImpl((int) maj_status, (int) min_status[0]);
        }

        ret = tmpName.setInternGSSName(name);
        if (ret != 0) {
            throw new GSSExceptionImpl((int) maj_status, (int) min_status[0]);
        }

        return tmpName;

    }

    public GSSName getName(Oid mechOID) throws GSSException {

        if(invalid) {
            throw new GSSException((int)gsswrapper.GSS_S_DEFECTIVE_CREDENTIAL,
                    0, "credential has been disposed, no longer valid");
        }

        GSSName name = getName();
        GSSName canoniName = name.canonicalize(mechOID);

        return canoniName;
    }

    public int getRemainingLifetime() throws GSSException {

        long maj_status = 0;
        long[] min_status = {0};
        long[] lifetime = {0};
        int[] cred_usage = {0};
        gss_name_t_desc name = new gss_name_t_desc();
        gss_OID_set_desc temp_mech_set = new gss_OID_set_desc();

        if(invalid) {
            throw new GSSException((int) gsswrapper.GSS_S_DEFECTIVE_CREDENTIAL,
                    0, "credential has been disposed, no longer valid");
        }

        maj_status = gsswrapper.gss_inquire_cred(min_status,
                this.internGSSCred, name, lifetime, cred_usage,
                temp_mech_set);

        if (maj_status != gsswrapper.GSS_S_COMPLETE) {
            throw new GSSExceptionImpl((int) maj_status, (int) min_status[0]);
        }

        /* check for native INDEFINITE_LIFETIME and convert to Java
           RFC version (Integer.MAX_VALUE) */
        if (lifetime[0] == 4294967295L)
            return GSSCredential.INDEFINITE_LIFETIME;
        return (int)lifetime[0];

    }

    public int getRemainingInitLifetime(Oid mech) throws GSSException {

        long maj_status = 0;
        long[] min_status = {0};
        long[] init_lifetime = {0};
        long[] accept_lifetime = {0};
        int[] cred_usage = {0};
        gss_name_t_desc name = new gss_name_t_desc();

        if(invalid) {
            throw new GSSException((int) gsswrapper.GSS_S_DEFECTIVE_CREDENTIAL,
                    0, "credential has been disposed, no longer valid");
        }

        maj_status = gsswrapper.gss_inquire_cred_by_mech(min_status,
                this.internGSSCred, mech.getNativeOid(), name, init_lifetime,
                accept_lifetime, cred_usage);

        if (maj_status != gsswrapper.GSS_S_COMPLETE) {
            throw new GSSExceptionImpl((int) maj_status, (int) min_status[0]);
        }

        if (cred_usage[0] == GSSCredential.INITIATE_ONLY ||
            cred_usage[0] == GSSCredential.INITIATE_AND_ACCEPT) {

            /* check for native INDEFINITE_LIFETIME and convert to Java
               RFC version (Integer.MAX_VALUE) */
            if (init_lifetime[0] == 4294967295L)
                return GSSCredential.INDEFINITE_LIFETIME;
            return (int)init_lifetime[0];
        } else {
            return 0;
        }
    }

    public int getRemainingAcceptLifetime(Oid mech) throws GSSException {

        long maj_status = 0;
        long[] min_status = {0};
        long[] init_lifetime = {0};
        long[] accept_lifetime = {0};
        int[] cred_usage = {0};
        gss_name_t_desc name = new gss_name_t_desc();

        if(invalid) {
            throw new GSSException((int) gsswrapper.GSS_S_DEFECTIVE_CREDENTIAL,
                    0, "credential has been disposed, no longer valid");
        }

        maj_status = gsswrapper.gss_inquire_cred_by_mech(min_status,
                this.internGSSCred, mech.getNativeOid(), name, init_lifetime,
                accept_lifetime, cred_usage);

        if (maj_status != gsswrapper.GSS_S_COMPLETE) {
            throw new GSSExceptionImpl((int) maj_status, (int) min_status[0]);
        }

        if (cred_usage[0] == GSSCredential.ACCEPT_ONLY ||
            cred_usage[0] == GSSCredential.INITIATE_AND_ACCEPT) {

            /* check for native INDEFINITE_LIFETIME and convert to Java
               RFC version (Integer.MAX_VALUE) */
            if (accept_lifetime[0] == 4294967295L)
                return GSSCredential.INDEFINITE_LIFETIME;
            return (int)accept_lifetime[0];
        } else {
            return 0;
        }

    }

    public int getUsage() throws GSSException {

        long maj_status = 0;
        long[] min_status = {0};
        long[] lifetime = {0};
        int[] cred_usage = {0};
        gss_name_t_desc name = new gss_name_t_desc();
        gss_OID_set_desc temp_mech_set = new gss_OID_set_desc();

        if(invalid) {
            throw new GSSException((int) gsswrapper.GSS_S_DEFECTIVE_CREDENTIAL,
                    0, "credential has been disposed, no longer valid");
        }

        maj_status = gsswrapper.gss_inquire_cred(min_status,
                this.internGSSCred, name, lifetime, cred_usage,
                temp_mech_set);

        if (maj_status != gsswrapper.GSS_S_COMPLETE) {
            throw new GSSExceptionImpl((int) maj_status, (int) min_status[0]);
        }

        return cred_usage[0];

    }

    public int getUsage(Oid mechOID) throws GSSException {

        long maj_status = 0;
        long[] min_status = {0};
        long[] init_lifetime = {0};
        long[] accept_lifetime = {0};
        int[] cred_usage = {0};
        gss_name_t_desc name = new gss_name_t_desc();

        if(invalid) {
            throw new GSSException((int) gsswrapper.GSS_S_DEFECTIVE_CREDENTIAL,
                    0, "credential has been disposed, no longer valid");
        }

        maj_status = gsswrapper.gss_inquire_cred_by_mech(min_status,
                this.internGSSCred, mechOID.getNativeOid(), name,
                init_lifetime, accept_lifetime, cred_usage);

        if (maj_status != gsswrapper.GSS_S_COMPLETE) {
            throw new GSSExceptionImpl((int) maj_status, (int) min_status[0]);
        }

        return cred_usage[0];

    }

    public Oid[] getMechs() throws GSSException {

        long maj_status = 0;
        long[] min_status = {0};
        long[] lifetime = {0};
        int[] cred_usage = {0};
        gss_name_t_desc name = new gss_name_t_desc();
        gss_OID_set_desc temp_mech_set = new gss_OID_set_desc();

        if(invalid) {
            throw new GSSException((int) gsswrapper.GSS_S_DEFECTIVE_CREDENTIAL,
                    0, "credential has been disposed, no longer valid");
        }

        maj_status = gsswrapper.gss_inquire_cred(min_status,
                this.internGSSCred, name, lifetime, cred_usage,
                temp_mech_set);

        if (maj_status != gsswrapper.GSS_S_COMPLETE) {
            throw new GSSExceptionImpl((int) maj_status, (int) min_status[0]);
        }

        /* temp_mech_set is a set, retrieve elements using getElement() and
           getCount() */
        Oid[] mechs = new Oid[(int) temp_mech_set.getCount()];

        for (int i = 0; i < temp_mech_set.getCount(); i++) {
            mechs[i] = new Oid(temp_mech_set.getElement(i).toDotString());
        }

        return mechs;
    }

    public void add(GSSName aName, int initLifetime, int acceptLifetime,
            Oid mech, int usage) throws GSSException {

        long maj_status = 0;
        long[] min_status = {0};
        long[] lifetime = {0};
        int[] cred_usage = {0};

        if(invalid) {
            throw new GSSException((int) gsswrapper.GSS_S_DEFECTIVE_CREDENTIAL,
                    0, "credential has been disposed, no longer valid");
        }

        maj_status = gsswrapper.gss_add_cred(min_status, this.internGSSCred,
                aName.getInternGSSName(), mech.getNativeOid(),
                usage, initLifetime, acceptLifetime, null, null,
                null, null);

        if (maj_status != gsswrapper.GSS_S_COMPLETE) {
            throw new GSSExceptionImpl((int) maj_status, (int) min_status[0]);
        }

    }

    public boolean equals(Object another) {

        if (! (another instanceof GSSCredential))
            return false;

        GSSCredential tmpCred = (GSSCredential) another;

        if (tmpCred == null)
            throw new NullPointerException("Input Object is null");

        try {

            /* test some elements of our Cred to test for equality */
            if (this.invalid)
                return false;

            if (!tmpCred.getName().equals(this.getName()))
                return false;

            if (tmpCred.getUsage() != this.getUsage())
                return false;

        } catch (GSSException e) {
            return false;
        }

        return true;
    }

    GSSCredential acquireCred(GSSName desiredName, int timeReq,
            Oid[] desiredMechs, int credUsage) throws GSSException {

        long maj_status = 0;
        long[] min_status = {0};
        long[] lifetime = {0};
        int[] cred_usage = {0};
        long[] time_rec = {0};
        long inTimeReq;

        /* initialize internal gss_cred_id_t_desc */
        internGSSCred = new gss_cred_id_t_desc();

        if (possiblyUseSubjectCreds(desiredName, desiredMechs, credUsage)) {
            System.err.println("XXX used subject creds");
            return this;
        }
        System.err.println("XXX did not use subject creds");

        gss_name_t_desc dName;
        gss_OID_set_desc dMechs;

        /* handle null GSSName arg */
        if (desiredName != null) {
            dName = desiredName.getInternGSSName();
        } else {
            dName = gsswrapper.GSS_C_NO_NAME;
        }

        /* handle time req.  Java uses an int to store INDEFINITE, whereas
           native uses a long */
        if (timeReq == GSSCredential.INDEFINITE_LIFETIME) {
            inTimeReq = (long) timeReq;
        } else {
            inTimeReq = gsswrapper.GSS_C_INDEFINITE;
        }

        /* handle null Oid arg, create gss_OID_set_desc from input set */
        if (desiredMechs != null) {
            dMechs = new gss_OID_set_desc();
            for (int i = 0; i < desiredMechs.length; i++) {
                maj_status = gsswrapper.gss_add_oid_set_member(min_status,
                        desiredMechs[i].getNativeOid(), dMechs);

                if (maj_status != gsswrapper.GSS_S_COMPLETE) {
                    throw new GSSExceptionImpl((int) maj_status,
                            (int) min_status[0]);
                }
            }
        } else {
            dMechs = gsswrapper.GSS_C_NO_OID_SET;
        }

        /* acquire cred */
        maj_status = gsswrapper.gss_acquire_cred(min_status,
                dName,
                inTimeReq,
                dMechs,
                credUsage,
                internGSSCred,
                null, time_rec);

        if (maj_status != gsswrapper.GSS_S_COMPLETE) {
            throw new GSSExceptionImpl((int) maj_status, (int) min_status[0]);
        }

        this.invalid = false;
        return this;

    }

    GSSCredential acquireCred(int usage) throws GSSException {

        return acquireCred((GSSName) null,
                GSSCredential.DEFAULT_LIFETIME, (Oid[]) null, usage);

    }

    public gss_cred_id_t_desc getInternGSSCred() {
        return this.internGSSCred;
    }

    public void setInternGSSCred(gss_cred_id_t_desc newCred) {
       if (newCred != null) {
           this.internGSSCred = newCred;
           this.invalid = false;
       } else {
           this.internGSSCred = gsswrapper.GSS_C_NO_CREDENTIAL;
           this.invalid = false;
       }
    }

    public void freeGSSCredential() {
        if (internGSSCred != null) {
            long maj_status = 0;
            long[] min_status = {0};

            maj_status = gsswrapper.gss_release_cred(min_status,
                    internGSSCred);
        }
    }

    /**
     * Attempt to import credentials from the Subject.
     *
     * If this routine succees, these credentials are now valid.
     *
     * @param desiredName the principal
     * @param usage initiate, accept, or both
     * @return whether the subject creds could be used
     */
    private boolean possiblyUseSubjectCreds(final GSSName desiredName,
            final Oid[] desiredMechs, final int usage)
                throws GSSException {
        // TODO(nater): validate that the desired mechs include Kerberos
        // or are set to the default
        KerberosCredentials subjectCreds = findCredsInSubject(
                (desiredName != null ? desiredName.toString() : null), usage);
        if (subjectCreds == null) {
            return false;
        }

        // TODO(nater): validate that the creds we looked up are valid
        // for the desired usage

        long maj_status = 0;
        long [] min_status = {0};
        gsswrapper.gss_krb5_import_cred(min_status, subjectCreds.getCcache(),
                null, subjectCreds.getKeytab(), internGSSCred);
        if (maj_status == 0) {
            this.invalid = false;
            return true;
        }
        return false;
    }

    /**
     * Search the subject for matching credentials.
     *
     * We don't need to check whether the mechanism matches because
     * we're the only ones populating the subject with these kinds of
     * credentials.
     *
     * @param principal the principal to match (may be null)
     * @param usage the intended usage (init, accept, or both)
     */
    private KerberosCredentials findCredsInSubject(final String principal,
            final int usage) {
        final Subject subject =
                Subject.getSubject(AccessController.getContext());
        KerberosCredentials creds = AccessController.doPrivileged(
                new PrivilegedAction<KerberosCredentials>() {
                    public KerberosCredentials run() {
                        return findCredsHelper(subject, principal, usage);
                    }
                });
        return creds;
    }

    /*
     * Helper for searching the subject.
     */
    private KerberosCredentials findCredsHelper(final Subject subject,
            final String principal, final int usage) {
        for (Object o: subject
                .getPrivateCredentials(KerberosCredentials.class)) {
            KerberosCredentials cred = (KerberosCredentials) o;
            // TODO(nater): match usage

            // TODO(nater): match principal

            // For now just returning the first
            return cred;
        }
        return null;
    }
}

