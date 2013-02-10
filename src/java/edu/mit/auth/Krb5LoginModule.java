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

package edu.mit.auth;

import java.io.IOException;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Set;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.security.auth.Subject;

import edu.mit.jgss.krb5.KerberosCredentials;
import edu.mit.jgss.krb5.LibKrb5Exception;
import edu.mit.jgss.swig.gsswrapper;
import edu.mit.jgss.swig.krb5_context_handle;
import edu.mit.jgss.swig.krb5_keytab_handle;
import edu.mit.jgss.swig.krb5_principal_data;
import edu.mit.jgss.swig.krb5_ccache_handle;
import edu.mit.jgss.swig.krb5_creds;

/**
 * Authenticates users using MIT Kerberos.
 *
 * The configuration entry for this login module has several options,
 * mostly analogous to those provided by the Sun implementation. They
 * are:
 * <dl>
 * <blockquote>
 *  <dt><b><code>useKeyTab</code></b>:</dt>
 *  <dd>
 *  Set this to true if the module should trye to load the principal's key
 *  from the keytab. The default value is false. If the <code>keytab</code>
 *  is not set then the module will attempt to use the default keytab file,
 *  which is a Kerberos implementation depdendent configuration setting.
 *  <dt><b><code>keyTab</code></b>:</td>
 *  <dd>Set this to the path to the principal's keytab file.</dd>
 *  </blockquote>
 *  </dl>
 *
 *  NOTE: The configuration options for this module are in beta, and
 *  are subject to change.
 */
public final class Krb5LoginModule implements LoginModule {
    /* TODO(nater): add logging facilities */

    /** Subject for this login. */
    private Subject subject = null;

    /** Callback handler for user interaction. */
    private CallbackHandler handler = null;

    /** State shared among chained login modules. */
    private Map<String, ?> sharedState = null;

    /** Whether to use a keytab file. */
    private boolean useKeyTab = false;

    /** The keytab file path. */
    private String keyTab = null;

    /** Whether a call to login succeeded. */
    private boolean loginSuccess = false;

    /** Whether a call to commit succeeded. */
    private boolean commitSuccess = false;

    /** Credentials store initialized by login. */
    private KerberosCredentials creds = null;

    /**
     * Initialize this module.
     *
     * Invoked by a LoginContext when establishing a new login.
     *
     * @param subject the subject logging in
     * @param handler callback handler (may be null)
     * @param sharedState state shared with other modules
     * @param options options specific to this module's jaas configuration
     */
    public void initialize(final Subject subject, final CallbackHandler handler,
            final Map<String, ?> sharedState, final Map<String, ?> options) {
        this.subject = subject;
        this.handler = handler;
        this.sharedState = sharedState;

        // Consume options
        useKeyTab = getBoolOption(options, "useKeyTab");
        keyTab = (String) options.get("keyTab");
    }

    /**
     * Perform the login.
     *
     * Initializes a Kerberos library context and performs an authentication
     * exchange using either credentials in a keytab or prompting for
     * a user name and password.
     *
     * TODO(nater): add isInitiator option and avoid obtaining a TGT
     * if it is set to false and the credentials are available in
     * the keytab file.
     *
     * @return true if login succeeds
     * @throws LoginException if login fails
     */
    public boolean login() throws LoginException {
        // Get the principal name
        //
        // TODO(nater): for full parity with Sun's implementation, there
        // should be a system property where one can set the principal.
        String userName = doNameCallback();

        krb5_context_handle cleanupContext = null;
        krb5_context_handle context = null;
        krb5_keytab_handle keytab = null;
        krb5_principal_data principal = null;
        krb5_ccache_handle ccache = null;
        krb5_creds kcreds = null;

        try {
            // Get a kerberos library context
            context = new krb5_context_handle();
            gsswrapper.krb5_init_context(context);
            cleanupContext = context; // Held for cleanup up other state

            if (useKeyTab && keyTab != null) {
                // This may be null
                keytab = resolveKeytabHandle(context);
            }

            // Load the principal name
            principal = new krb5_principal_data();
            gsswrapper.krb5_parse_name(context, userName, principal);

            // TODO(nater): make cache type / location configurable
            ccache = new krb5_ccache_handle();
            gsswrapper.krb5_cc_new_unique(context, "MEMORY", null,
                    ccache);

            // Initialize the cache
            gsswrapper.krb5_cc_initialize(context, ccache, principal);

            // TODO(nater): set init creds options, like renewable duration

            kcreds = new krb5_creds();
            if (keytab != null) {
                gsswrapper.krb5_get_init_creds_keytab(context, kcreds,
                        principal, keytab, /* startingIn= */ 0,
                        /* in_tkt_service= */ null, /* options= */ null);
            } else {
                // Try password-based authentication
                String password = doPasswordCallback();
                gsswrapper.krb5_get_init_creds_password(context,
                        kcreds, principal, password, /* prompter= */ null,
                        /* prompterData= */ null, /* startingIn= */ 0,
                        /* in_tkt_service= */ null, /* options= */ null);
            }

            // Store credentials in the cache
            gsswrapper.krb5_cc_store_cred(context, ccache, kcreds);

            // Hold on to the credentials in this cache
            creds = new KerberosCredentials(context, ccache);
            // Forget about these; the rest will be freed below
            context = null;
            ccache = null;
        } catch (LibKrb5Exception lke) {
            throw (LoginException) new LoginException("While authenticating: " +
                    lke.getMessage()).initCause(lke);
        } finally {
            // Release unused resources
            if (kcreds != null) {
                // No release method needed
                kcreds = null;
            }
            if (ccache != null) {
                gsswrapper.krb5_cc_destroy(cleanupContext, ccache);
                ccache = null;
            }
            if (principal != null) {
                gsswrapper.krb5_free_principal(cleanupContext, principal);
                principal = null;
            }
            if (keytab != null) {
                gsswrapper.krb5_kt_close(cleanupContext, keytab);
                keytab = null;
            }
            if (context != null) {
                gsswrapper.krb5_free_context(context);
                context = null;
            }
            cleanupContext = null;
        }

        loginSuccess = true;
        return true;
    }

    /**
     * Commit this login into the subject.
     *
     * Stores the KerberosCredentials object into the Subject's private creds.
     *
     * For compatibility with applications written against the Sun
     * Krb5LoginModule that use the <b><code>storeKey</code></b> option, also
     * extracts the following and stores them in the Subject:
     *
     *  - the TGT, as a KerberosTicket
     *  - the private Kerberos key(s), as KerberosKey objects
     *
     * @return whether the commit succeded
     * @throws LoginException if an error occurs
     */
    public boolean commit() throws LoginException {
        if (!loginSuccess) {
            // No saved state to clean up in this case
            return false;
        }

        // Store KerberosCredentials object into the private store
        Set<Object> privCreds = subject.getPrivateCredentials();
        privCreds.add(creds);

        // TODO(nater): store TGT and key(s)

        // Remember that commit succeeded
        commitSuccess = true;
        return true;
    }

    /**
     * Handle an abort by cleaning up state.
     *
     * @return whether the abort succeeded
     * @throws LoginException if an error occurs
     */
    public boolean abort() throws LoginException {
        if (!loginSuccess) {
            // Nothing to clean up
            return false;
        }

        if (!commitSuccess) {
            // Login was successful but commit failed. Clean up the
            // KerberosCredentials object.
            //
            // TODO(nater): this is insufficient; we should implement
            // the Destroyable interface and invoke dstroy (see logout, below)
            creds = null;
        } else {
            // Commit succeded, but we've already stored information into
            // the Subject, so that needs to be removed. Same logic as
            // logout() (may throw).
            logout();
        }
        loginSuccess = false;
        commitSuccess = false;
        return true;
    }

    /**
     * Remove and destroy state saved to the Subject.
     *
     * @return true if successful
     * @throws LoginException if an error occurs
     */
    public boolean logout() throws LoginException {
        if (subject.isReadOnly()) {
            // TODO(nater): once our state implements Destroyable, we can
            // remove this throw and instead just destroy all the cached state.
            throw new LoginException("Unable to logout read-only Subject");
        }

        // Remove KerberosCredentials from the cred set
        subject.getPrivateCredentials().remove(creds);
        // TODO(nater): these should be destroyed, instead of waiting for gc
        creds = null;
        // TODO(nater): when keys and tickets are added, also remove these

        // Reset state
        loginSuccess = false;
        commitSuccess = false;
        return true;
    }

    /**
     * Resolve a keytab handle, swallowing exceptions.
     *
     * @param context the library context
     * @return the handle, or null
     */
    private krb5_keytab_handle resolveKeytabHandle(
            final krb5_context_handle context) {
        krb5_keytab_handle keytab = null;
        try {
            keytab = new krb5_keytab_handle();
            gsswrapper.krb5_kt_resolve(context, keyTab, keytab);
        } catch (LibKrb5Exception lke) {
            // Swallow the exception
            // TODO(nater): logging
        }
        return keytab;
    }

    /**
     * Obtain the principal name by executing a callback.
     *
     * @return the principal name
     * @throws LoginException if no handler exists, or if an error occurs
     */
    private String doNameCallback() throws LoginException {
        if (handler == null) {
            // Sadness
            throw new LoginException("No handler registered to prompt user");
        }

        try {
            // Set up a user name prompt callback
            //
            // TODO(nater): infer a default user name from system properties
            NameCallback cb = new NameCallback("Kerberos user name:");
            // Invoke the handler
            handler.handle(new Callback[] {cb});
            // Sanity check results
            String name = cb.getName();
            if (name == null || name.isEmpty()) {
                throw new LoginException("No principal name provided");
            }
            return name;
        } catch (IOException ioe) {
            throw (LoginException)
                new LoginException("While prompting user name: " +
                        ioe.getMessage()).initCause(ioe);
        } catch (UnsupportedCallbackException uce) {
            throw (LoginException)
                new LoginException("While prompting user name: " +
                        uce.getMessage()).initCause(uce);
        }
    }

    /**
     * Obtain the password by executing a callback.
     *
     * @return the password
     * @throws LoginException if no handler exists, or if an error occurs
     */
    private String doPasswordCallback() throws LoginException {
        if (handler == null) {
            // Sadness
            throw new LoginException("No handler registered to prompt user");
        }

        try {
            // Set up a password prompt callback
            PasswordCallback cb = new PasswordCallback("Kerberos password:",
                    /* echoOn= */ false);
            // Invoke handler
            handler.handle(new Callback[] {cb});
            // This is a copy
            char[] password = cb.getPassword();

            String ret;
            if (password != null) {
                ret = new String(password);
                // There must be a better way
                for (int i = 0; i < password.length; ++i) {
                    password[i] = (char) 0;
                }
            } else {
                // Never return null, or the underlying kerberos library
                // will prompt!
                ret = new String();
            }
            cb.clearPassword();
            return ret;
        } catch (IOException ioe) {
            throw (LoginException)
                new LoginException("While prompting password: " +
                        ioe.getMessage()).initCause(ioe);
        } catch (UnsupportedCallbackException uce) {
            throw (LoginException)
                new LoginException("While prompting password: " +
                        uce.getMessage()).initCause(uce);
        }
    }

    /**
     * Test for a boolean option.
     *
     * @param options the options map
     * @param option the option name
     * @return the option value
     */
    private static boolean getBoolOption(final Map<String, ?> options,
            final String option) {
        return "true".equalsIgnoreCase((String) options.get(option));
    }
}
