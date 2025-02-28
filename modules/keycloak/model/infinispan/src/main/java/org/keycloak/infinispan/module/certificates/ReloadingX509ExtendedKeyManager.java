package org.keycloak.infinispan.module.certificates;

import java.lang.invoke.MethodHandles;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;

import javax.net.ssl.X509ExtendedKeyManager;

/**
 * A {@link X509ExtendedKeyManager} implementation that allows to update the keys and certificates at runtime.
 */
class ReloadingX509ExtendedKeyManager extends X509ExtendedKeyManager {

    private static final Logger logger = Logger.getLogger(MethodHandles.lookup().lookupClass());
    private volatile X509ExtendedKeyManager delegate;

    public ReloadingX509ExtendedKeyManager(X509ExtendedKeyManager delegate) {
        this.delegate = Objects.requireNonNull(delegate);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        var r = delegate.getClientAliases(keyType, issuers);
        if (logger.isDebugEnabled() && r != null) {
            logger.debugf("getClientAliases - %s", Arrays.toString(r));
        }
        return r;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        var r = delegate.chooseClientAlias(keyType, issuers, socket);
        logger.debugf("chooseClientAlias - %s", r);
        return r;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        var r = delegate.getServerAliases(keyType, issuers);
        if (logger.isDebugEnabled()) {
            logger.debugf("getServerAliases - %s", Arrays.toString(r));
        }
        return r;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        var r = delegate.chooseServerAlias(keyType, issuers, socket);
        logger.debugf("chooseServerAlias - %s", r);
        return r;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        var r = delegate.getCertificateChain(alias);
        if (logger.isDebugEnabled() && r != null) {
            logger.debugf("getCertificateChain - serial numbers: %s", Arrays.stream(r).map(X509Certificate::getSerialNumber).map(String::valueOf).collect(Collectors.joining(", ")));
        }
        return r;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return delegate.getPrivateKey(alias);
    }

    public void reload(X509ExtendedKeyManager keyManager) {
        delegate = Objects.requireNonNull(keyManager);
    }
}
