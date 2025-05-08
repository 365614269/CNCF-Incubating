/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.spi.infinispan.impl.embedded;

import java.lang.invoke.MethodHandles;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.infinispan.commons.configuration.attributes.Attribute;
import org.infinispan.configuration.global.TransportConfigurationBuilder;
import org.infinispan.configuration.parsing.ConfigurationBuilderHolder;
import org.infinispan.remoting.transport.jgroups.EmbeddedJGroupsChannelConfigurator;
import org.infinispan.remoting.transport.jgroups.JGroupsTransport;
import org.jboss.logging.Logger;
import org.jgroups.conf.ClassConfigurator;
import org.jgroups.conf.ProtocolConfiguration;
import org.jgroups.protocols.TCP_NIO2;
import org.jgroups.protocols.UDP;
import org.jgroups.stack.Protocol;
import org.jgroups.util.DefaultSocketFactory;
import org.jgroups.util.SocketFactory;
import org.keycloak.Config;
import org.keycloak.connections.infinispan.InfinispanConnectionProvider;
import org.keycloak.connections.infinispan.InfinispanConnectionSpi;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.connections.jpa.JpaConnectionProviderFactory;
import org.keycloak.connections.jpa.util.JpaUtils;
import org.keycloak.jgroups.protocol.KEYCLOAK_JDBC_PING2;
import org.keycloak.models.KeycloakSession;
import org.keycloak.spi.infinispan.JGroupsCertificateProvider;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManager;

import static org.infinispan.configuration.global.TransportConfiguration.STACK;

/**
 * Utility class to configure JGroups based on the Keycloak configuration.
 */
public final class JGroupsConfigurator {

    private static final Logger logger = Logger.getLogger(MethodHandles.lookup().lookupClass());
    private static final String TLS_PROTOCOL_VERSION = "TLSv1.3";
    private static final String TLS_PROTOCOL = "TLS";

    private static final String KUBERNETES_STACK = "kubernetes";
    private static final String KUBERNETES_PATCHED_STACK = "kubernetes-patched";

    private JGroupsConfigurator() {
    }

    static {
        // Use custom Keycloak JDBC_PING implementation that workarounds issue https://issues.redhat.com/browse/JGRP-2870
        // The id 1025 follows this instruction: https://github.com/belaban/JGroups/blob/38219e9ec1c629fa2f7929e3b53d1417d8e60b61/conf/jg-protocol-ids.xml#L85
        ClassConfigurator.addProtocol((short) 1025, KEYCLOAK_JDBC_PING2.class);
    }

    /**
     * Configures JGroups based on the Keycloak configuration.
     *
     * @param config  The Keycloak configuration.
     * @param holder  The {@link ConfigurationBuilderHolder} where the transport is configured.
     * @param session The {@link KeycloakSession} sessions for Database access.
     */
    public static void configureJGroups(Config.Scope config, ConfigurationBuilderHolder holder, KeycloakSession session) {
        var stack = config.get(DefaultCacheEmbeddedConfigProviderFactory.STACK);
        if (stack != null) {
            transportOf(holder).stack(stack);
        }
        configureDiscovery(holder, session);
        configureTls(holder, session);
        warnDeprecatedStack(holder);
        patchKubernetesStack(holder);
    }

    /**
     * Patch for <a href="https://github.com/keycloak/keycloak/issues/39023">GHI#39023</a> and <a
     * href="https://github.com/keycloak/keycloak/issues/39454">GHI#39454</a>
     */
    private static void patchKubernetesStack(ConfigurationBuilderHolder holder) {
        var stackXmlAttribute = transportStackOf(holder);
        if (!Objects.equals(KUBERNETES_STACK, stackXmlAttribute.get())) {
            // not the kubernetes stack
            return;
        }
        logger.info("[PATCH] Patching kubernetes stack.");
        // patch port range
        var attributes = Map.of("port_range", "0");
        var patch = List.of(new ProtocolConfiguration("TCP", attributes));
        holder.addJGroupsStack(new EmbeddedJGroupsChannelConfigurator(KUBERNETES_PATCHED_STACK, patch, null), KUBERNETES_STACK);
        transportOf(holder).stack(KUBERNETES_PATCHED_STACK);
    }

    /**
     * Configures the topology information in the Infinispan transport.
     *
     * @param config The Keycloak configuration.
     * @param holder The {@link ConfigurationBuilderHolder} where the transport is configured.
     */
    public static void configureTopology(Config.Scope config, ConfigurationBuilderHolder holder) {
        if (System.getProperty(InfinispanConnectionProvider.JBOSS_SITE_NAME) != null) {
            throw new IllegalArgumentException(
                    String.format("System property %s is in use. Use --spi-cache-embedded-%s-site-name config option instead",
                            InfinispanConnectionProvider.JBOSS_SITE_NAME, DefaultCacheEmbeddedConfigProviderFactory.PROVIDER_ID));
        }
        if (System.getProperty(InfinispanConnectionProvider.JBOSS_NODE_NAME) != null) {
            throw new IllegalArgumentException(
                    String.format("System property %s is in use. Use --spi-cache-embedded-%s-node-name config option instead",
                            InfinispanConnectionProvider.JBOSS_NODE_NAME, DefaultCacheEmbeddedConfigProviderFactory.PROVIDER_ID));
        }
        var transport = transportOf(holder);
        var nodeName = config.get(DefaultCacheEmbeddedConfigProviderFactory.NODE_NAME);
        if (nodeName != null) {
            transport.nodeName(nodeName);
        }
        //legacy option, for backwards compatibility --spi-connections-infinispan-quarkus-site-name
        var legacySiteName = Config.scope(InfinispanConnectionSpi.SPI_NAME, "quarkus").get("site-name");
        if (legacySiteName != null) {
            logger.warn("--spi-connections-infinispan-quarkus-site-name is deprecated and may be removed in the future. Use --spi-cache-embedded-%s-site-name".formatted(DefaultCacheEmbeddedConfigProviderFactory.PROVIDER_ID));
        }
        var siteName = config.get(DefaultCacheEmbeddedConfigProviderFactory.SITE_NAME, legacySiteName);
        if (siteName != null) {
            transport.siteId(siteName);
        }
    }

    private static void configureTls(ConfigurationBuilderHolder holder, KeycloakSession session) {
        var provider = session.getProvider(JGroupsCertificateProvider.class);
        if (provider == null || !provider.isEnabled()) {
            return;
        }
        var factory = createSocketFactory(provider);
        transportOf(holder).addProperty(JGroupsTransport.SOCKET_FACTORY, factory);
        validateTlsAvailable(holder);
        logger.info("JGroups Encryption enabled (mTLS).");
    }

    private static SocketFactory createSocketFactory(JGroupsCertificateProvider provider) {
        try {
            var sslContext = SSLContext.getInstance(TLS_PROTOCOL);
            sslContext.init(new KeyManager[]{provider.keyManager()}, new TrustManager[]{provider.trustManager()}, null);
            return createFromContext(sslContext);
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            // we should have valid certificates and keys.
            throw new RuntimeException(e);
        }
    }

    private static SocketFactory createFromContext(SSLContext context) {
        DefaultSocketFactory socketFactory = new DefaultSocketFactory(context);
        final SSLParameters serverParameters = new SSLParameters();
        serverParameters.setProtocols(new String[]{TLS_PROTOCOL_VERSION});
        serverParameters.setNeedClientAuth(true);
        socketFactory.setServerSocketConfigurator(socket -> ((SSLServerSocket) socket).setSSLParameters(serverParameters));
        return socketFactory;
    }

    private static void configureDiscovery(ConfigurationBuilderHolder holder, KeycloakSession session) {
        var stackXmlAttribute = transportStackOf(holder);
        if (stackXmlAttribute.isModified() && !isJdbcPingStack(stackXmlAttribute.get())) {
            logger.debugf("Custom stack configured (%s). JDBC_PING discovery disabled.", stackXmlAttribute.get());
            return;
        }

        logger.debug("JDBC_PING discovery enabled.");
        if (!stackXmlAttribute.isModified()) {
            // defaults to jdbc-ping
            transportOf(holder).stack("jdbc-ping");
        }

        var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        var stackName = transportStackOf(holder).get();
        var isUdp = stackName.endsWith("udp");
        var tableName = JpaUtils.getTableNameForNativeQuery("JGROUPS_PING", em);
        var stack = getProtocolConfigurations(tableName, isUdp ? "PING" : "MPING");
        var connectionFactory = (JpaConnectionProviderFactory) session.getKeycloakSessionFactory().getProviderFactory(JpaConnectionProvider.class);
        holder.addJGroupsStack(new JpaFactoryAwareJGroupsChannelConfigurator(stackName, stack, connectionFactory, isUdp), null);

        transportOf(holder).stack(stackName);
        JGroupsConfigurator.logger.info("JGroups JDBC_PING discovery enabled.");
    }

    private static List<ProtocolConfiguration> getProtocolConfigurations(String tableName, String discoveryProtocol) {
        var attributes = Map.of(
                // Leave initialize_sql blank as table is already created by Keycloak
                "initialize_sql", "",
                // Explicitly specify clear and select_all SQL to ensure "cluster_name" column is used, as the default
                // "cluster" cannot be used with Oracle DB as it's a reserved word.
                "clear_sql", String.format("DELETE from %s WHERE cluster_name=?", tableName),
                "delete_single_sql", String.format("DELETE from %s WHERE address=?", tableName),
                "insert_single_sql", String.format("INSERT INTO %s values (?, ?, ?, ?, ?)", tableName),
                "select_all_pingdata_sql", String.format("SELECT address, name, ip, coord FROM %s WHERE cluster_name=?", tableName),
                "remove_all_data_on_view_change", "true",
                "register_shutdown_hook", "false",
                "stack.combine", "REPLACE",
                "stack.position", discoveryProtocol
        );
        return List.of(new ProtocolConfiguration(KEYCLOAK_JDBC_PING2.class.getName(), attributes));
    }

    private static void warnDeprecatedStack(ConfigurationBuilderHolder holder) {
        var stackName = transportStackOf(holder).get();
        switch (stackName) {
            case "jdbc-ping-udp":
            case "tcp":
            case "udp":
            case "azure":
            case "ec2":
            case "google":
                logger.warnf("Stack '%s' is deprecated. We recommend to use 'jdbc-ping' instead", stackName);
        }
    }

    private static TransportConfigurationBuilder transportOf(ConfigurationBuilderHolder holder) {
        return holder.getGlobalConfigurationBuilder().transport();
    }

    private static Attribute<String> transportStackOf(ConfigurationBuilderHolder holder) {
        var transport = transportOf(holder);
        assert transport != null;
        return transport.attributes().attribute(STACK);
    }

    private static void validateTlsAvailable(ConfigurationBuilderHolder holder) {
        var stackName = transportStackOf(holder).get();
        if (stackName == null) {
            // unable to validate
            return;
        }
        var config = transportOf(holder).build();
        for (var protocol : config.transport().jgroups().configurator(stackName).getProtocolStack()) {
            var name = protocol.getProtocolName();
            if (name.equals(UDP.class.getSimpleName()) ||
                    name.equals(UDP.class.getName()) ||
                    name.equals(TCP_NIO2.class.getSimpleName()) ||
                    name.equals(TCP_NIO2.class.getName())) {
                throw new RuntimeException("Cache TLS is not available with protocol " + name);
            }
        }
    }

    private static boolean isJdbcPingStack(String stackName) {
        return "jdbc-ping".equals(stackName) || "jdbc-ping-udp".equals(stackName);
    }

    private static class JpaFactoryAwareJGroupsChannelConfigurator extends EmbeddedJGroupsChannelConfigurator {

        private final JpaConnectionProviderFactory factory;

        public JpaFactoryAwareJGroupsChannelConfigurator(String name, List<ProtocolConfiguration> stack, JpaConnectionProviderFactory factory, boolean isUdp) {
            super(name, stack, null, isUdp ? "udp" : "tcp");
            this.factory = Objects.requireNonNull(factory);
        }

        @Override
        public void afterCreation(Protocol protocol) {
            super.afterCreation(protocol);
            if (protocol instanceof KEYCLOAK_JDBC_PING2 kcPing) {
                kcPing.setJpaConnectionProviderFactory(factory);
            }
        }
    }
}
