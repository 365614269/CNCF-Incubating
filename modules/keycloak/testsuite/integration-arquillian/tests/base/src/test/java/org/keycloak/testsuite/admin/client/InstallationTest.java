/*
 * Copyright 2016 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.keycloak.testsuite.admin.client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import jakarta.ws.rs.core.Response;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.protocol.saml.SamlConfigAttributes;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.installation.SamlSPDescriptorClientInstallation;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.testsuite.ProfileAssume;
import org.keycloak.testsuite.updaters.ClientAttributeUpdater;
import org.keycloak.testsuite.util.AdminEventPaths;
import org.keycloak.testsuite.util.KeyUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.keycloak.common.Profile.Feature.AUTHORIZATION;
import static org.keycloak.testsuite.auth.page.AuthRealm.TEST;
import static org.keycloak.testsuite.util.ServerURLs.getAuthServerContextRoot;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.METADATA_NSURI;

/**
 * Test getting the installation/configuration files for OIDC and SAML.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class InstallationTest extends AbstractClientTest {

    private static final String OIDC_NAME = "oidcInstallationClient";
    private static final String OIDC_NAME_BEARER_ONLY_NAME = "oidcInstallationClientBearerOnly";
    private static final String OIDC_NAME_BEARER_ONLY_WITH_AUTHZ_NAME = "oidcInstallationClientBearerOnlyWithAuthz";
    private static final String SAML_NAME = "samlInstallationClient";

    private ClientResource oidcClient;
    private String oidcClientId;
    private ClientResource oidcBearerOnlyClient;
    private String oidcBearerOnlyClientId;
    private ClientResource oidcBearerOnlyClientWithAuthz;
    private String oidcBearerOnlyClientWithAuthzId;
    private ClientResource samlClient;
    private String samlClientId;

    @Before
    public void createClients() {
        oidcClientId = createOidcClient(OIDC_NAME);
        oidcBearerOnlyClientId = createOidcBearerOnlyClient(OIDC_NAME_BEARER_ONLY_NAME);

        oidcClient = findClientResource(OIDC_NAME);
        oidcBearerOnlyClient = findClientResource(OIDC_NAME_BEARER_ONLY_NAME);

        samlClientId = createSamlClient(SAML_NAME);
        samlClient = findClientResource(SAML_NAME);
    }

    @After
    public void tearDown() {
        removeClient(oidcClientId);
        removeClient(oidcBearerOnlyClientId);
        removeClient(samlClientId);
    }

    private String authServerUrl() {
        return getAuthServerContextRoot() + "/auth";
    }

    private String samlUrl() {
        return authServerUrl() + "/realms/test/protocol/saml";
    }

    @Test
    public void testOidcJBossXml() {
        Response response = oidcClient.getInstallationProvider("keycloak-oidc-jboss-subsystem");
        String xml = response.readEntity(String.class);
        assertOidcInstallationConfig(xml);
        assertThat(xml, containsString("<secure-deployment"));
    }

    @Test
    public void testOidcJson() {
        Response response = oidcClient.getInstallationProvider("keycloak-oidc-keycloak-json");
        String json = response.readEntity(String.class);
        assertOidcInstallationConfig(json);
    }

    @Test
    public void testOidcJBossCli() {
        Response response = oidcClient.getInstallationProvider("keycloak-oidc-jboss-subsystem-cli");
        String cli = response.readEntity(String.class);
        assertOidcInstallationConfig(cli);
        assertThat(cli, containsString("/subsystem=keycloak/secure-deployment=\"WAR MODULE NAME.war\""));
    }

    @Test
    public void testOidcBearerOnlyJson() {
        Response response = oidcBearerOnlyClient.getInstallationProvider("keycloak-oidc-keycloak-json");
        String json = response.readEntity(String.class);
        assertOidcInstallationConfig(json);
        assertThat(json, containsString("bearer-only"));
        assertThat(json, not(containsString("public-client")));
        assertThat(json, not(containsString("credentials")));
        assertThat(json, not(containsString("verify-token-audience")));
    }

    @Test
    public void testOidcBearerOnlyJsonWithAudienceClientScope() {
        // Generate audience client scope
        String clientScopeId = testingClient.testing().generateAudienceClientScope("test", OIDC_NAME_BEARER_ONLY_NAME);

        Response response = oidcBearerOnlyClient.getInstallationProvider("keycloak-oidc-keycloak-json");
        String json = response.readEntity(String.class);
        assertOidcInstallationConfig(json);
        assertThat(json, containsString("bearer-only"));
        assertThat(json, not(containsString("public-client")));
        assertThat(json, not(containsString("credentials")));
        assertThat(json, containsString("verify-token-audience"));

        // Remove clientScope
        testRealmResource().clientScopes().get(clientScopeId).remove();
        assertAdminEvents.assertEvent(getRealmId(), OperationType.DELETE, AdminEventPaths.clientScopeResourcePath(clientScopeId), null, ResourceType.CLIENT_SCOPE);
    }

    @Test
    public void testOidcBearerOnlyWithAuthzJson() {
        ProfileAssume.assumeFeatureEnabled(AUTHORIZATION);

        oidcBearerOnlyClientWithAuthzId = createOidcConfidentialClientWithAuthz(OIDC_NAME_BEARER_ONLY_WITH_AUTHZ_NAME);
        oidcBearerOnlyClientWithAuthz = findClientResource(OIDC_NAME_BEARER_ONLY_WITH_AUTHZ_NAME);

        Response response = oidcBearerOnlyClientWithAuthz.getInstallationProvider("keycloak-oidc-keycloak-json");
        String json = response.readEntity(String.class);
        assertOidcInstallationConfig(json);
        assertThat(json, not(containsString("bearer-only")));
        assertThat(json, not(containsString("public-client")));
        assertThat(json, containsString("credentials"));
        assertThat(json, containsString("secret"));
        assertThat(json, containsString("policy-enforcer"));

        removeClient(oidcBearerOnlyClientWithAuthzId);
    }

    private void assertOidcInstallationConfig(String config) {
        assertThat(config, containsString("test"));
        assertThat(config, not(containsString(KeyUtils.findActiveSigningKey(testRealmResource()).getPublicKey())));
        assertThat(config, containsString(authServerUrl()));
    }

    @Test
    public void testSamlMetadataIdpDescriptor() {
        Response response = samlClient.getInstallationProvider("saml-idp-descriptor");
        assertEquals(404, response.getStatus());
    }

    @Test
    public void testSamlAdapterXml() {
        Response response = samlClient.getInstallationProvider("keycloak-saml");
        String xml = response.readEntity(String.class);
        assertThat(xml, containsString("<keycloak-saml-adapter>"));
        assertThat(xml, containsString("SPECIFY YOUR entityID!"));
        assertThat(xml, not(containsString(KeyUtils.findActiveSigningKey(testRealmResource()).getCertificate())));
        assertThat(xml, containsString(samlUrl()));
    }

    @Test
    public void testSamlAdapterCli() {
        Response response = samlClient.getInstallationProvider("keycloak-saml-subsystem-cli");
        String cli = response.readEntity(String.class);
        assertThat(cli, containsString("/subsystem=keycloak-saml/secure-deployment=YOUR-WAR.war/"));
        assertThat(cli, containsString("SPECIFY YOUR entityID!"));
        assertThat(cli, not(containsString(KeyUtils.findActiveSigningKey(testRealmResource()).getCertificate())));
        assertThat(cli, containsString(samlUrl()));
    }

    @Test
    public void testSamlMetadataSpDescriptor() throws Exception {
        Response response = samlClient.getInstallationProvider(SamlSPDescriptorClientInstallation.SAML_CLIENT_INSTALATION_SP_DESCRIPTOR);
        String xml = response.readEntity(String.class);
        Document doc = getDocumentFromXmlString(xml);
        assertElements(doc, METADATA_NSURI.get(), "EntityDescriptor", null);
        assertElements(doc, METADATA_NSURI.get(), "SPSSODescriptor", null);
        assertThat(xml, containsString(SAML_NAME));
    }

    @Test
    public void testSamlJBossXml() {
        Response response = samlClient.getInstallationProvider("keycloak-saml-subsystem");
        String xml = response.readEntity(String.class);
        assertThat(xml, containsString("<secure-deployment"));
        assertThat(xml, containsString("SPECIFY YOUR entityID!"));
        assertThat(xml, not(containsString(KeyUtils.findActiveSigningKey(testRealmResource()).getCertificate())));
        assertThat(xml, containsString(samlUrl()));
    }

    @Test
    public void testSamlMetadataSpDescriptorPost() throws Exception {
        try (ClientAttributeUpdater updater = ClientAttributeUpdater.forClient(adminClient, TEST, SAML_NAME)) {

            assertThat(updater.getResource().toRepresentation().getAttributes().get(SamlConfigAttributes.SAML_FORCE_POST_BINDING), equalTo("true"));

            //error fallback
            Response response = updater.getResource().getInstallationProvider(SamlSPDescriptorClientInstallation.SAML_CLIENT_INSTALATION_SP_DESCRIPTOR);
            Document doc = getDocumentFromXmlString(response.readEntity(String.class));
            Map<String, String> attrNamesAndValues = new HashMap<>();
            attrNamesAndValues.put("Binding", JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get());
            attrNamesAndValues.put("Location", "ERROR:ENDPOINT_NOT_SET");
            assertElements(doc, METADATA_NSURI.get(), "SingleLogoutService", attrNamesAndValues);
            assertElements(doc, METADATA_NSURI.get(), "AssertionConsumerService", attrNamesAndValues);
            attrNamesAndValues.clear();

            //fallback to adminUrl
            updater.setAdminUrl("https://admin-url").update();
            assertAdminEvents.assertEvent(getRealmId(), OperationType.UPDATE, AdminEventPaths.clientResourcePath(samlClientId), ResourceType.CLIENT);
            response = updater.getResource().getInstallationProvider(SamlSPDescriptorClientInstallation.SAML_CLIENT_INSTALATION_SP_DESCRIPTOR);
            doc = getDocumentFromXmlString(response.readEntity(String.class));
            attrNamesAndValues.put("Binding", JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get());
            attrNamesAndValues.put("Location", "https://admin-url");
            assertElements(doc, METADATA_NSURI.get(), "SingleLogoutService", attrNamesAndValues);
            assertElements(doc, METADATA_NSURI.get(), "AssertionConsumerService", attrNamesAndValues);
            attrNamesAndValues.clear();

            //fine grained
            updater.setAttribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE, "https://saml-assertion-post-url")
                   .setAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_POST_ATTRIBUTE, "https://saml-logout-post-url")
                   .setAttribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_REDIRECT_ATTRIBUTE, "https://saml-assertion-redirect-url")
                   .setAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_REDIRECT_ATTRIBUTE, "https://saml-logout-redirect-url")
                   .update();
            assertAdminEvents.assertEvent(getRealmId(), OperationType.UPDATE, AdminEventPaths.clientResourcePath(samlClientId), ResourceType.CLIENT);

            response = updater.getResource().getInstallationProvider(SamlSPDescriptorClientInstallation.SAML_CLIENT_INSTALATION_SP_DESCRIPTOR);
            doc = getDocumentFromXmlString(response.readEntity(String.class));
            attrNamesAndValues.put("Binding", JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get());
            attrNamesAndValues.put("Location", "https://saml-logout-post-url");
            assertElements(doc, METADATA_NSURI.get(), "SingleLogoutService", attrNamesAndValues);
            attrNamesAndValues.clear();
            attrNamesAndValues.put("Binding", JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get());
            attrNamesAndValues.put("Location", "https://saml-assertion-post-url");
            assertElements(doc, METADATA_NSURI.get(), "AssertionConsumerService", attrNamesAndValues);
        }
        assertAdminEvents.assertEvent(getRealmId(), OperationType.UPDATE, AdminEventPaths.clientResourcePath(samlClientId), ResourceType.CLIENT);
    }

    @Test
    public void testSamlMetadataSpDescriptorRedirect() throws Exception {
        try (ClientAttributeUpdater updater = ClientAttributeUpdater.forClient(adminClient, TEST, SAML_NAME)
                .setAttribute(SamlConfigAttributes.SAML_FORCE_POST_BINDING, "false")
                .update()) {

            assertAdminEvents.assertEvent(getRealmId(), OperationType.UPDATE, AdminEventPaths.clientResourcePath(samlClientId), ResourceType.CLIENT);
            assertThat(updater.getResource().toRepresentation().getAttributes().get(SamlConfigAttributes.SAML_FORCE_POST_BINDING), equalTo("false"));

            //error fallback
            Response response = updater.getResource().getInstallationProvider(SamlSPDescriptorClientInstallation.SAML_CLIENT_INSTALATION_SP_DESCRIPTOR);
            Document doc = getDocumentFromXmlString(response.readEntity(String.class));
            Map<String, String> attrNamesAndValues = new HashMap<>();
            attrNamesAndValues.put("Binding", JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get());
            attrNamesAndValues.put("Location", "ERROR:ENDPOINT_NOT_SET");
            assertElements(doc, METADATA_NSURI.get(), "SingleLogoutService", attrNamesAndValues);
            assertElements(doc, METADATA_NSURI.get(), "AssertionConsumerService", attrNamesAndValues);
            attrNamesAndValues.clear();

            //fallback to adminUrl
            updater.setAdminUrl("https://admin-url").update();
            assertAdminEvents.assertEvent(getRealmId(), OperationType.UPDATE, AdminEventPaths.clientResourcePath(samlClientId), ResourceType.CLIENT);
            response = updater.getResource().getInstallationProvider(SamlSPDescriptorClientInstallation.SAML_CLIENT_INSTALATION_SP_DESCRIPTOR);
            doc = getDocumentFromXmlString(response.readEntity(String.class));
            attrNamesAndValues.put("Binding", JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get());
            attrNamesAndValues.put("Location", "https://admin-url");
            assertElements(doc, METADATA_NSURI.get(), "SingleLogoutService", attrNamesAndValues);
            assertElements(doc, METADATA_NSURI.get(), "AssertionConsumerService", attrNamesAndValues);
            attrNamesAndValues.clear();

            //fine grained
            updater.setAttribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE, "https://saml-assertion-post-url")
                   .setAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_POST_ATTRIBUTE, "https://saml-logout-post-url")
                   .setAttribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_REDIRECT_ATTRIBUTE, "https://saml-assertion-redirect-url")
                   .setAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_REDIRECT_ATTRIBUTE, "https://saml-logout-redirect-url")
                   .update();
            assertAdminEvents.assertEvent(getRealmId(), OperationType.UPDATE, AdminEventPaths.clientResourcePath(samlClientId), ResourceType.CLIENT);
            response = updater.getResource().getInstallationProvider(SamlSPDescriptorClientInstallation.SAML_CLIENT_INSTALATION_SP_DESCRIPTOR);
            doc = getDocumentFromXmlString(response.readEntity(String.class));
            attrNamesAndValues.put("Binding", JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get());
            attrNamesAndValues.put("Location", "https://saml-logout-redirect-url");
            assertElements(doc, METADATA_NSURI.get(), "SingleLogoutService", attrNamesAndValues);
            attrNamesAndValues.clear();
            attrNamesAndValues.put("Binding", JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get());
            attrNamesAndValues.put("Location", "https://saml-assertion-redirect-url");
            assertElements(doc, METADATA_NSURI.get(), "AssertionConsumerService", attrNamesAndValues);
        }
        assertAdminEvents.assertEvent(getRealmId(), OperationType.UPDATE, AdminEventPaths.clientResourcePath(samlClientId), ResourceType.CLIENT);
    }

    @Test
    public void testPemsInModAuthMellonExportShouldBeFormattedInRfc7468() throws IOException {
        Response response = samlClient.getInstallationProvider("mod-auth-mellon");
        byte[] result = response.readEntity(byte[].class);

        String clientPrivateKey = null;
        String clientCert = null;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(result))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().endsWith("client-private-key.pem")) {
                    clientPrivateKey = new String(zis.readAllBytes(), StandardCharsets.US_ASCII);
                }
                else if (entry.getName().endsWith("client-cert.pem")) {
                    clientCert = new String(zis.readAllBytes(), StandardCharsets.US_ASCII);
                }
            }
        }

        assertNotNull(clientPrivateKey);
        assertNotNull(clientCert);
        assertRfc7468PrivateKey(clientPrivateKey);
        assertRfc7468Cert(clientCert);
    }

    private void assertRfc7468PrivateKey(String result) {
        assertTrue(result.startsWith("-----BEGIN PRIVATE KEY-----"));
        assertTrue(result.endsWith("-----END PRIVATE KEY-----"));
        result.lines().forEach(line -> assertTrue(line.length() <= 64));
    }

    private void assertRfc7468Cert(String result) {
        assertTrue(result.startsWith("-----BEGIN CERTIFICATE-----"));
        assertTrue(result.endsWith("-----END CERTIFICATE-----"));
        result.lines().forEach(line -> assertTrue(line.length() <= 64));
    }

    private Document getDocumentFromXmlString(String xml) throws SAXException, ParserConfigurationException, IOException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        InputSource is = new InputSource();
        is.setCharacterStream(new StringReader(xml));
        return db.parse(is);
    }

    private void assertElements(Document doc, String tagNamespace, String tagName, Map<String, String> attrNamesAndValues) {
        NodeList elementsByTagName = doc.getElementsByTagNameNS(tagNamespace, tagName);
        assertThat("Expected exactly one " + tagName + " element!", elementsByTagName.getLength(), is(equalTo(1)));
        Node element = elementsByTagName.item(0);

        if (attrNamesAndValues != null) {
            for (String attrName : attrNamesAndValues.keySet()) {
                assertThat(element.getAttributes().getNamedItem(attrName).getNodeValue(), containsString(attrNamesAndValues.get(attrName)));
            }
        }
    }
}
