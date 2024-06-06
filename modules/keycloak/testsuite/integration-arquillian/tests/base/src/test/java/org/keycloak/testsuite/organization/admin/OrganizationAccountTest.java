/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.organization.admin;

import java.io.IOException;
import java.util.SortedSet;

import com.fasterxml.jackson.core.type.TypeReference;
import jakarta.ws.rs.core.Response.Status;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.admin.client.resource.OrganizationResource;
import org.keycloak.broker.provider.util.SimpleHttp.Response;
import org.keycloak.common.Profile.Feature;
import org.keycloak.representations.account.LinkedAccountRepresentation;
import org.keycloak.representations.idm.ErrorRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.broker.util.SimpleHttpDefault;
import org.keycloak.testsuite.util.TokenUtil;

@EnableFeature(Feature.ORGANIZATION)
public class OrganizationAccountTest extends AbstractOrganizationTest {

    @Rule
    public TokenUtil tokenUtil = new TokenUtil(bc.getUserEmail(), bc.getUserPassword());

    private CloseableHttpClient client;

    @Before
    public void before() {
        client = HttpClientBuilder.create().build();
    }

    @After
    public void after() {
        try {
            client.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testFailUnlinkIdentityProvider() throws IOException {
        // federate user
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        assertBrokerRegistration(organization, bc.getUserEmail());
        // reset password to obtain a token and access the account api
        UserRepresentation user = ApiUtil.findUserByUsername(realmsResouce().realm(bc.consumerRealmName()), bc.getUserLogin());
        ApiUtil.resetUserPassword(realmsResouce().realm(bc.consumerRealmName()).users().get(user.getId()), bc.getUserPassword(), false);

        LinkedAccountRepresentation link = findLinkedAccount(bc.getIDPAlias());
        Assert.assertNotNull(link);
        try (Response response = SimpleHttpDefault.doDelete(getAccountUrl("linked-accounts/" + link.getProviderAlias()), client).auth(tokenUtil.getToken()).acceptJson().asResponse()) {
            Assert.assertEquals(Status.BAD_REQUEST.getStatusCode(), response.getStatus());
            ErrorRepresentation error = response.asJson(ErrorRepresentation.class);
            Assert.assertEquals("You cannot remove the link to an identity provider associated with an organization.", error.getErrorMessage());
        }

        // broker no longer linked to the organization
        organization.identityProviders().get(bc.getIDPAlias()).delete().close();
        try (Response response = SimpleHttpDefault.doDelete(getAccountUrl("linked-accounts/" + link.getProviderAlias()), client).auth(tokenUtil.getToken()).acceptJson().asResponse()) {
            Assert.assertEquals(Status.NO_CONTENT.getStatusCode(), response.getStatus());
        }
    }

    private SortedSet<LinkedAccountRepresentation> linkedAccountsRep() throws IOException {
        return SimpleHttpDefault.doGet(getAccountUrl("linked-accounts"), client).auth(tokenUtil.getToken())
                .asJson(new TypeReference<>() {});
    }

    private String getAccountUrl(String resource) {
        return suiteContext.getAuthServerInfo().getContextRoot().toString() + "/auth/realms/test/account" + (resource != null ? "/" + resource : "");
    }

    private LinkedAccountRepresentation findLinkedAccount(String providerAlias) throws IOException {
        for (LinkedAccountRepresentation account : linkedAccountsRep()) {
            if (account.getProviderAlias().equals(providerAlias)) return account;
        }

        return null;
    }
}
