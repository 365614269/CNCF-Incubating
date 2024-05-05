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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;
import java.util.function.Function;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import org.jboss.arquillian.graphene.page.Page;
import org.keycloak.admin.client.resource.OrganizationResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.OrganizationDomainRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.admin.AbstractAdminTest;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.admin.Users;
import org.keycloak.testsuite.broker.KcOidcBrokerConfiguration;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.pages.IdpConfirmLinkPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.pages.UpdateAccountInformationPage;
import org.keycloak.testsuite.util.UserBuilder;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public abstract class AbstractOrganizationTest extends AbstractAdminTest  {

    protected String organizationName = "neworg";
    protected String memberEmail = "jdoe@neworg.org";
    protected String memberPassword = "password";
    protected Function<String, KcOidcBrokerConfiguration> brokerConfigFunction = name ->  new KcOidcBrokerConfiguration() {
        @Override
        public String consumerRealmName() {
            return TEST_REALM_NAME;
        }

        @Override
        public RealmRepresentation createProviderRealm() {
            RealmRepresentation providerRealm = super.createProviderRealm();

            providerRealm.setClients(createProviderClients());
            providerRealm.setUsers(List.of(
                    UserBuilder.create()
                        .username(getUserLogin())
                        .email(getUserEmail())
                        .password(getUserPassword())
                        .enabled(true)
                        .build(),
                    UserBuilder.create()
                        .username("external")
                        .email("external@user.org")
                        .password("password")
                        .enabled(true)
                        .build()
                    )
            );

            return providerRealm;
        }

        @Override
        public String getUserEmail() {
            return getUserLogin() + "@" + organizationName + ".org";
        }

        @Override
        public String getIDPAlias() {
            return name + "-identity-provider";
        }

        @Override
        public List<ClientRepresentation> createProviderClients() {
            List<ClientRepresentation> clients = super.createProviderClients();
            clients.get(0).setRedirectUris(List.of("*"));
            return clients;
        }
    };

    @Page
    protected LoginPage loginPage;

    @Page
    protected IdpConfirmLinkPage idpConfirmLinkPage;

    @Page
    protected UpdateAccountInformationPage updateAccountInformationPage;

    @Page
    protected AppPage appPage;

    protected KcOidcBrokerConfiguration bc = brokerConfigFunction.apply(organizationName);

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        testRealm.getClients().addAll(bc.createConsumerClients());
        testRealm.setSmtpServer(null);
        super.configureTestRealm(testRealm);
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        testRealms.add(bc.createProviderRealm());
        super.addTestRealms(testRealms);
    }

    protected OrganizationRepresentation createOrganization() {
        return createOrganization(organizationName);
    }

    protected OrganizationRepresentation createOrganization(String name) {
        return createOrganization(name, name + ".org");
    }

    protected OrganizationRepresentation createOrganization(String name, String... orgDomain) {
        OrganizationRepresentation org = createRepresentation(name, orgDomain);
        String id;

        try (Response response = testRealm().organizations().create(org)) {
            assertEquals(Status.CREATED.getStatusCode(), response.getStatus());
            id = ApiUtil.getCreatedId(response);
        }

        testRealm().organizations().get(id).identityProviders().create(brokerConfigFunction.apply(name).setUpIdentityProvider()).close();
        org = testRealm().organizations().get(id).toRepresentation();
        getCleanup().addCleanup(() -> testRealm().organizations().get(id).delete().close());

        return org;
    }

    protected OrganizationRepresentation createRepresentation(String name, String... orgDomains) {
        OrganizationRepresentation org = new OrganizationRepresentation();
        org.setName(name);

        for (String orgDomain : orgDomains) {
            OrganizationDomainRepresentation domainRep = new OrganizationDomainRepresentation();
            domainRep.setName(orgDomain);
            org.addDomain(domainRep);
        }

        return org;
    }

    protected UserRepresentation addMember(OrganizationResource organization) {
        return addMember(organization, memberEmail);
    }

    protected UserRepresentation addMember(OrganizationResource organization, String email) {
        return addMember(organization, email, null, null);
    }

    protected UserRepresentation addMember(OrganizationResource organization, String email, String firstName, String lastName) {
        UserRepresentation expected = new UserRepresentation();

        expected.setEmail(email);
        expected.setUsername(expected.getEmail());
        expected.setEnabled(true);
        expected.setFirstName(firstName);
        expected.setLastName(lastName);
        Users.setPasswordFor(expected, memberPassword);

        try (Response response = testRealm().users().create(expected)) {
            expected.setId(ApiUtil.getCreatedId(response));
        }

        getCleanup().addCleanup(() -> testRealm().users().get(expected.getId()).remove());

        String userId = expected.getId();

        try (Response response = organization.members().addMember(userId)) {
            assertEquals(Status.CREATED.getStatusCode(), response.getStatus());
            UserRepresentation actual = organization.members().member(userId).toRepresentation();

            assertNotNull(expected);
            assertEquals(userId, actual.getId());
            assertEquals(expected.getUsername(), actual.getUsername());
            assertEquals(expected.getEmail(), actual.getEmail());

            return actual;
        }
    }
}
