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

package org.keycloak.testsuite.organization.member;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.keycloak.models.OrganizationModel.ORGANIZATION_ATTRIBUTE;
import static org.keycloak.testsuite.broker.BrokerTestTools.waitForPage;

import java.util.ArrayList;
import java.util.List;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import java.io.IOException;

import org.hamcrest.Matchers;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.keycloak.admin.client.resource.OrganizationMemberResource;
import org.keycloak.admin.client.resource.OrganizationResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.common.Profile.Feature;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.representations.idm.ErrorRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.MemberRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.keycloak.representations.userprofile.config.UPConfig.UnmanagedAttributePolicy;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.organization.admin.AbstractOrganizationTest;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.updaters.RealmAttributeUpdater;

@EnableFeature(Feature.ORGANIZATION)
public class OrganizationMemberTest extends AbstractOrganizationTest {

    @Test
    public void testUpdate() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        UserRepresentation expected = getUserRepFromMemberRep(addMember(organization));

        expected.setFirstName("f");
        expected.setLastName("l");
        expected.setEmail("some@differentthanorg.com");

        testRealm().users().get(expected.getId()).update(expected);

        UserRepresentation existing = organization.members().member(expected.getId()).toRepresentation();
        assertEquals(expected.getId(), existing.getId());
        assertEquals(expected.getUsername(), existing.getUsername());
        assertEquals(expected.getEmail(), existing.getEmail());
        assertEquals(expected.getFirstName(), existing.getFirstName());
        assertEquals(expected.getLastName(), existing.getLastName());
    }

    @Test
    public void testFailSetUserOrganizationAttribute() {
        UPConfig upConfig = testRealm().users().userProfile().getConfiguration();
        upConfig.setUnmanagedAttributePolicy(UnmanagedAttributePolicy.ENABLED);
        testRealm().users().userProfile().update(upConfig);
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        UserRepresentation expected = getUserRepFromMemberRep(addMember(organization));

        expected.singleAttribute(ORGANIZATION_ATTRIBUTE, "invalid");

        UserResource userResource = testRealm().users().get(expected.getId());

        try {
            userResource.update(expected);
            Assert.fail("The attribute is readonly");
        } catch (BadRequestException bre) {
            ErrorRepresentation error = bre.getResponse().readEntity(ErrorRepresentation.class);
            assertEquals(ORGANIZATION_ATTRIBUTE, error.getField());
            assertEquals("error-user-attribute-read-only", error.getErrorMessage());
        }

        // the attribute is readonly, removing it from the rep does not make any difference
        expected.getAttributes().remove(ORGANIZATION_ATTRIBUTE);
        userResource.update(expected);
        expected = userResource.toRepresentation();
        assertNull(expected.getAttributes());
        getTestingClient().server(TEST_REALM_NAME).run(OrganizationMemberTest::assertMembersHaveOrgAttribute);
    }

    private static void assertMembersHaveOrgAttribute(KeycloakSession session) {
        OrganizationModel organization = session.getProvider(OrganizationProvider.class).getByDomainName("neworg.org");
        assertTrue(session.getProvider(OrganizationProvider.class).getMembersStream(organization, null, false, -1, -1).
                anyMatch(userModel -> userModel.getAttributes().getOrDefault(ORGANIZATION_ATTRIBUTE, List.of()).contains(organization.getId())));
    }

    @Test
    public void testUserAlreadyMemberOfOrganization() {
        UPConfig upConfig = testRealm().users().userProfile().getConfiguration();
        upConfig.setUnmanagedAttributePolicy(UnmanagedAttributePolicy.ENABLED);
        testRealm().users().userProfile().update(upConfig);
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        UserRepresentation expected = addMember(organization, KeycloakModelUtils.generateId() + "@user.org");

        try (Response response = organization.members().addMember(expected.getId())) {
            assertEquals(Status.CONFLICT.getStatusCode(), response.getStatus());
        }
    }

    @Test
    public void testGet() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        UserRepresentation expected = addMember(organization);
        UserRepresentation existing = organization.members().member(expected.getId()).toRepresentation();
        assertEquals(expected.getId(), existing.getId());
        assertEquals(expected.getUsername(), existing.getUsername());
        assertEquals(expected.getEmail(), existing.getEmail());
    }

    @Test
    public void testGetMemberOrganization() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        UserRepresentation member = addMember(organization);
        OrganizationRepresentation expected = organization.toRepresentation();
        OrganizationRepresentation actual = organization.members().getOrganization(member.getId());
        assertNotNull(actual);
        assertEquals(expected.getId(), actual.getId());
    }

    @Test
    public void testGetAll() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        List<UserRepresentation> expected = new ArrayList<>();

        for (int i = 0; i < 5; i++) {
            expected.add(addMember(organization, "member-" + i + "@neworg.org"));
        }

        List<MemberRepresentation> existing = organization.members().getAll();
        assertFalse(existing.isEmpty());
        assertEquals(expected.size(), existing.size());
        for (UserRepresentation expectedRep : expected) {
            UserRepresentation existingRep = existing.stream().filter(member -> member.getId().equals(expectedRep.getId())).findAny().orElse(null);
            assertNotNull(existingRep);
            assertEquals(expectedRep.getId(), existingRep.getId());
            assertEquals(expectedRep.getUsername(), existingRep.getUsername());
            assertEquals(expectedRep.getEmail(), existingRep.getEmail());
            assertEquals(expectedRep.getFirstName(), existingRep.getFirstName());
            assertEquals(expectedRep.getLastName(), existingRep.getLastName());
            assertTrue(expectedRep.isEnabled());
        }
    }

    @Test
    public void testGetAllDisabledOrganization() {
        OrganizationRepresentation orgRep = createOrganization();
        OrganizationResource organization = testRealm().organizations().get(orgRep.getId());

        // add some unmanaged members to the organization.
        for (int i = 0; i < 5; i++) {
            addMember(organization, "member-" + i + "@neworg.org");
        }

        // onboard a test user by authenticating using the organization's provider.
        super.assertBrokerRegistration(organization, bc.getUserLogin(), bc.getUserEmail());

        // disable the organization and check that fetching its representation has it disabled.
        orgRep.setEnabled(false);
        try (Response response = organization.update(orgRep)) {
            assertEquals(Status.NO_CONTENT.getStatusCode(), response.getStatus());
        }
        OrganizationRepresentation existingOrg = organization.toRepresentation();
        assertThat(orgRep.getId(), is(equalTo(existingOrg.getId())));
        assertThat(orgRep.getName(), is(equalTo(existingOrg.getName())));
        assertThat(existingOrg.isEnabled(), is(false));

        // now fetch all users from the org - unmanaged users should still be enabled, but managed ones should not.
        List<MemberRepresentation> existing = organization.members().getAll();
        assertThat(existing, not(empty()));
        assertThat(existing, hasSize(6));
        for (UserRepresentation user : existing) {
            if (user.getEmail().equals(bc.getUserEmail())) {
                assertThat(user.isEnabled(), is(false));
            } else {
                assertThat(user.isEnabled(), is(true));
            }
        }

        // fetching users from the users endpoint should have the same result.
        UserRepresentation disabledUser = null;
        List<UserRepresentation> existingUsers = testRealm().users().search("*neworg*",0, 10);
        assertThat(existingUsers, not(empty()));
        assertThat(existingUsers, hasSize(6));
        for (UserRepresentation user : existingUsers) {
            if (user.getEmail().equals(bc.getUserEmail())) {
                assertThat(user.isEnabled(), is(false));
                disabledUser = user;
            } else {
                assertThat(user.isEnabled(), is(true));
            }
        }

        assertThat(disabledUser, notNullValue());
        // try to update the disabled user (for example, try to re-enable the user) - should not be possible.
        disabledUser.setEnabled(true);
        try {
            testRealm().users().get(disabledUser.getId()).update(disabledUser);
            fail("Should not be possible to update disabled org user");
        } catch(BadRequestException ignored) {
        }
    }

    @Test
    public void testGetAllDisabledOrganizationProvider() throws IOException {
        OrganizationRepresentation orgRep = createOrganization();
        OrganizationResource organization = testRealm().organizations().get(orgRep.getId());

        // add some unmanaged members to the organization.
        for (int i = 0; i < 5; i++) {
            addMember(organization, "member-" + i + "@neworg.org");
        }

        // onboard a test user by authenticating using the organization's provider.
        super.assertBrokerRegistration(organization, bc.getUserLogin(), bc.getUserEmail());

        // now fetch all users from the realm
        List<UserRepresentation> members = testRealm().users().search("*neworg*", null, null);
        members.stream().forEach(user -> assertThat(user.isEnabled(), is(Boolean.TRUE)));

        // disable the organization provider
        try (RealmAttributeUpdater rau = new RealmAttributeUpdater(testRealm())
                .setOrganizationsEnabled(Boolean.FALSE)
                .update()) {

            // now fetch all members from the realm - unmanaged users should still be enabled, but managed ones should not.
            List<UserRepresentation> existing = testRealm().users().search("*neworg*", null, null);
            assertThat(existing, hasSize(members.size()));
            for (UserRepresentation user : existing) {
                if (user.getEmail().equals(bc.getUserEmail())) {
                    assertThat(user.isEnabled(), is(Boolean.FALSE));

                    // try to update the disabled user (for example, try to re-enable the user) - should not be possible.
                    user.setEnabled(Boolean.TRUE);
                    try {
                        testRealm().users().get(user.getId()).update(user);
                        fail("Should not be possible to update disabled org user");
                    } catch(BadRequestException expected) {}
                } else {
                    assertThat("User " + user.getUsername(), user.isEnabled(), is(true));
                }
            }
        }
    }

    @Test
    public void testDeleteUnmanagedMember() {
        UPConfig upConfig = testRealm().users().userProfile().getConfiguration();
        upConfig.setUnmanagedAttributePolicy(UnmanagedAttributePolicy.ENABLED);
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        UserRepresentation expected = addMember(organization);
        assertNotNull(expected.getAttributes());
        assertNull(expected.getAttributes().get(ORGANIZATION_ATTRIBUTE));
        OrganizationMemberResource member = organization.members().member(expected.getId());

        try (Response response = member.delete()) {
            assertEquals(Status.NO_CONTENT.getStatusCode(), response.getStatus());
        }

        // user should exist but no longer an organization member
        expected = testRealm().users().get(expected.getId()).toRepresentation();
        assertNull(expected.getAttributes());
        try {
            member.toRepresentation();
            fail("should not be an organization member");
        } catch (NotFoundException ignore) {

        }
    }

    @Test
    public void testUpdateEmailUnmanagedMember() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        UserRepresentation expected = getUserRepFromMemberRep(addMember(organization));
        expected.setEmail("some@unknown.org");
        UserResource userResource = testRealm().users().get(expected.getId());
        userResource.update(expected);
        UserRepresentation actual = userResource.toRepresentation();
        assertEquals(expected.getId(), actual.getId());
        assertEquals(expected.getEmail(), actual.getEmail());

    }

    private UserRepresentation getUserRepFromMemberRep(MemberRepresentation member) {
        return new UserRepresentation(member);
    }

    @Test
    public void testDeleteMembersOnOrganizationRemoval() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        List<MemberRepresentation> expected = new ArrayList<>();

        for (int i = 0; i < 5; i++) {
            expected.add(addMember(organization, "member-" + i + "@neworg.org"));
        }

        organization.delete().close();

        for (MemberRepresentation member : expected) {
            try {
                organization.members().member(member.getId()).toRepresentation();
                fail("should be deleted");
            } catch (NotFoundException ignore) {}
        }

        for (MemberRepresentation member : expected) {
            // users should exist as they are not managed by the organization
            testRealm().users().get(member.getId()).toRepresentation();
        }

        for (MemberRepresentation member : expected) {
            try {
                // user no longer bound to the organization
                organization.members().getOrganization(member.getId());
                fail("should not be associated with the organization anymore");
            } catch (NotFoundException ignore) {
            }
        }
    }

    @Test
    public void testSearchMembers() {

        // create test users, ordered by username (e-mail).
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        List<UserRepresentation> expected = new ArrayList<>();
        expected.add(addMember(organization, "batwoman@neworg.org", "Katherine", "Kane"));
        expected.add(addMember(organization, "brucewayne@neworg.org", "Bruce", "Wayne"));
        expected.add(addMember(organization, "harveydent@neworg.org", "Harvey", "Dent"));
        expected.add(addMember(organization, "marthaw@neworg.org", "Martha", "Wayne"));
        expected.add(addMember(organization, "thejoker@neworg.org", "Jack", "White"));

        // exact search - username/e-mail, first name, last name.
        List<MemberRepresentation> existing = organization.members().search("brucewayne@neworg.org", true, null, null);
        assertThat(existing, hasSize(1));
        assertThat(existing.get(0).getUsername(), is(equalTo("brucewayne@neworg.org")));
        assertThat(existing.get(0).getEmail(), is(equalTo("brucewayne@neworg.org")));
        assertThat(existing.get(0).getFirstName(), is(equalTo("Bruce")));
        assertThat(existing.get(0).getLastName(), is(equalTo("Wayne")));

        existing = organization.members().search("Harvey", true, null, null);
        assertThat(existing, hasSize(1));
        assertThat(existing.get(0).getUsername(), is(equalTo("harveydent@neworg.org")));
        assertThat(existing.get(0).getEmail(), is(equalTo("harveydent@neworg.org")));
        assertThat(existing.get(0).getFirstName(), is(equalTo("Harvey")));
        assertThat(existing.get(0).getLastName(), is(equalTo("Dent")));

        existing = organization.members().search("Wayne", true, null, null);
        assertThat(existing, hasSize(2));
        assertThat(existing.get(0).getUsername(), is(equalTo("brucewayne@neworg.org")));
        assertThat(existing.get(1).getUsername(), is(equalTo("marthaw@neworg.org")));

        existing = organization.members().search("Gordon", true, null, null);
        assertThat(existing, is(empty()));

        // partial search - partial e-mail should match all users.
        existing = organization.members().search("neworg", false, null, null);
        assertThat(existing, hasSize(5));
        for (int i = 0; i < 5; i++) { // returned entries should also be ordered.
            assertThat(expected.get(i).getId(), is(equalTo(expected.get(i).getId())));
            assertThat(expected.get(i).getUsername(), is(equalTo(expected.get(i).getUsername())));
            assertThat(expected.get(i).getEmail(), is(equalTo(expected.get(i).getEmail())));
            assertThat(expected.get(i).getFirstName(), is(equalTo(expected.get(i).getFirstName())));
            assertThat(expected.get(i).getLastName(), is(equalTo(expected.get(i).getLastName())));
        }

        // partial search using 'th' search string - should match 'Katherine' by name, 'Jack' by username/e-mail
        // and 'Martha' either by username or first name.
        existing = organization.members().search("th", false, null, null);
        assertThat(existing, hasSize(3));
        assertThat(existing.get(0).getUsername(), is(equalTo("batwoman@neworg.org")));
        assertThat(existing.get(0).getFirstName(), is(equalTo("Katherine")));
        assertThat(existing.get(1).getUsername(), is(equalTo("marthaw@neworg.org")));
        assertThat(existing.get(1).getFirstName(), is(equalTo("Martha")));
        assertThat(existing.get(2).getUsername(), is(equalTo("thejoker@neworg.org")));
        assertThat(existing.get(2).getFirstName(), is(equalTo("Jack")));

        // partial search using 'way' - should match both 'Bruce' (either by username or last name) and 'Martha' by last name.
        existing = organization.members().search("way", false, null, null);
        assertThat(existing, hasSize(2));
        assertThat(existing.get(0).getUsername(), is(equalTo("brucewayne@neworg.org")));
        assertThat(existing.get(0).getFirstName(), is(equalTo("Bruce")));
        assertThat(existing.get(1).getUsername(), is(equalTo("marthaw@neworg.org")));
        assertThat(existing.get(1).getFirstName(), is(equalTo("Martha")));

        // partial search using with no match - e.g. 'nonexistent'.
        existing = organization.members().search("nonexistent", false, null, null);
        assertThat(existing, is(empty()));

        // paginated search - try to fetch 3 users per page.
        existing = organization.members().search("", false, 0, 3);
        assertThat(existing, hasSize(3));
        assertThat(existing.get(0).getUsername(), is(equalTo("batwoman@neworg.org")));
        assertThat(existing.get(1).getUsername(), is(equalTo("brucewayne@neworg.org")));
        assertThat(existing.get(2).getUsername(), is(equalTo("harveydent@neworg.org")));

        existing = organization.members().search("", false, 3, 3);
        assertThat(existing, hasSize(2));
        assertThat(existing.get(0).getUsername(), is(equalTo("marthaw@neworg.org")));
        assertThat(existing.get(1).getUsername(), is(equalTo("thejoker@neworg.org")));
    }

    @Test
    public void testAddMemberFromDifferentRealm() {
        String orgId = createOrganization().getId();

        getTestingClient().server(TEST_REALM_NAME).run(session -> {
            OrganizationProvider provider = session.getProvider(OrganizationProvider.class);
            OrganizationModel organization = provider.getById(orgId);

            RealmModel realm = session.realms().getRealmByName("master");
            session.users().addUser(realm, "master-test-user");
            UserModel user = null;
            try {
                user = session.users().getUserByUsername(realm, "master-test-user");
                assertFalse(provider.addMember(organization, user));
            } finally {
                session.users().removeUser(realm, user);
            }
        });
    }

    @Test
    public void testUserFederatedBeforeTheIDPBoundWithAnOrgIsNotMember() {
        // create non-org idp in a realm
        String idpAlias = "former-non-org-identity-provider";
        IdentityProviderRepresentation idpRep = brokerConfigFunction.apply("former-non-org").setUpIdentityProvider();
        try (Response response = testRealm().identityProviders().create(idpRep)) {
            assertThat(response.getStatus(), equalTo(Status.CREATED.getStatusCode()));
            getCleanup().addCleanup(testRealm().identityProviders().get(bc.getIDPAlias())::remove);
        }

        loginViaNonOrgIdP(idpAlias);

        List<UserRepresentation> search = testRealm().users().search(bc.getUserLogin(), Boolean.TRUE);
        assertThat(search, hasSize(1));

        // create org
        String orgDomain = organizationName + ".org";
        OrganizationRepresentation orgRep = createRepresentation(organizationName, orgDomain);
        String id;

        try (Response response = testRealm().organizations().create(orgRep)) {
            assertThat(response.getStatus(), equalTo(Status.CREATED.getStatusCode()));
            id = ApiUtil.getCreatedId(response);
            getCleanup().addCleanup(() -> testRealm().organizations().get(id).delete().close());
        }

        // assign IdP to the org
        idpRep.getConfig().put(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE, orgDomain);
        idpRep.getConfig().put(OrganizationModel.IdentityProviderRedirectMode.EMAIL_MATCH.getKey(), Boolean.TRUE.toString());
        
        try (Response response = testRealm().organizations().get(id).identityProviders().addIdentityProvider(idpAlias)) {
            assertThat(response.getStatus(), equalTo(Status.NO_CONTENT.getStatusCode()));
        }

        //check the federated user is not a member
        assertThat(testRealm().organizations().get(id).members().getAll(), hasSize(0));
    }

    private void loginViaNonOrgIdP(String idpAlias) {
        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());

        assertTrue(loginPage.isPasswordInputPresent());
        assertTrue(loginPage.isSocialButtonPresent(idpAlias));
        loginPage.clickSocial(idpAlias);

        waitForPage(driver, "sign in to", true);

        // user automatically redirected to the identity provider
        assertThat("Driver should be on the provider realm page right now",
                driver.getCurrentUrl(), Matchers.containsString("/auth/realms/" + bc.providerRealmName() + "/"));
        
        loginPage.login(bc.getUserLogin(), bc.getUserPassword());

        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation(bc.getUserLogin(), bc.getUserEmail(), "Firstname", "Lastname");

        appPage.assertCurrent();
        assertThat(appPage.getRequestType(), equalTo(AppPage.RequestType.AUTH_RESPONSE));
    }
}
