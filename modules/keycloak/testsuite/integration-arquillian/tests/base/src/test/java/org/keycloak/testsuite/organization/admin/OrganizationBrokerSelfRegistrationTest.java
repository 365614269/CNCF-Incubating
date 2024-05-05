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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.keycloak.testsuite.broker.BrokerTestTools.waitForPage;

import java.util.List;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import org.junit.Test;
import org.keycloak.admin.client.resource.OrganizationIdentityProviderResource;
import org.keycloak.admin.client.resource.OrganizationMemberResource;
import org.keycloak.admin.client.resource.OrganizationResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.common.Profile.Feature;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.ErrorRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.OrganizationDomainRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.util.UserBuilder;

@EnableFeature(Feature.ORGANIZATION)
public class OrganizationBrokerSelfRegistrationTest extends AbstractOrganizationTest {

    @Test
    public void testRegistrationRedirectWhenSingleBroker() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        assertBrokerRegistration(organization, bc.getUserEmail());
    }

    @Test
    public void testLoginHintSentToBrokerWhenEnabled() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        IdentityProviderRepresentation idp = organization.identityProviders().get(bc.getIDPAlias()).toRepresentation();
        idp.getConfig().put(IdentityProviderModel.LOGIN_HINT, "true");
        organization.identityProviders().get(bc.getIDPAlias()).update(idp).close();

        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        Assert.assertFalse(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));
        loginPage.loginUsername(bc.getUserEmail());

        // user automatically redirected to the organization identity provider
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        // check if the username is automatically filled
        Assert.assertEquals(bc.getUserEmail(), loginPage.getUsername());
    }

    @Test
    public void testDefaultAuthenticationMechanismIfNotOrganizationMember() {
        testRealm().organizations().get(createOrganization().getId());
        oauth.clientId("broker-app");

        // login with email only
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        Assert.assertFalse(loginPage.isPasswordInputPresent());
        loginPage.loginUsername("user@noorg.org");

        // check if the login page is shown
        Assert.assertTrue(loginPage.isUsernameInputPresent());
        Assert.assertTrue(loginPage.isPasswordInputPresent());
    }

    @Test
    public void testRealmLevelBrokersAvailableIfEmailDoesNotMatchOrganization() {
        testRealm().organizations().get(createOrganization().getId());
        oauth.clientId("broker-app");

        // login with email only
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        Assert.assertFalse(loginPage.isPasswordInputPresent());
        loginPage.loginUsername("user");

        // check if the login page is shown
        Assert.assertTrue(loginPage.isUsernameInputPresent());
        Assert.assertTrue(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));

        IdentityProviderRepresentation idp = bc.setUpIdentityProvider();
        idp.setAlias("realm-level-idp");
        Assert.assertFalse(loginPage.isSocialButtonPresent(idp.getAlias()));
        testRealm().identityProviders().create(idp).close();

        driver.navigate().refresh();

        Assert.assertTrue(loginPage.isUsernameInputPresent());
        Assert.assertTrue(loginPage.isPasswordInputPresent());
        Assert.assertTrue(loginPage.isSocialButtonPresent(idp.getAlias()));
    }

    @Test
    public void testLinkExistingAccount() {
        // create a realm user in the consumer realm
        realmsResouce().realm(bc.consumerRealmName()).users()
                .create(UserBuilder.create()
                    .username(bc.getUserLogin())
                    .email(bc.getUserEmail())
                    .password(bc.getUserPassword())
                    .enabled(true).build()
                ).close();

        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        oauth.clientId("broker-app");

        // login with email only
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        loginPage.loginUsername(bc.getUserEmail());

        // user automatically redirected to the organization identity provider
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));

        // login to the organization identity provider and run the configured first broker login flow
        loginPage.login(bc.getUserEmail(), bc.getUserPassword());
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation(bc.getUserEmail(), bc.getUserEmail(), "Firstname", "Lastname");

        // account with the same email exists in the realm, execute account linking
        waitForPage(driver, "account already exists", false);
        idpConfirmLinkPage.assertCurrent();
        idpConfirmLinkPage.clickLinkAccount();
        // confirm the link by authenticating
        loginPage.login(bc.getUserEmail(), bc.getUserPassword());
        assertIsMember(bc.getUserEmail(), organization);
    }

    @Test
    public void testReAuthenticateWhenAlreadyMember() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());

        // add the member for the first time
        assertBrokerRegistration(organization, bc.getUserEmail());

        // logout to force the user to authenticate again
        UserRepresentation account = getUserRepresentation(bc.getUserEmail());
        realmsResouce().realm(bc.consumerRealmName()).users().get(account.getId()).logout();

        // login with email only
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        loginPage.loginUsername(bc.getUserEmail());

        // user automatically redirected to the organization identity provider
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));

        // login to the organization identity provider and automatically redirects to the app as the account already exists
        loginPage.login(bc.getUserEmail(), bc.getUserPassword());
        appPage.assertCurrent();
        assertIsMember(bc.getUserEmail(), organization);
    }

    @Test
    public void testFailUpdateEmailNotAssociatedOrganizationUsingAdminAPI() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        OrganizationIdentityProviderResource idp = organization.identityProviders().get(bc.getIDPAlias());
        IdentityProviderRepresentation idpRep = idp.toRepresentation();
        idpRep.getConfig().put(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE, "neworg.org");
        idp.update(idpRep).close();

        // add the member for the first time
        assertBrokerRegistration(organization, bc.getUserEmail());
        UserRepresentation member = getUserRepresentation(bc.getUserEmail());

        member.setEmail(KeycloakModelUtils.generateId() + "@user.org");

        try {
            // member has a hard link with the organization, and the email must match the domains set to the organization
            testRealm().users().get(member.getId()).update(member);
            fail("Should fail because email domain does not match any from organization");
        } catch (BadRequestException expected) {
            ErrorRepresentation error = expected.getResponse().readEntity(ErrorRepresentation.class);
            assertEquals(UserModel.EMAIL, error.getField());
            assertEquals("Email domain does not match any domain from the organization", error.getErrorMessage());
        }

        member.setEmail(member.getEmail().replace("@user.org", "@" + organizationName + ".org"));
        testRealm().users().get(member.getId()).update(member);
    }

    @Test
    public void testDeleteManagedMember() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());

        // add the member for the first time
        assertBrokerRegistration(organization, bc.getUserEmail());
        UserRepresentation member = getUserRepresentation(bc.getUserEmail());
        OrganizationMemberResource organizationMember = organization.members().member(member.getId());

        organizationMember.delete().close();

        try {
            testRealm().users().get(member.getId()).toRepresentation();
            fail("it is managed member should be removed from the realm");
        } catch (NotFoundException expected) {
        }

        try {
            organizationMember.toRepresentation();
            fail("it is managed member should be removed from the realm");
        } catch (NotFoundException expected) {
        }
    }

    @Test
    public void testRedirectToIdentityProviderAssociatedWithOrganizationDomain() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        IdentityProviderRepresentation idp = organization.identityProviders().get(bc.getIDPAlias()).toRepresentation();
        idp.getConfig().put(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE, "neworg.org");
        organization.identityProviders().get(bc.getIDPAlias()).update(idp).close();
        idp.setAlias("second-idp");
        idp.setInternalId(null);
        idp.getConfig().remove(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE);
        organization.identityProviders().create(idp).close();

        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        Assert.assertFalse(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));
        Assert.assertFalse(loginPage.isSocialButtonPresent(idp.getAlias()));
        loginPage.loginUsername(bc.getUserEmail());

        // user automatically redirected to the organization identity provider
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        loginPage.login(bc.getUserEmail(), bc.getUserPassword());
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation(bc.getUserEmail(), bc.getUserEmail(), "Firstname", "Lastname");
        appPage.assertCurrent();
        assertIsMember(bc.getUserEmail(), organization);
        UserRepresentation user = testRealm().users().search(bc.getUserEmail()).get(0);
        List<FederatedIdentityRepresentation> federatedIdentities = testRealm().users().get(user.getId()).getFederatedIdentity();
        assertEquals(1, federatedIdentities.size());
        assertEquals(bc.getIDPAlias(), federatedIdentities.get(0).getIdentityProvider());
    }

    @Test
    public void testIdentityFirstLoginShowsPublicOrganizationBrokers() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        OrganizationRepresentation representation = organization.toRepresentation();
        representation.addDomain(new OrganizationDomainRepresentation("other.org"));
        organization.update(representation).close();
        IdentityProviderRepresentation idp = organization.identityProviders().get(bc.getIDPAlias()).toRepresentation();
        idp.getConfig().put(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE, "neworg.org");
        // set a domain to the existing broker
        organization.identityProviders().get(bc.getIDPAlias()).update(idp).close();

        idp = bc.setUpIdentityProvider();
        idp.setAlias("second-idp");
        idp.setInternalId(null);
        idp.getConfig().remove(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE);
        idp.getConfig().put(OrganizationModel.BROKER_PUBLIC, Boolean.TRUE.toString());
        // create a second broker without a domain set
        organization.identityProviders().create(idp).close();
        idp = organization.identityProviders().get(idp.getAlias()).toRepresentation();

        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        Assert.assertFalse(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));
        Assert.assertFalse(loginPage.isSocialButtonPresent(idp.getAlias()));
        loginPage.loginUsername("external@user.org");
        Assert.assertTrue(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));
        Assert.assertTrue(loginPage.isSocialButtonPresent(idp.getAlias()));

        idp.getConfig().put(OrganizationModel.BROKER_PUBLIC, Boolean.FALSE.toString());
        organization.identityProviders().get(idp.getAlias()).update(idp).close();
        driver.navigate().refresh();
        Assert.assertTrue(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));
        Assert.assertFalse(loginPage.isSocialButtonPresent(idp.getAlias()));
    }

    @Test
    public void testLoginUsingBrokerWithoutDomain() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        IdentityProviderRepresentation idp = organization.identityProviders().get(bc.getIDPAlias()).toRepresentation();
        idp.getConfig().put(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE, "neworg.org");
        // set a domain to the existing broker
        organization.identityProviders().get(bc.getIDPAlias()).update(idp).close();

        idp = bc.setUpIdentityProvider();
        idp.setAlias("second-idp");
        idp.setInternalId(null);
        idp.getConfig().remove(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE);
        idp.getConfig().put(OrganizationModel.BROKER_PUBLIC, Boolean.TRUE.toString());
        // create a second broker without a domain set
        organization.identityProviders().create(idp).close();

        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        Assert.assertFalse(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));
        String email = "external@user.org";
        loginPage.loginUsername(email);
        loginPage.clickSocial(idp.getAlias());

        // user automatically redirected to the organization identity provider
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        loginPage.login("external", "password");
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation(email, email, "Firstname", "Lastname");
        appPage.assertCurrent();
        assertIsMember(email, organization);

        // make sure the federated identity matches the expected broker
        UserRepresentation user = testRealm().users().search(email).get(0);
        List<FederatedIdentityRepresentation> federatedIdentities = testRealm().users().get(user.getId()).getFederatedIdentity();
        assertEquals(1, federatedIdentities.size());
        assertEquals(idp.getAlias(), federatedIdentities.get(0).getIdentityProvider());
    }

    @Test
    public void testEmailDomainDoesNotMatchBrokerDomain() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        OrganizationRepresentation representation = organization.toRepresentation();
        representation.addDomain(new OrganizationDomainRepresentation("other.org"));
        organization.update(representation).close();
        IdentityProviderRepresentation idp = organization.identityProviders().get(bc.getIDPAlias()).toRepresentation();
        idp.getConfig().put(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE, "neworg.org");
        // set a domain to the existing broker
        organization.identityProviders().get(bc.getIDPAlias()).update(idp).close();

        idp = bc.setUpIdentityProvider();
        idp.setAlias("second-idp");
        idp.setInternalId(null);
        idp.getConfig().put(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE, "other.org");
        idp.getConfig().put(OrganizationModel.BROKER_PUBLIC, Boolean.TRUE.toString());
        // create a second broker without a domain set
        organization.identityProviders().create(idp).close();

        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        Assert.assertFalse(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));
        String email = "external@user.org";
        loginPage.loginUsername(email);
        loginPage.clickSocial(idp.getAlias());

        // user automatically redirected to the organization identity provider
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        loginPage.login(email, "password");
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation(email, email, "Firstname", "Lastname");
        Assert.assertTrue(driver.getPageSource().contains("Email domain does not match any domain from the organization"));
        assertIsNotMember(email, organization);
        updateAccountInformationPage.updateAccountInformation("external@other.org", "external@other.org", "Firstname", "Lastname");
        appPage.assertCurrent();
        assertIsMember("external@other.org", organization);
    }

    @Test
    public void testAnyEmailFromBrokerWithoutDomainSet() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        OrganizationRepresentation representation = organization.toRepresentation();
        representation.addDomain(new OrganizationDomainRepresentation("other.org"));
        organization.update(representation).close();
        IdentityProviderRepresentation idp = organization.identityProviders().get(bc.getIDPAlias()).toRepresentation();
        idp.getConfig().put(OrganizationModel.ORGANIZATION_DOMAIN_ATTRIBUTE, "neworg.org");
        // set a domain to the existing broker
        organization.identityProviders().get(bc.getIDPAlias()).update(idp).close();

        idp = bc.setUpIdentityProvider();
        idp.setAlias("second-idp");
        idp.setInternalId(null);
        idp.getConfig().put(OrganizationModel.BROKER_PUBLIC, Boolean.TRUE.toString());
        // create a second broker without a domain set
        organization.identityProviders().create(idp).close();

        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        Assert.assertFalse(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));
        String email = "external@user.org";
        loginPage.loginUsername(email);
        loginPage.clickSocial(idp.getAlias());

        // user automatically redirected to the organization identity provider
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        loginPage.login(email, "password");
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation("external@unknown.org", "external@unknown.org", "Firstname", "Lastname");
        appPage.assertCurrent();
        assertIsMember("external@unknown.org", organization);
    }

    @Test
    public void testRealmLevelBrokerNotImpactedByOrganizationFlow() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        IdentityProviderRepresentation idp = bc.setUpIdentityProvider();
        idp.setAlias("realm-idp");
        idp.setInternalId(null);
        // create a second broker without a domain set
        testRealm().identityProviders().create(idp).close();

        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        Assert.assertFalse(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));
        loginPage.loginUsername("some@user.org");
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the consumer realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        loginPage.clickSocial(idp.getAlias());

        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        loginPage.login("external", "password");
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation(bc.getUserEmail(), bc.getUserEmail(), "Firstname", "Lastname");
        appPage.assertCurrent();
        assertTrue(organization.members().getAll().isEmpty());

        UserRepresentation user = testRealm().users().search(bc.getUserEmail()).get(0);
        testRealm().users().get(user.getId()).remove();
    }

    @Test
    public void testMemberRegistrationUsingDifferentDomainThanOrganization() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        IdentityProviderRepresentation idpRep = organization.identityProviders().getIdentityProviders().get(0);

        // make sure the user can select this idp from the organization when authenticating
        idpRep.getConfig().put(OrganizationModel.BROKER_PUBLIC, Boolean.TRUE.toString());
        organization.identityProviders().get(idpRep.getAlias()).update(idpRep).close();

        // create a user to the provider realm using a email that does not share the same domain as the org
        UserRepresentation user = UserBuilder.create()
                .username("user")
                .email("user@different.org")
                .password("password")
                .enabled(true)
                .build();
        realmsResouce().realm(bc.providerRealmName()).users().create(user).close();

        // select the organization broker to authenticate
        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());
        loginPage.loginUsername("user@different.org");
        loginPage.clickSocial(idpRep.getAlias());

        // login through the organization broker
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        loginPage.login("user@different.org", "password");
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation(user.getUsername(), user.getEmail(), "Firstname", "Lastname");
        appPage.assertCurrent();
    }

    @Test
    public void testMemberFromBrokerRedirectedToOriginBroker() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        IdentityProviderRepresentation idpRep = organization.identityProviders().getIdentityProviders().get(0);

        // make sure the user can select this idp from the organization when authenticating
        idpRep.getConfig().put(OrganizationModel.BROKER_PUBLIC, Boolean.TRUE.toString());
        organization.identityProviders().get(idpRep.getAlias()).update(idpRep).close();

        // create a user to the provider realm using a email that does not share the same domain as the org
        UserRepresentation user = UserBuilder.create()
                .username("user")
                .email("user@different.org")
                .password("password")
                .enabled(true)
                .build();
        realmsResouce().realm(bc.providerRealmName()).users().create(user).close();

        // execute the identity-first login
        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());
        loginPage.loginUsername(user.getEmail());

        waitForPage(driver, "sign in to", true);
        // select the organization broker to authenticate
        assertTrue(loginPage.isPasswordInputPresent());
        assertTrue(loginPage.isUsernameInputPresent());
        loginPage.clickSocial(idpRep.getAlias());

        // login through the organization broker
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        loginPage.login("user@different.org", "password");
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation(user.getUsername(), user.getEmail(), "Firstname", "Lastname");
        UserRepresentation account = getUserRepresentation(user.getEmail());
        realmsResouce().realm(bc.consumerRealmName()).users().get(account.getId()).logout();

        // the flow now changed and the user should be automatically redirected to the origin broker
        loginPage.open(bc.consumerRealmName());
        waitForPage(driver, "sign in to", true);
        loginPage.loginUsername(user.getEmail());
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        loginPage.login("user@different.org", "password");
        appPage.assertCurrent();
    }

    private void assertBrokerRegistration(OrganizationResource organization, String email) {
        // login with email only
        oauth.clientId("broker-app");
        loginPage.open(bc.consumerRealmName());
        log.debug("Logging in");
        Assert.assertFalse(loginPage.isPasswordInputPresent());
        Assert.assertFalse(loginPage.isSocialButtonPresent(bc.getIDPAlias()));
        loginPage.loginUsername(email);

        // user automatically redirected to the organization identity provider
        waitForPage(driver, "sign in to", true);
        Assert.assertTrue("Driver should be on the provider realm page right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));
        // login to the organization identity provider and run the configured first broker login flow
        loginPage.login(email, bc.getUserPassword());
        waitForPage(driver, "update account information", false);
        updateAccountInformationPage.assertCurrent();
        Assert.assertTrue("We must be on correct realm right now",
                driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));
        log.debug("Updating info on updateAccount page");
        updateAccountInformationPage.updateAccountInformation(bc.getUserLogin(), email, "Firstname", "Lastname");

        assertIsMember(email, organization);
    }

    private void assertIsMember(String userEmail, OrganizationResource organization) {
        UserRepresentation account = getUserRepresentation(userEmail);
        UserRepresentation member = organization.members().member(account.getId()).toRepresentation();
        Assert.assertEquals(account.getId(), member.getId());
    }

    private void assertIsNotMember(String userEmail, OrganizationResource organization) {
        UsersResource users = adminClient.realm(bc.consumerRealmName()).users();
        List<UserRepresentation> reps = users.searchByEmail(userEmail, true);

        if (reps.isEmpty()) {
            return;
        }

        assertEquals(1, reps.size());
        UserRepresentation account = reps.get(0);

        try {
            assertNull(organization.members().member(account.getId()).toRepresentation());
        } catch (NotFoundException ignore) {
        }
    }

    private UserRepresentation getUserRepresentation(String userEmail) {
        UsersResource users = adminClient.realm(bc.consumerRealmName()).users();
        List<UserRepresentation> reps = users.searchByEmail(userEmail, true);
        Assert.assertFalse(reps.isEmpty());
        Assert.assertEquals(1, reps.size());
        return reps.get(0);
    }
}
