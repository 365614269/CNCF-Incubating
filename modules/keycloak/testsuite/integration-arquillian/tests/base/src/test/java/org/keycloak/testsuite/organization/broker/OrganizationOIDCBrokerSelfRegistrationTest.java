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

package org.keycloak.testsuite.organization.broker;

import org.junit.Test;
import org.keycloak.admin.client.resource.OrganizationResource;
import org.keycloak.common.Profile.Feature;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;

import java.util.List;

import static org.junit.Assert.assertEquals;

@EnableFeature(Feature.ORGANIZATION)
public class OrganizationOIDCBrokerSelfRegistrationTest extends AbstractBrokerSelfRegistrationTest {

    @Test
    public void testMaskedSecretInIDPRepresentation() {
        OrganizationResource organization = testRealm().organizations().get(createOrganization().getId());
        List<IdentityProviderRepresentation> identityProviders = organization.identityProviders().getIdentityProviders();

        String maskedSecret = "**********";

        identityProviders.forEach(idp -> assertEquals(maskedSecret, idp.getConfig().get("clientSecret")));

        identityProviders.stream().map(IdentityProviderRepresentation::getAlias).forEach(alias -> {
            IdentityProviderRepresentation rep = organization.identityProviders().get(alias).toRepresentation();
            assertEquals(maskedSecret, rep.getConfig().get("clientSecret"));
        });
    }
}
