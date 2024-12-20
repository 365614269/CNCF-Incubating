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

package org.keycloak.protocol.oid4vc.issuance.credentialbuilder;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtCredentialBuilderFactory implements CredentialBuilderFactory {

    @Override
    public String getId() {
        return Format.SD_JWT_VC;
    }

    @Override
    public String getHelpText() {
        return "Builds verifiable credentials on the SD-JWT format (https://drafts.oauth.net/oauth-sd-jwt-vc/draft-ietf-oauth-sd-jwt-vc.html).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public CredentialBuilder create(KeycloakSession session, ComponentModel model) {
        // Use the credential issuer URI advertised on the metadata endpoint by default.
        // An issuer DID configured at the realm level overrides that value.
        String credentialIssuer = CredentialBuilderUtils.getIssuerDid(session)
                .orElse(OID4VCIssuerWellKnownProvider.getIssuer(session.getContext()));

        return new SdJwtCredentialBuilder(credentialIssuer);
    }
}
