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

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

import java.net.URI;
import java.util.Optional;
import java.util.UUID;

public class CredentialBuilderUtils {

    private static final String ISSUER_DID_REALM_ATTRIBUTE_KEY = "issuerDid";
    private static final String ID_TEMPLATE = "urn:uuid:%s";

    // retrieve the credential id from the given VC or generate one.
    public static String createCredentialId(VerifiableCredential verifiableCredential) {
        return Optional.ofNullable(verifiableCredential.getId())
                .orElse(URI.create(String.format(ID_TEMPLATE, UUID.randomUUID())))
                .toString();
    }

    public static Optional<String> getIssuerDid(KeycloakSession keycloakSession) {
        RealmModel realm = keycloakSession.getContext().getRealm();
        return Optional.ofNullable(realm.getAttribute(ISSUER_DID_REALM_ATTRIBUTE_KEY));
    }
}
