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

package org.keycloak.protocol.oid4vc.issuance.signing;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.VerifiableCredential;

/**
 * {@link VerifiableCredentialsSigningService} implementing the SD_JWT_VC format. It returns a String, containing
 * the signed SD-JWT
 * <p>
 * {@see https://drafts.oauth.net/oauth-sd-jwt-vc/draft-ietf-oauth-sd-jwt-vc.html}
 * {@see https://www.ietf.org/archive/id/draft-fett-oauth-selective-disclosure-jwt-02.html}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class SdJwtSigningService extends SigningService<String> {

    public SdJwtSigningService(KeycloakSession keycloakSession, String keyId, String algorithmType) {
        super(keycloakSession, keyId, algorithmType);
    }

    @Override
    public String signCredential(VerifiableCredential verifiableCredential) {
        throw new UnsupportedOperationException("SD-JWT Signing is not yet supported.");
    }
}