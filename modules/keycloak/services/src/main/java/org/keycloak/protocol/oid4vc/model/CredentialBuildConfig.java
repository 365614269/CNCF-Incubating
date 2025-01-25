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

package org.keycloak.protocol.oid4vc.model;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration.CREDENTIAL_BUILD_CONFIG_KEY;
import static org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration.DOT_SEPARATOR;
import static org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration.VERIFIABLE_CREDENTIAL_TYPE_KEY;

/**
 * Define credential-specific configurations for its builder.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class CredentialBuildConfig {

    public static final String MULTIVALUED_STRING_SEPARATOR = ",";

    private static final String TOKEN_JWS_TYPE_KEY = "token_jws_type";
    private static final String HASH_ALGORITHM_KEY = "hash_algorithm";
    private static final String VISIBLE_CLAIMS_KEY = "visible_claims";
    private static final String NUMBER_OF_DECOYS_KEY = "decoys";

    private static final String SIGNING_KEY_ID_KEY = "signing_key_id";
    private static final String OVERRIDE_KEY_ID_KEY = "override_key_id";
    private static final String SIGNING_ALGORITHM_KEY = "signing_algorithm";
    private static final String LDP_PROOF_TYPE_KEY = "ldp_proof_type";

    // This is saved here to facilitate dot notation reconstruction
    private String credentialId;

    //-- Proper building configuration fields --//

    // The vct field to be used for the SD-JWT.
    private String credentialType;

    // The type of the token to be created.
    // Will be used as `typ` claim in the JWT-Header.
    private String tokenJwsType;

    // The hash algorithm to be used for the SD-JWTs.
    private String hashAlgorithm;

    // List of claims to stay disclosed in the SD-JWT.
    private List<String> visibleClaims;

    // The number of decoys to be added to the SD-JWT.
    private Integer numberOfDecoys;

    //-- Signing configuration fields --//

    // The id of the key to be used for signing credentials.
    // The key needs to be provided as a realm key.
    private String signingKeyId;

    // An alternative kid to take precedence.
    // Depending on the did-schema, the above signingKeyId
    // might not be enough and can be overwritten here.
    private String overrideKeyId;

    // The type of the algorithm to be used for signing.
    // Needs to fit the provided signing key.
    private String signingAlgorithm;

    // The type of LD-Proofs to be created.
    // Needs to fit the provided signing key.
    private String ldpProofType;

    public String getCredentialId() {
        return credentialId;
    }

    public CredentialBuildConfig setCredentialId(String credentialId) {
        this.credentialId = credentialId;
        return this;
    }

    public String getTokenJwsType() {
        return tokenJwsType;
    }

    public CredentialBuildConfig setTokenJwsType(String tokenJwsType) {
        this.tokenJwsType = tokenJwsType;
        return this;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public CredentialBuildConfig setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        return this;
    }

    public List<String> getVisibleClaims() {
        return visibleClaims;
    }

    public CredentialBuildConfig setVisibleClaims(List<String> visibleClaims) {
        this.visibleClaims = visibleClaims;
        return this;
    }

    public int getNumberOfDecoys() {
        return numberOfDecoys;
    }

    public CredentialBuildConfig setNumberOfDecoys(int numberOfDecoys) {
        this.numberOfDecoys = numberOfDecoys;
        return this;
    }

    public String getCredentialType() {
        return credentialType;
    }

    public CredentialBuildConfig setCredentialType(String credentialType) {
        this.credentialType = credentialType;
        return this;
    }

    public String getSigningKeyId() {
        return signingKeyId;
    }

    public CredentialBuildConfig setSigningKeyId(String signingKeyId) {
        this.signingKeyId = signingKeyId;
        return this;
    }

    public String getOverrideKeyId() {
        return overrideKeyId;
    }

    public CredentialBuildConfig setOverrideKeyId(String overrideKeyId) {
        this.overrideKeyId = overrideKeyId;
        return this;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public CredentialBuildConfig setSigningAlgorithm(String signingAlgorithm) {
        this.signingAlgorithm = signingAlgorithm;
        return this;
    }

    public String getLdpProofType() {
        return ldpProofType;
    }

    public CredentialBuildConfig setLdpProofType(String ldpProofType) {
        this.ldpProofType = ldpProofType;
        return this;
    }

    public Map<String, String> toDotNotation() {
        Map<String, String> dotNotation = new HashMap<>();

        // vct is skipped because it is not expected nester under CREDENTIAL_BUILD_CONFIG_KEY

        String prefix = getDotNotationPrefix(credentialId);

        Optional.ofNullable(tokenJwsType)
                .ifPresent(tokenJwsType -> dotNotation.put(prefix + TOKEN_JWS_TYPE_KEY, tokenJwsType));
        Optional.ofNullable(hashAlgorithm)
                .ifPresent(hashAlgorithm -> dotNotation.put(prefix + HASH_ALGORITHM_KEY, hashAlgorithm));

        Optional.ofNullable(numberOfDecoys)
                .ifPresent(numberOfDecoys ->
                        dotNotation.put(prefix + NUMBER_OF_DECOYS_KEY, String.valueOf(numberOfDecoys)));

        Optional.ofNullable(visibleClaims)
                .ifPresent(claims -> dotNotation.put(prefix + VISIBLE_CLAIMS_KEY,
                        String.join(MULTIVALUED_STRING_SEPARATOR, claims)));

        Optional.ofNullable(signingKeyId)
                .ifPresent(signingKeyId -> dotNotation.put(prefix + SIGNING_KEY_ID_KEY, signingKeyId));
        Optional.ofNullable(overrideKeyId)
                .ifPresent(overrideKeyId -> dotNotation.put(prefix + OVERRIDE_KEY_ID_KEY, overrideKeyId));
        Optional.ofNullable(signingAlgorithm)
                .ifPresent(signingAlgorithm -> dotNotation.put(prefix + SIGNING_ALGORITHM_KEY, signingAlgorithm));
        Optional.ofNullable(ldpProofType)
                .ifPresent(ldpProofType -> dotNotation.put(prefix + LDP_PROOF_TYPE_KEY, ldpProofType));

        return dotNotation;
    }

    public static CredentialBuildConfig fromDotNotation(String credentialId, Map<String, String> dotNotated) {
        String prefix = getDotNotationPrefix(credentialId);
        if (dotNotated.keySet().stream().noneMatch(key -> key.startsWith(prefix))) {
            return null;
        }

        // Start populating config

        CredentialBuildConfig credentialBuildConfig = new CredentialBuildConfig()
                .setCredentialId(credentialId);

        // No need to redefine `vct` under CREDENTIAL_BUILD_CONFIG_KEY

        Optional.ofNullable(dotNotated.get(credentialId + DOT_SEPARATOR + VERIFIABLE_CREDENTIAL_TYPE_KEY))
                .ifPresent(credentialBuildConfig::setCredentialType);

        // These other fields are nested under CREDENTIAL_BUILD_CONFIG_KEY

        Optional.ofNullable(dotNotated.get(prefix + TOKEN_JWS_TYPE_KEY))
                .ifPresent(credentialBuildConfig::setTokenJwsType);
        Optional.ofNullable(dotNotated.get(prefix + HASH_ALGORITHM_KEY))
                .ifPresent(credentialBuildConfig::setHashAlgorithm);

        Optional.ofNullable(dotNotated.get(prefix + NUMBER_OF_DECOYS_KEY))
                .map(Integer::parseInt)
                .ifPresent(credentialBuildConfig::setNumberOfDecoys);

        Optional.ofNullable(dotNotated.get(prefix + VISIBLE_CLAIMS_KEY))
                .map(cbms -> cbms.split(MULTIVALUED_STRING_SEPARATOR))
                .map(Arrays::asList)
                .ifPresent(credentialBuildConfig::setVisibleClaims);

        Optional.ofNullable(dotNotated.get(prefix + SIGNING_KEY_ID_KEY))
                .ifPresent(credentialBuildConfig::setSigningKeyId);
        Optional.ofNullable(dotNotated.get(prefix + OVERRIDE_KEY_ID_KEY))
                .ifPresent(credentialBuildConfig::setOverrideKeyId);
        Optional.ofNullable(dotNotated.get(prefix + SIGNING_ALGORITHM_KEY))
                .ifPresent(credentialBuildConfig::setSigningAlgorithm);
        Optional.ofNullable(dotNotated.get(prefix + LDP_PROOF_TYPE_KEY))
                .ifPresent(credentialBuildConfig::setLdpProofType);

        return credentialBuildConfig;
    }

    private static String getDotNotationPrefix(String credentialId) {
        return credentialId + DOT_SEPARATOR + CREDENTIAL_BUILD_CONFIG_KEY + DOT_SEPARATOR;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CredentialBuildConfig that = (CredentialBuildConfig) o;
        return Objects.equals(credentialId, that.credentialId) && Objects.equals(credentialType, that.credentialType) && Objects.equals(tokenJwsType, that.tokenJwsType) && Objects.equals(hashAlgorithm, that.hashAlgorithm) && Objects.equals(visibleClaims, that.visibleClaims) && Objects.equals(numberOfDecoys, that.numberOfDecoys) && Objects.equals(signingKeyId, that.signingKeyId) && Objects.equals(overrideKeyId, that.overrideKeyId) && Objects.equals(signingAlgorithm, that.signingAlgorithm) && Objects.equals(ldpProofType, that.ldpProofType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(credentialId, credentialType, tokenJwsType, hashAlgorithm, visibleClaims, numberOfDecoys, signingKeyId, overrideKeyId, signingAlgorithm, ldpProofType);
    }
}
