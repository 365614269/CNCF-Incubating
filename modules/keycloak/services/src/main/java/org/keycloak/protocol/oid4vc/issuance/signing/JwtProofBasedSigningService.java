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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.model.Proof;
import org.keycloak.protocol.oid4vc.model.ProofType;
import org.keycloak.protocol.oid4vc.model.ProofTypeJWT;
import org.keycloak.protocol.oid4vc.model.ProofTypesSupported;
import org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;

/**
 * Common signing service logic to handle proofs.
 *
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public abstract class JwtProofBasedSigningService<T> extends SigningService<T> {

    private static final Logger LOGGER = Logger.getLogger(JwtProofBasedSigningService.class);
    private static final String CRYPTOGRAPHIC_BINDING_METHOD_JWK = "jwk";
    public static final String PROOF_JWT_TYP="openid4vci-proof+jwt";

    protected JwtProofBasedSigningService(KeycloakSession keycloakSession, String keyId, String format, String type) {
        super(keycloakSession, keyId, format, type);
    }

    /*
     * Validates a proof provided by the client if any.
     *
     * Returns null if there is no need to include a key binding in the credential
     *
     * Return the JWK to be included as key binding in the JWK if the provided proof was correctly validated
     *
     * @param vcIssuanceContext
     * @return
     * @throws VCIssuerException
     * @throws JWSInputException
     * @throws VerificationException
     * @throws IllegalStateException: is credential type badly configured
     * @throws IOException
     */
    protected JWK validateProof(VCIssuanceContext vcIssuanceContext) throws VCIssuerException, JWSInputException, VerificationException, IOException {

        Optional<Proof> optionalProof = getProofFromContext(vcIssuanceContext);

        if (optionalProof.isEmpty()) {
            return null; // No proof support
        }

        // Check key binding config for jwt. Only type supported.
        checkCryptographicKeyBinding(vcIssuanceContext);

        JWSInput jwsInput = getJwsInput(optionalProof.get());
        JWSHeader jwsHeader = jwsInput.getHeader();
        validateJwsHeader(vcIssuanceContext, jwsHeader);

        JWK jwk = Optional.ofNullable(jwsHeader.getKey())
                .orElseThrow(() -> new VCIssuerException("Missing binding key. Make sure provided JWT contains the jwk jwsHeader claim."));

        // Parsing the Proof as an access token shall work, as a proof is a strict subset of an access token.
        AccessToken proofPayload = JsonSerialization.readValue(jwsInput.getContent(), AccessToken.class);
        validateProofPayload(vcIssuanceContext, proofPayload);

        SignatureVerifierContext signatureVerifierContext = getVerifier(jwk, jwsHeader.getAlgorithm().name());
        if (signatureVerifierContext == null) {
            throw new VCIssuerException("No verifier configured for " + jwsHeader.getAlgorithm());
        }
        if (!signatureVerifierContext.verify(jwsInput.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8), jwsInput.getSignature())) {
            throw new VCIssuerException("Could not verify provided proof");
        }

        return jwk;
    }

    private void checkCryptographicKeyBinding(VCIssuanceContext vcIssuanceContext){
        // Make sure we are dealing with a jwk proof.
        if (vcIssuanceContext.getCredentialConfig().getCryptographicBindingMethodsSupported() == null ||
                !vcIssuanceContext.getCredentialConfig().getCryptographicBindingMethodsSupported().contains(CRYPTOGRAPHIC_BINDING_METHOD_JWK)) {
            throw new IllegalStateException("This SD-JWT implementation only supports jwk as cryptographic binding method");
        }
    }

    private Optional<Proof> getProofFromContext(VCIssuanceContext vcIssuanceContext) throws VCIssuerException {
        return Optional.ofNullable(vcIssuanceContext.getCredentialConfig())
                .map(SupportedCredentialConfiguration::getProofTypesSupported)
                .flatMap(proofTypesSupported -> {
                    Optional.ofNullable(proofTypesSupported.getJwt())
                            .orElseThrow(() -> new VCIssuerException("SD-JWT supports only jwt proof type."));

                    Proof proof = Optional.ofNullable(vcIssuanceContext.getCredentialRequest().getProof())
                            .orElseThrow(() -> new VCIssuerException("Credential configuration requires a proof of type: " + ProofType.JWT));

                    if (!Objects.equals(proof.getProofType(), ProofType.JWT)) {
                        throw new VCIssuerException("Wrong proof type");
                    }

                    return Optional.of(proof);
                });
    }

    private JWSInput getJwsInput(Proof proof) throws JWSInputException {
        return new JWSInput(proof.getJwt());
    }

    /**
     * As we limit accepted algorithm to the ones listed by the issuer, we can omit checking for "none"
     * The Algorithm enum class does not list the none value anyway.
     *
     * @param vcIssuanceContext
     * @param jwsHeader
     * @throws VCIssuerException
     */
    private void validateJwsHeader(VCIssuanceContext vcIssuanceContext, JWSHeader jwsHeader) throws VCIssuerException {
        Optional.ofNullable(jwsHeader.getAlgorithm())
                .orElseThrow(() -> new VCIssuerException("Missing jwsHeader claim alg"));

        // As we limit accepted algorithm to the ones listed by the server, we can omit checking for "none"
        // The Algorithm enum class does not list the none value anyway.
        Optional.ofNullable(vcIssuanceContext.getCredentialConfig())
                .map(SupportedCredentialConfiguration::getProofTypesSupported)
                .map(ProofTypesSupported::getJwt)
                .map(ProofTypeJWT::getProofSigningAlgValuesSupported)
                .filter(supportedAlgs -> supportedAlgs.contains(jwsHeader.getAlgorithm().name()))
                .orElseThrow(() -> new VCIssuerException("Proof signature algorithm not supported: " + jwsHeader.getAlgorithm().name()));

        Optional.ofNullable(jwsHeader.getType())
                .filter(type -> Objects.equals(PROOF_JWT_TYP, type))
                .orElseThrow(() -> new VCIssuerException("JWT type must be: " + PROOF_JWT_TYP));

        // KeyId shall not be present alongside the jwk.
        Optional.ofNullable(jwsHeader.getKeyId())
                .ifPresent(keyId -> {
                    throw new VCIssuerException("KeyId not expected in this JWT. Use the jwk claim instead.");
                });
    }

    private void validateProofPayload(VCIssuanceContext vcIssuanceContext, AccessToken proofPayload) throws VCIssuerException {
        // azp is the id of the client, as mentioned in the access token used to request the credential.
        // Token provided from user is obtained with a clientId that support the oidc login protocol.
        // oid4vci client doesn't. But it is the client needed at the credential endpoint.
        //        String azp = vcIssuanceContext.getAuthResult().getToken().getIssuedFor();
        //        Optional.ofNullable(proofPayload.getIssuer())
        //                .filter(proofIssuer -> Objects.equals(azp, proofIssuer))
        //                .orElseThrow(() -> new VCIssuerException("Issuer claim must be null for preauthorized code else the clientId of the client making the request: " + azp));

        // The issuer is the token / credential is the audience of the proof
        String credentialIssuer = vcIssuanceContext.getVerifiableCredential().getIssuer().toString();
        Optional.ofNullable(proofPayload.getAudience()) // Ensure null-safety with Optional
                .map(Arrays::asList) // Convert to List<String>
                .filter(audiences -> audiences.contains(credentialIssuer)) // Check if the issuer is in the audience list
                .orElseThrow(() -> new VCIssuerException(
                        "Proof not produced for this audience. Audience claim must be: " + credentialIssuer + " but are " + Arrays.asList(proofPayload.getAudience())));

        // Validate mandatory iat.
        // I do not understand the rationale behind requiring an issue time if we are not checking expiration.
        Optional.ofNullable(proofPayload.getIat())
                .orElseThrow(() -> new VCIssuerException("Missing proof issuing time. iat claim must be provided."));

        // Check cNonce matches.
        // If the token endpoint provides a c_nonce, we would like this:
        // - stored in the access token
        // - having the same validity as the access token.
        Optional.ofNullable(vcIssuanceContext.getAuthResult().getToken().getNonce())
                        .ifPresent(
                                cNonce -> {
                                    Optional.ofNullable(proofPayload.getNonce())
                                            .filter(nonce -> Objects.equals(cNonce, nonce))
                                            .orElseThrow(() -> new VCIssuerException("Missing or wrong nonce value. Please provide nonce returned by the issuer if any."));

                                    // We expect the expiration to be identical to the token expiration. We assume token expiration has been checked by AuthManager,
                                    // So no_op
                                }
                        );

    }
}
