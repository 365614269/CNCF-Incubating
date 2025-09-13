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

package org.keycloak.protocol.oid4vc.issuance;

import jakarta.ws.rs.core.UriInfo;
import org.apache.http.HttpHeaders;
import org.keycloak.common.util.Time;
import org.keycloak.constants.Oid4VciConstants;
import org.keycloak.crypto.CryptoUtils;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.CredentialBuilder;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;

import org.keycloak.protocol.oid4vc.model.CredentialResponseEncryptionMetadata;
import org.keycloak.protocol.oid4vc.model.CredentialRequestEncryptionMetadata;
import org.keycloak.protocol.oid4vc.model.SupportedCredentialConfiguration;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.protocol.oidc.utils.JWKSServerUtils;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.MediaType;
import org.keycloak.wellknown.WellKnownProvider;
import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JSONWebKeySet;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.constants.Oid4VciConstants.SIGNED_METADATA_JWT_TYPE;
import static org.keycloak.crypto.KeyType.RSA;
import static org.keycloak.jose.jwk.RSAPublicJWK.RS256;

/**
 * {@link WellKnownProvider} implementation to provide the .well-known/openid-credential-issuer endpoint, offering
 * the Credential Issuer Metadata as defined by the OID4VCI protocol
 * {@see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2.2}
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class OID4VCIssuerWellKnownProvider implements WellKnownProvider {

    private static final Logger LOGGER = Logger.getLogger(OID4VCIssuerWellKnownProvider.class);

    // Realm attributes for signed metadata configuration
    public static final String SIGNED_METADATA_ENABLED_ATTR = "oid4vci.signed_metadata.enabled";
    public static final String SIGNED_METADATA_LIFESPAN_ATTR = "oid4vci.signed_metadata.lifespan";
    public static final String SIGNED_METADATA_ALG_ATTR = "oid4vci.signed_metadata.alg";

    public static final String VC_KEY = "vc";
    public static final String ATTR_ENCRYPTION_REQUIRED = "oid4vci.encryption.required";


    protected final KeycloakSession keycloakSession;

    public OID4VCIssuerWellKnownProvider(KeycloakSession keycloakSession) {
        this.keycloakSession = keycloakSession;
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public Object getConfig() {
        CredentialIssuer issuer = getIssuerMetadata();
        return getMetadataResponse(issuer, keycloakSession);
    }

    public CredentialIssuer getIssuerMetadata() {
        KeycloakContext context = keycloakSession.getContext();
        return new CredentialIssuer()
                .setCredentialIssuer(getIssuer(context))
                .setCredentialEndpoint(getCredentialsEndpoint(context))
                .setNonceEndpoint(getNonceEndpoint(context))
                .setDeferredCredentialEndpoint(getDeferredCredentialEndpoint(context))
                .setCredentialsSupported(getSupportedCredentials(keycloakSession))
                .setAuthorizationServers(List.of(getIssuer(context)))
                .setCredentialResponseEncryption(getCredentialResponseEncryption(keycloakSession))
                .setBatchCredentialIssuance(getBatchCredentialIssuance(keycloakSession))
                .setCredentialRequestEncryption(getCredentialRequestEncryption(keycloakSession));
    }

    public Object getMetadataResponse(CredentialIssuer issuer, KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        String acceptHeader = session.getContext().getRequestHeaders().getHeaderString(HttpHeaders.ACCEPT);
        boolean preferJwt = acceptHeader != null && acceptHeader.contains(MediaType.APPLICATION_JWT);
        boolean signedMetadataEnabled = Boolean.parseBoolean(realm.getAttribute(SIGNED_METADATA_ENABLED_ATTR));

        if (preferJwt && signedMetadataEnabled) {
            Optional<String> signedJwt = generateSignedMetadata(issuer, session);
            if (signedJwt.isPresent()) {
                return signedJwt.get();
            } else {
                LOGGER.debugf("Falling back to JSON response due to signed metadata failure for realm: %s", realm.getName());
            }
        }
        return issuer;
    }

    private static String getDeferredCredentialEndpoint(KeycloakContext context) {
        return getIssuer(context) + "/protocol/" + OID4VCLoginProtocolFactory.PROTOCOL_ID + "/deferred_credential";
    }

    private CredentialIssuer.BatchCredentialIssuance getBatchCredentialIssuance(KeycloakSession session) {
        return getBatchCredentialIssuance(session.getContext().getRealm());
    }

    /**
     * Returns the batch credential issuance configuration for the given realm.
     * This method is public and static to facilitate testing without requiring session state management.
     *
     * @param realm The realm model
     * @return The batch credential issuance configuration or null if not configured or invalid
     */
    public static CredentialIssuer.BatchCredentialIssuance getBatchCredentialIssuance(RealmModel realm) {
        String batchSize = realm.getAttribute(Oid4VciConstants.BATCH_CREDENTIAL_ISSUANCE_BATCH_SIZE);
        if (batchSize != null) {
            try {
                int parsedBatchSize = Integer.parseInt(batchSize);
                if (parsedBatchSize < 2) {
                    LOGGER.warnf("%s must be 2 or greater, but was %d. Skipping batch_credential_issuance.", Oid4VciConstants.BATCH_CREDENTIAL_ISSUANCE_BATCH_SIZE, parsedBatchSize);
                    return null;
                }
                return new CredentialIssuer.BatchCredentialIssuance()
                        .setBatchSize(parsedBatchSize);
            } catch (Exception e) {
                LOGGER.warnf(e, "Failed to parse %s from realm attributes.", Oid4VciConstants.BATCH_CREDENTIAL_ISSUANCE_BATCH_SIZE);
            }
        }
        return null;
    }

    /**
     * Generates signed metadata as a JWS using JsonWebToken infrastructure.
     *
     * @param metadata The CredentialIssuer metadata object to sign.
     * @param session  The Keycloak session.
     * @return Optional containing the compact JWS string if successful, empty if fallback to unsigned JSON is needed.
     */
    public Optional<String> generateSignedMetadata(CredentialIssuer metadata, KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        KeyManager keyManager = session.keys();

        // Select asymmetric signing algorithm
        String alg;
        try {
            alg = getSigningAlgorithm(realm, session);
        } catch (IllegalStateException e) {
            LOGGER.warnf("Failed to get signing algorithm: %s. Falling back to unsigned metadata.", e.getMessage());
            return Optional.empty(); // Return empty to indicate fallback to JSON
        }

        // Retrieve active key
        KeyWrapper keyWrapper = keyManager.getActiveKey(realm, KeyUse.SIG, alg);
        if (keyWrapper == null) {
            LOGGER.warnf("No active key found for realm '%s' with algorithm '%s'. Falling back to unsigned metadata.", realm.getName(), alg);
            return Optional.empty();
        }

        // Create JsonWebToken with metadata as claims
        JsonWebToken jwt = createMetadataJwt(metadata, realm);

        // Validate lifespan configuration
        String lifespanStr = realm.getAttribute(SIGNED_METADATA_LIFESPAN_ATTR);
        if (lifespanStr != null) {
            try {
                long lifespan = Long.parseLong(lifespanStr);
                jwt.exp(Time.currentTime() + lifespan);
            } catch (NumberFormatException e) {
                LOGGER.warnf("Invalid lifespan duration for signed metadata: %s. Falling back to unsigned metadata.", lifespanStr);
                return Optional.empty(); // Return empty to indicate fallback to JSON
            }
        }

        // Build JWS with proper headers
        JWSBuilder jwsBuilder = new JWSBuilder()
                .type(SIGNED_METADATA_JWT_TYPE)
                .kid(keyWrapper.getKid());

        // Add x5c certificate chain if available
        addCertificateHeaders(jwsBuilder, keyWrapper, realm);

        // Sign the JWS
        SignatureProvider signerProvider = session.getProvider(SignatureProvider.class, alg);
        if (signerProvider == null) {
            LOGGER.warnf("No signature provider for algorithm: %s. Falling back to unsigned metadata.", alg);
            return Optional.empty();
        }

        SignatureSignerContext signer = signerProvider.signer(keyWrapper);
        if (signer == null) {
            LOGGER.warnf("No signer context for algorithm: %s. Falling back to unsigned metadata.", alg);
            return Optional.empty();
        }

        try {
            return Optional.of(jwsBuilder.jsonContent(jwt).sign(signer));
        } catch (Exception e) {
            LOGGER.warnf(e, "Failed to sign metadata. Falling back to unsigned metadata.");
            return Optional.empty();
        }
    }


    private String getSigningAlgorithm(RealmModel realm, KeycloakSession session) {
        List<String> supportedAlgorithms = getSupportedAsymmetricSignatureAlgorithms(session);

        if (supportedAlgorithms.isEmpty()) {
            throw new IllegalStateException("No asymmetric signing algorithms available for realm: " + realm.getName());
        }

        String configuredAlg = realm.getAttribute(SIGNED_METADATA_ALG_ATTR);
        if (configuredAlg != null) {
            if (!supportedAlgorithms.contains(configuredAlg)) {
                throw new IllegalStateException("Configured signing algorithm '" + configuredAlg + "' is not supported for realm: " + realm.getName());
            }
            // Use the configured algorithm if present and supported
            return configuredAlg;
        }

        // Prefer RS256 if available, otherwise use the first supported asymmetric algorithm
        return supportedAlgorithms.contains(RS256) ? RS256 : supportedAlgorithms.get(0);
    }

    private JsonWebToken createMetadataJwt(CredentialIssuer metadata, RealmModel realm) {
        JsonWebToken jwt = new JsonWebToken();

        // Set standard JWT claims
        jwt.subject(metadata.getCredentialIssuer());
        jwt.issuer(metadata.getCredentialIssuer());
        jwt.issuedNow();

        // Convert metadata to map and add as other claims
        Map<String, Object> metadataClaims = JsonSerialization.mapper.convertValue(metadata, Map.class);
        metadataClaims.forEach(jwt::setOtherClaims);

        return jwt;
    }

    private void addCertificateHeaders(JWSBuilder jwsBuilder, KeyWrapper keyWrapper, RealmModel realm) {
        if (keyWrapper.getCertificateChain() != null && !keyWrapper.getCertificateChain().isEmpty()) {
            jwsBuilder.x5c(keyWrapper.getCertificateChain());
        } else if (keyWrapper.getCertificate() != null) {
            jwsBuilder.x5c(List.of(keyWrapper.getCertificate()));
        } else {
            LOGGER.debugf("No certificate or certificate chain available for x5c header in realm: %s", realm.getName());
        }
    }


    /**
     * Returns the credential response encryption for the issuer.
     * Now determines supported algorithms from available realm keys.
     *
     * @param session The Keycloak session
     * @return The credential response encryption metadata
     */
    public static CredentialResponseEncryptionMetadata getCredentialResponseEncryption(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        CredentialResponseEncryptionMetadata metadata = new CredentialResponseEncryptionMetadata();

        // Get supported algorithms from available encryption keys
        metadata.setAlgValuesSupported(getSupportedEncryptionAlgorithms(session));
        metadata.setEncValuesSupported(getSupportedEncryptionMethods());
        metadata.setZipValuesSupported(getSupportedCompressionMethods());
        metadata.setEncryptionRequired(isEncryptionRequired(realm));

        return metadata;
    }

    /**
     * Returns the credential request encryption metadata for the issuer.
     * Determines supported algorithms from available realm keys.
     *
     * @param session The Keycloak session
     * @return The credential request encryption metadata
     */
    public static CredentialRequestEncryptionMetadata getCredentialRequestEncryption(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        CredentialRequestEncryptionMetadata metadata = new CredentialRequestEncryptionMetadata();

        // Get supported algorithms from available encryption keys
        metadata.setJwks(getEncryptionJwks(session));
        metadata.setEncValuesSupported(getSupportedEncryptionMethods());
        metadata.setZipValuesSupported(getSupportedCompressionMethods());
        metadata.setEncryptionRequired(isEncryptionRequired(realm));

        return metadata;
    }

    /**
     * Returns the supported encryption algorithms from realm attributes.
     */
    public static List<String> getSupportedEncryptionAlgorithms(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        KeyManager keyManager = session.keys();

        List<String> supportedEncryptionAlgorithms = keyManager.getKeysStream(realm)
                .filter(key -> KeyUse.ENC.equals(key.getUse()))
                .map(KeyWrapper::getAlgorithm)
                .filter(algorithm -> algorithm != null && !algorithm.isEmpty())
                .distinct()
                .collect(Collectors.toList());

        if (supportedEncryptionAlgorithms.isEmpty()) {
            boolean hasRsaKeys = keyManager.getKeysStream(realm)
                    .filter(key -> KeyUse.ENC.equals(key.getUse()))
                    .anyMatch(key -> RSA.equals(key.getType()));

            if (hasRsaKeys) {
                supportedEncryptionAlgorithms.add(JWEConstants.RSA_OAEP);
                supportedEncryptionAlgorithms.add(JWEConstants.RSA_OAEP_256);
            }
        }

        return supportedEncryptionAlgorithms;
    }

    /**
     * Returns the supported encryption methods from realm attributes.
     */
    private static List<String> getSupportedEncryptionMethods() {
        return List.of(JWEConstants.A256GCM);
    }

    /**
     * Returns the supported compression methods from realm attributes.
     *
     * Note: Keycloak's JWE implementation currently only has placeholder support for compression
     * in the JWEHeader class, but no actual compression/decompression logic is implemented.
     * The compression algorithm field exists but is not processed during JWE encoding/decoding.
     *
     * TODO: Implement JWE compression support when Keycloak core adds compression functionality
     */
    private static List<String> getSupportedCompressionMethods() {
        // Keycloak JWE implementation lacks compression support - only header placeholder exists
        return List.of();
    }

    /**
     * Returns the encryption JWKS from realm keys.
     * Filters the realm JWKS to include only encryption keys.
     */
    private static List<JWK> getEncryptionJwks(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        JSONWebKeySet realmJwks = JWKSServerUtils.getRealmJwks(session, realm);

        if (realmJwks.getKeys() == null) {
            return List.of();
        }

        return Stream.of(realmJwks.getKeys())
                .filter(jwk -> KeyUse.ENC.getSpecName().equals(jwk.getPublicKeyUse()))
                .toList();
    }

    /**
     * Returns whether encryption is required from realm attributes.
     */
    private static boolean isEncryptionRequired(RealmModel realm) {
        String required = realm.getAttribute(ATTR_ENCRYPTION_REQUIRED);
        return Boolean.parseBoolean(required);
    }

    /**
     * Return the supported credentials from the current session.
     * It will take into account the configured {@link CredentialBuilder}'s and their supported format
     * and the credentials supported by the clients available in the session.
     */
    public static Map<String, SupportedCredentialConfiguration> getSupportedCredentials(KeycloakSession keycloakSession) {
        List<String> globalSupportedSigningAlgorithms = getSupportedSignatureAlgorithms(keycloakSession);

        RealmModel realm = keycloakSession.getContext().getRealm();
        Map<String, SupportedCredentialConfiguration> supportedCredentialConfigurations =
                keycloakSession.clientScopes()
                        .getClientScopesByProtocol(realm, Oid4VciConstants.OID4VC_PROTOCOL)
                        .map(CredentialScopeModel::new)
                        .map(clientScope -> {
                            return SupportedCredentialConfiguration.parse(keycloakSession,
                                    clientScope,
                                    globalSupportedSigningAlgorithms
                            );
                        })
                        .collect(Collectors.toMap(SupportedCredentialConfiguration::getId, sc -> sc, (sc1, sc2) -> sc1));

        return supportedCredentialConfigurations;
    }

    public static SupportedCredentialConfiguration toSupportedCredentialConfiguration(KeycloakSession keycloakSession,
                                                                                      CredentialScopeModel credentialModel) {
        List<String> globalSupportedSigningAlgorithms = getSupportedSignatureAlgorithms(keycloakSession);
        return SupportedCredentialConfiguration.parse(keycloakSession,
                credentialModel,
                globalSupportedSigningAlgorithms);
    }

    /**
     * Return the url of the issuer.
     */
    public static String getIssuer(KeycloakContext context) {
        UriInfo frontendUriInfo = context.getUri(UrlType.FRONTEND);
        return Urls.realmIssuer(frontendUriInfo.getBaseUri(),
                context.getRealm().getName());
    }

    /**
     * Return the nonce endpoint address
     */
    public static String getNonceEndpoint(KeycloakContext context) {
        return getIssuer(context) + "/protocol/" + OID4VCLoginProtocolFactory.PROTOCOL_ID + "/" +
                OID4VCIssuerEndpoint.NONCE_PATH;
    }

    /**
     * Return the credentials endpoint address
     */
    public static String getCredentialsEndpoint(KeycloakContext context) {
        return getIssuer(context) + "/protocol/" + OID4VCLoginProtocolFactory.PROTOCOL_ID + "/" + OID4VCIssuerEndpoint.CREDENTIAL_PATH;
    }

    public static List<String> getSupportedSignatureAlgorithms(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        KeyManager keyManager = session.keys();

        return keyManager.getKeysStream(realm)
                .filter(key -> KeyUse.SIG.equals(key.getUse()))
                .map(KeyWrapper::getAlgorithm)
                .filter(algorithm -> algorithm != null && !algorithm.isEmpty())
                .distinct()
                .collect(Collectors.toList());
    }

    /**
     * Returns the supported asymmetric signature algorithms.
     * Delegates to CryptoUtils for shared implementation with OIDCWellKnownProvider.
     * This includes all asymmetric algorithms supported by Keycloak (RSA, EC, EdDSA).
     */
    public static List<String> getSupportedAsymmetricSignatureAlgorithms(KeycloakSession session) {
        return CryptoUtils.getSupportedAsymmetricSignatureAlgorithms(session);
    }

}
