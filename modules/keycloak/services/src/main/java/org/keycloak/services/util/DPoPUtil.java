/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.services.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

import org.apache.commons.codec.binary.Hex;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.exceptions.TokenVerificationException;
import org.keycloak.http.HttpRequest;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenResponseMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;
import org.keycloak.util.JWKSUtils;

import static org.keycloak.utils.StringUtil.isNotBlank;

/**
 * @author <a href="mailto:dmitryt@backbase.com">Dmitry Telegin</a>
 */
public class DPoPUtil {

    public static final int DEFAULT_PROOF_LIFETIME = 10;
    public static final int DEFAULT_ALLOWED_CLOCK_SKEW = 2;
    public static final String DPOP_TOKEN_TYPE = "DPoP";
    public static final String DPOP_SCHEME = "DPoP";
    public final static String DPOP_SESSION_ATTRIBUTE = "dpop";

    public static enum Mode {
        ENABLED,
        OPTIONAL,
        DISABLED
    }

    public static final String DPOP_HTTP_HEADER = "DPoP";
    private static final String DPOP_JWT_HEADER_TYPE = "dpop+jwt";
    private static final String DPOP_ATH_ALG = "RS256";

    public static final Set<String> DPOP_SUPPORTED_ALGS = Stream.of(
        Algorithm.ES256,
        Algorithm.ES384,
        Algorithm.ES512,
        Algorithm.PS256,
        Algorithm.PS384,
        Algorithm.PS512,
        Algorithm.RS256,
        Algorithm.RS384,
        Algorithm.RS512
    ).collect(Collectors.toSet());

    private static URI normalize(URI uri) {
        return UriBuilder.fromUri(uri).replaceQuery("").build();
    }

    /**
     * creates a protocol mapper that cannot be modified by administration users and that is used to bind AccessTokens
     * to specific DPoP keys. <br />
     * <br />
     * NOTE: The binding was solved with a protocol mapper to have generic solution for DPoP on all implemented
     *       grantTypes, even custom-implemented grantTypes.
     */
    public static Stream<Map.Entry<ProtocolMapperModel, ProtocolMapper>> getTransientProtocolMapper() {
        final String PROVIDER_ID = DPOP_SCHEME.toLowerCase(Locale.ROOT) + "-protocol-mapper";

        ProtocolMapperModel protocolMapperModel = new ProtocolMapperModel();
        protocolMapperModel.setId(DPOP_SCHEME);
        protocolMapperModel.setName(DPOP_SCHEME);
        protocolMapperModel.setProtocolMapper(PROVIDER_ID);
        protocolMapperModel.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<>();
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "false");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "false");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION, "false");
        protocolMapperModel.setConfig(config);

        ProtocolMapper dpopProtocolMapper = new DpopProtocolMapper(PROVIDER_ID);
        return Stream.of(Map.entry(protocolMapperModel, dpopProtocolMapper));
    }

    /**
     * checks the current request if a DPoP HTTP Header is present and returns it if it is present.
     */
    public static Optional<DPoP> retrieveDPoPHeaderIfPresent(KeycloakSession keycloakSession,
                                                             OIDCAdvancedConfigWrapper clientConfig,
                                                             EventBuilder event,
                                                             Cors cors) {
        boolean isDPoPSupported = Profile.isFeatureEnabled(Profile.Feature.DPOP);
        if (!isDPoPSupported) {
            return Optional.empty();
        }

        HttpRequest request = keycloakSession.getContext().getHttpRequest();
        final boolean isClientRequiresDpop = clientConfig != null && clientConfig.isUseDPoP();
        final boolean isDpopHeaderPresent = request.getHttpHeaders().getHeaderString(DPoPUtil.DPOP_HTTP_HEADER) != null;
        if (!isClientRequiresDpop && !isDpopHeaderPresent) {
            return Optional.empty();
        }

        try {
            DPoP dPoP = new DPoPUtil.Validator(keycloakSession).request(request).uriInfo(keycloakSession.getContext().getUri()).validate();
            keycloakSession.setAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE, dPoP);
            return Optional.of(dPoP);
        } catch (VerificationException ex) {
            event.detail(Details.REASON, ex.getMessage());
            event.error(Errors.INVALID_DPOP_PROOF);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_DPOP_PROOF, ex.getMessage(), Response.Status.BAD_REQUEST);
        }
    }

    private static DPoP validateDPoP(KeycloakSession session, URI uri, String method, String token, String accessToken, int lifetime, int clockSkew) throws VerificationException {

        if (token == null || token.trim().equals("")) {
            throw new VerificationException("DPoP proof is missing");
        }

        TokenVerifier<DPoP> verifier = TokenVerifier.create(token, DPoP.class);
        JWSHeader header;

        try {
            header = verifier.getHeader();
        } catch (VerificationException ex) {
            throw new VerificationException("DPoP header verification failure");
        }

        if (!DPOP_JWT_HEADER_TYPE.equals(header.getType())) {
            throw new VerificationException("Invalid or missing type in DPoP header: " + header.getType());
        }

        String algorithm = header.getAlgorithm().name();

        if (!DPOP_SUPPORTED_ALGS.contains(algorithm)) {
            throw new VerificationException("Unsupported DPoP algorithm: " + header.getAlgorithm());
        }

        JWK jwk = header.getKey();
        KeyWrapper key;

        if (jwk == null) {
            throw new VerificationException("No JWK in DPoP header");
        } else {
            key = JWKSUtils.getKeyWrapper(jwk);
            if (key.getPublicKey() == null) {
                throw new VerificationException("No public key in DPoP header");
            }
            if (key.getPrivateKey() != null) {
                throw new VerificationException("Private key is present in DPoP header");
            }
        }

        key.setAlgorithm(header.getAlgorithm().name());

        SignatureVerifierContext signatureVerifier = session.getProvider(SignatureProvider.class, algorithm).verifier(key);
        verifier.verifierContext(signatureVerifier);
        verifier.withChecks(
                DPoPClaimsCheck.INSTANCE,
                new DPoPHTTPCheck(uri, method),
                new DPoPIsActiveCheck(session, lifetime, clockSkew),
                new DPoPReplayCheck(session, lifetime));

        if (accessToken != null) {
            verifier.withChecks(new DPoPAccessTokenHashCheck(accessToken));
        }

        try {
            DPoP dPoP = verifier.verify().getToken();
            dPoP.setThumbprint(JWKSUtils.computeThumbprint(jwk));
            return dPoP;
        } catch (DPoPVerificationException ex) {
            throw ex;
        } catch (VerificationException ex) {
            throw new VerificationException("DPoP verification failure: " + ex.getMessage(), ex);
        }

    }

    public static void validateBinding(AccessToken token, DPoP dPoP) throws VerificationException {
        try {
            TokenVerifier.createWithoutSignature(token)
                    .withChecks(new DPoPUtil.DPoPBindingCheck(dPoP))
                    .verify();
        } catch (TokenVerificationException ex) {
            throw ex;
        } catch (VerificationException ex) {
            throw new VerificationException("Token verification failure", ex);
        }
    }

    public static void bindToken(AccessToken token, String thumbprint) {
        AccessToken.Confirmation confirmation = token.getConfirmation();

        if (confirmation == null) {
            confirmation = new AccessToken.Confirmation();
            token.setConfirmation(confirmation);
        }

        confirmation.setKeyThumbprint(thumbprint);
    }

    public static void bindToken(AccessToken token, DPoP dPoP) {
        bindToken(token, dPoP.getThumbprint());
    }

    private static class DPoPClaimsCheck implements TokenVerifier.Predicate<DPoP> {

        static final TokenVerifier.Predicate<DPoP> INSTANCE = new DPoPClaimsCheck();

        @Override
        public boolean test(DPoP t) throws DPoPVerificationException {
            Long iat = t.getIat();
            String jti = t.getId();
            String htu = t.getHttpUri();
            String htm = t.getHttpMethod();

            if (iat != null &&
                isNotBlank(jti) &&
                isNotBlank(htm) &&
                isNotBlank(htu)) {
                return true;
            } else {
                throw new DPoPVerificationException(t, "DPoP mandatory claims are missing");
            }
        }

    }

    private static class DPoPHTTPCheck implements TokenVerifier.Predicate<DPoP> {

        private final URI uri;
        private final String method;

        DPoPHTTPCheck(URI uri, String method) {
            this.uri = uri;
            this.method = method;
        }

        @Override
        public boolean test(DPoP t) throws DPoPVerificationException {
            try {
                if (!normalize(new URI(t.getHttpUri())).equals(normalize(uri)))
                    throw new DPoPVerificationException(t, "DPoP HTTP URL mismatch");

                if (!method.equals(t.getHttpMethod()))
                    throw new DPoPVerificationException(t, "DPoP HTTP method mismatch");
            } catch (URISyntaxException ex) {
                throw new DPoPVerificationException(t, "Malformed HTTP URL in DPoP proof");
            }

            return true;
        }

    }

    private static class DPoPReplayCheck implements TokenVerifier.Predicate<DPoP> {

        private final KeycloakSession session;
        private final int lifetime;

        public DPoPReplayCheck(KeycloakSession session, int lifetime) {
            this.session = session;
            this.lifetime = lifetime;
        }

        @Override
        public boolean test(DPoP t) throws DPoPVerificationException {
            SingleUseObjectProvider singleUseCache = session.singleUseObjects();
            byte[] hash = HashUtils.hash("SHA1", (t.getId() + "\n" + t.getHttpUri()).getBytes());
            String hashString = Hex.encodeHexString(hash);
            if (!singleUseCache.putIfAbsent(hashString, (int)(t.getIat() + lifetime - Time.currentTime()))) {
                throw new DPoPVerificationException(t, "DPoP proof has already been used");
            }
            return true;
        }

    }

    private static class DPoPIsActiveCheck implements TokenVerifier.Predicate<DPoP> {

        private final int lifetime;
        private final int clockSkew;

        public DPoPIsActiveCheck(KeycloakSession session, int lifetime, int clockSkew) {
            this.lifetime = lifetime;
            this.clockSkew = clockSkew;
        }

        @Override
        public boolean test(DPoP t) throws DPoPVerificationException {
            long time = Time.currentTime();
            Long iat = t.getIat();

            if (!(iat <= time + clockSkew && iat > time - lifetime)) {
                throw new DPoPVerificationException(t, "DPoP proof is not active");
            }
            return true;
        }
    }

    private static class DPoPAccessTokenHashCheck implements TokenVerifier.Predicate<DPoP> {

        private String hash;

        public DPoPAccessTokenHashCheck(String tokenString) {
            hash = HashUtils.accessTokenHash(DPOP_ATH_ALG, tokenString, true);
        }

        @Override
        public boolean test(DPoP t) throws DPoPVerificationException {
            if (t.getAccessTokenHash() == null) {
                throw new DPoPVerificationException(t, "No access token hash in DPoP proof");
            }
            if (!t.getAccessTokenHash().equals(hash)) {
                throw new DPoPVerificationException(t, "DPoP proof access token hash mismatch");
            }
            return true;
        }

    }

    private static class DPoPBindingCheck implements TokenVerifier.Predicate<AccessToken> {

        private final DPoP proof;

        public DPoPBindingCheck(DPoP proof) {
            this.proof = proof;
        }

        @Override
        public boolean test(AccessToken t) throws VerificationException {
            String thumbprint = proof.getThumbprint();

            AccessToken.Confirmation confirmation = t.getConfirmation();
            if (confirmation == null) {
                throw new TokenVerificationException(t, "No DPoP confirmation in access token");
            }
            String keyThumbprint = confirmation.getKeyThumbprint();
            if (keyThumbprint == null) {
                throw new TokenVerificationException(t, "No DPoP key thumbprint in access token");
            }
            if (!keyThumbprint.equals(thumbprint)) {
                throw new TokenVerificationException(t, "DPoP confirmation doesn't match DPoP proof");
            }
            return true;
        }

    }

    public static class DPoPVerificationException extends TokenVerificationException {

        public DPoPVerificationException(DPoP token, String message) {
            super(token, message);
        }

    }

    public static class Validator {

        private URI uri;
        private String method;
        private String dPoP;
        private String accessToken;
        private int clockSkew = DEFAULT_ALLOWED_CLOCK_SKEW;
        private int lifetime = DEFAULT_PROOF_LIFETIME;

        private final KeycloakSession session;

        public Validator(KeycloakSession session) {
            this.session = session;
        }

        public Validator request(HttpRequest request) {
            this.uri = request.getUri().getAbsolutePath();
            this.method = request.getHttpMethod();
            this.dPoP = request.getHttpHeaders().getHeaderString(DPOP_HTTP_HEADER);
            return this;
        }

        public Validator dPoP(String dPoP) {
            this.dPoP = dPoP;
            return this;
        }

        public Validator accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public Validator uriInfo(UriInfo uriInfo) {
            this.uri = uriInfo.getAbsolutePath();
            return this;
        }

        public Validator uri(String uri) throws URISyntaxException {
            this.uri = new URI(uri);
            return this;
        }

        public Validator method(String method) {
            this.method = method;
            return this;
        }

        public DPoP validate() throws VerificationException {
            return validateDPoP(session, uri, method, dPoP, accessToken, lifetime, clockSkew);
        }

    }

    /**
     * a custom protocol mapper that is not meant for configuration in the Admin-UI. This mapper is created on the
     * fly for TokenRequests to bind the created generated AccessTokens to the key of the DPoP HTTP Header.
     */
    private static final class DpopProtocolMapper extends AbstractOIDCProtocolMapper
            implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper,
            OIDCAccessTokenResponseMapper {

        private final String providerId;

        public DpopProtocolMapper(String providerId) {
            this.providerId = providerId;
        }

        @Override
        public String getDisplayCategory() {
            return TOKEN_MAPPER_CATEGORY;
        }

        @Override
        public String getDisplayType() {
            return DPOP_SCHEME;
        }

        @Override
        public String getHelpText() {
            return "not needed";
        }

        @Override
        public List<ProviderConfigProperty> getConfigProperties() {
            return List.of(new ProviderConfigProperty("multivalued", ProtocolMapperUtils.MULTIVALUED, "",
                                                      ProviderConfigProperty.BOOLEAN_TYPE, false));
        }

        @Override
        public String getId() {
            return providerId;
        }

        @Override
        public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
            boolean isDPoPSupported = Profile.isFeatureEnabled(Profile.Feature.DPOP);
            if (!isDPoPSupported) {
                return super.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);
            }

            DPoP dPoP = session.getAttribute(DPOP_SESSION_ATTRIBUTE, DPoP.class);
            if (dPoP == null) {
                return super.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);
            }
            AccessToken.Confirmation confirmation = (AccessToken.Confirmation) token.getOtherClaims()
                    .get(OAuth2Constants.CNF);
            if (confirmation == null) {
                confirmation = new AccessToken.Confirmation();
                token.setConfirmation(confirmation);
            }
            confirmation.setKeyThumbprint(dPoP.getThumbprint());
            // make sure that the token-type is set to DPoP. This will be resolved if the AccessTokenResponse is built.
            token.type(DPOP_TOKEN_TYPE);
            return super.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);
        }
    }
}
