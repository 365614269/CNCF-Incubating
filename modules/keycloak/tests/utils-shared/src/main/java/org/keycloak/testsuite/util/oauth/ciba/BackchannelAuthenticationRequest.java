package org.keycloak.testsuite.util.oauth.ciba;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.keycloak.OAuth2Constants;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.grants.ciba.CibaGrantType;
import org.keycloak.testsuite.util.oauth.AbstractHttpPostRequest;
import org.keycloak.testsuite.util.oauth.AbstractOAuthClient;

import java.io.IOException;
import java.util.Map;

public class BackchannelAuthenticationRequest extends AbstractHttpPostRequest<BackchannelAuthenticationRequest, AuthenticationRequestAcknowledgement> {

    private final String userid;
    private String bindingMessage;
    private String acrValues;
    private String clientNotificationToken;
    private Map<String, String> additionalParams;

    BackchannelAuthenticationRequest(String userid, AbstractOAuthClient<?> client) {
        super(client);
        this.userid = userid;
    }

    public BackchannelAuthenticationRequest bindingMessage(String bindingMessage) {
        this.bindingMessage = bindingMessage;
        return this;
    }

    public BackchannelAuthenticationRequest acrValues(String acrValues) {
        this.acrValues = acrValues;
        return this;
    }

    public BackchannelAuthenticationRequest clientNotificationToken(String clientNotificationToken) {
        this.clientNotificationToken = clientNotificationToken;
        return this;
    }

    public BackchannelAuthenticationRequest additionalParams(Map<String, String> additionalParams) {
        this.additionalParams = additionalParams;
        return this;
    }

    @Override
    protected String getEndpoint() {
        return client.getEndpoints().getBackchannelAuthentication();
    }

    protected void initRequest() {
        parameter(OIDCLoginProtocol.LOGIN_HINT_PARAM, userid);
        parameter(CibaGrantType.BINDING_MESSAGE, bindingMessage);
        parameter(OAuth2Constants.ACR_VALUES, acrValues);
        parameter(CibaGrantType.CLIENT_NOTIFICATION_TOKEN, clientNotificationToken);
        parameter(OIDCLoginProtocol.REQUEST_URI_PARAM, client.getRequestUri());
        parameter(OIDCLoginProtocol.REQUEST_PARAM, client.getRequest());
        parameter(OIDCLoginProtocol.CLAIMS_PARAM, client.getClaims());

        if (additionalParams != null) {
            additionalParams.forEach(this::parameter);
        }

        scope();
    }

    @Override
    protected AuthenticationRequestAcknowledgement toResponse(CloseableHttpResponse response) throws IOException {
        return new AuthenticationRequestAcknowledgement(response);
    }

}
