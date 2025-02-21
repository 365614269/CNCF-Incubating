package org.keycloak.testsuite.util.oauth;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.keycloak.OAuth2Constants;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.util.TokenUtil;

import java.io.IOException;

public class PasswordGrantRequest extends AbstractHttpPostRequest<PasswordGrantRequest, AccessTokenResponse> {

    private final String username;
    private final String password;
    private String otp;

    PasswordGrantRequest(String username, String password, AbstractOAuthClient<?> client) {
        super(client);
        this.username = username;
        this.password = password;
    }

    @Override
    protected String getEndpoint() {
        return client.getEndpoints().getToken();
    }

    public PasswordGrantRequest otp(String otp) {
        this.otp = otp;
        return this;
    }

    protected void initRequest() {
        header(TokenUtil.TOKEN_TYPE_DPOP, client.getDpopProof());

        parameter(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD);
        parameter("username", username);
        parameter("password", password);
        parameter("otp", otp);

        parameter(AdapterConstants.CLIENT_SESSION_STATE, client.getClientSessionState());
        parameter(AdapterConstants.CLIENT_SESSION_HOST, client.getClientSessionHost());

        scope();
    }

    @Override
    protected AccessTokenResponse toResponse(CloseableHttpResponse response) throws IOException {
        return new AccessTokenResponse(response);
    }

}
