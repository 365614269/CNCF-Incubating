package org.keycloak.testsuite.util.oauth;

import jakarta.ws.rs.core.UriBuilder;

public abstract class AbstractUrlBuilder {

    protected final AbstractOAuthClient<?> client;
    protected UriBuilder uriBuilder;

    public AbstractUrlBuilder(AbstractOAuthClient<?> client) {
        this.client = client;
    }

    public abstract String getEndpoint();

    protected abstract void initRequest();

    public void open() {
        client.driver.navigate().to(build());
    }

    protected void parameter(String name, String value) {
        if (value != null) {
            uriBuilder.queryParam(name, value);
        }
    }

    protected void replaceParameter(String name, String value) {
        if (value != null) {
            uriBuilder.replaceQueryParam(name, value);
        }
    }

    public String build() {
        uriBuilder = UriBuilder.fromUri(getEndpoint());
        initRequest();

        return uriBuilder.build().toString();
    }

}
