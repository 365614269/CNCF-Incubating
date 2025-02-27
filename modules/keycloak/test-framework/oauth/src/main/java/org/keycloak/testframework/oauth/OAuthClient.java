package org.keycloak.testframework.oauth;

import org.apache.http.impl.client.CloseableHttpClient;
import org.keycloak.OAuth2Constants;
import org.keycloak.testframework.ui.page.LoginPage;
import org.keycloak.testsuite.util.oauth.AbstractOAuthClient;
import org.keycloak.testsuite.util.oauth.OAuthClientConfig;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.PageFactory;

public class OAuthClient extends AbstractOAuthClient<OAuthClient> {

    public OAuthClient(String baseUrl, CloseableHttpClient httpClient, WebDriver webDriver) {
        super(baseUrl, httpClient, webDriver);

        config = new OAuthClientConfig()
                .responseType(OAuth2Constants.CODE);
    }

    @Override
    public void fillLoginForm(String username, String password) {
        LoginPage loginPage = new LoginPage(driver);
        PageFactory.initElements(driver, loginPage);
        loginPage.fillLogin(username, password);
        loginPage.submit();
    }

    public void close() {
    }

}
