/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.testsuite.adapter.example.cors;

import org.jboss.arquillian.container.test.api.Deployer;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.drone.api.annotation.Drone;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jetbrains.annotations.Nullable;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.adapter.AbstractExampleAdapterTest;
import org.keycloak.testsuite.adapter.page.AngularCorsProductTestApp;
import org.keycloak.testsuite.adapter.page.CorsDatabaseServiceTestApp;
import org.keycloak.testsuite.arquillian.annotation.AppServerContainer;
import org.keycloak.testsuite.util.JavascriptBrowser;
import org.keycloak.testsuite.utils.arquillian.ContainerConstants;
import org.keycloak.testsuite.auth.page.login.OIDCLogin;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static junit.framework.TestCase.assertNotNull;
import org.keycloak.testsuite.util.DroneUtils;

import static org.keycloak.testsuite.utils.io.IOUtil.loadRealm;
import static org.keycloak.testsuite.util.URLAssert.assertCurrentUrlStartsWith;
import static org.keycloak.testsuite.util.WaitUtils.waitForPageToLoad;
import static org.keycloak.testsuite.util.WaitUtils.waitUntilElement;

/**
 * Tests CORS functionality in adapters.
 *
 * <p>
 *    Note, for SSL this test disables TLS certificate verification. Since CORS uses different hostnames
 *    (localhost-auth for example), the Subject Name won't match.
 * </p>
 *
 * @author fkiss
 */
@AppServerContainer(ContainerConstants.APP_SERVER_WILDFLY)
@AppServerContainer(ContainerConstants.APP_SERVER_EAP)
@AppServerContainer(ContainerConstants.APP_SERVER_EAP6)
@AppServerContainer(ContainerConstants.APP_SERVER_EAP71)
public class CorsExampleAdapterTest extends AbstractExampleAdapterTest {

    public static final String CORS = "cors";

    @ArquillianResource
    private Deployer deployer;

    // Javascript browser needed, but not PhantomJS
    @Drone
    @JavascriptBrowser
    protected WebDriver jsDriver;

    @Page
    @JavascriptBrowser
    protected OIDCLogin jsDriverTestRealmLoginPage;

    @Page
    @JavascriptBrowser
    private AngularCorsProductTestApp jsDriverAngularCorsProductPage;

    @Deployment(name = AngularCorsProductTestApp.DEPLOYMENT_NAME, managed = false)
    protected static WebArchive angularCorsProductExample() throws IOException {
        return exampleDeployment(AngularCorsProductTestApp.CLIENT_ID);
    }

    @Deployment(name = CorsDatabaseServiceTestApp.DEPLOYMENT_NAME, managed = false)
    protected static WebArchive corsDatabaseServiceExample() throws IOException {
        return exampleDeployment(CorsDatabaseServiceTestApp.CLIENT_ID);
    }

    @Override
    public void addAdapterTestRealms(List<RealmRepresentation> testRealms) {
        testRealms.add(
                loadRealm(new File(TEST_APPS_HOME_DIR + "/cors/cors-realm.json")));
    }

    @Before
    public void onBefore() {
        DroneUtils.addWebDriver(jsDriver);
        deployer.deploy(CorsDatabaseServiceTestApp.DEPLOYMENT_NAME);
        deployer.deploy(AngularCorsProductTestApp.DEPLOYMENT_NAME);
    }

    @After
    public void onAfter() {
        deployer.undeploy(CorsDatabaseServiceTestApp.DEPLOYMENT_NAME);
        deployer.undeploy(AngularCorsProductTestApp.DEPLOYMENT_NAME);
    }


    @Override
    public void setDefaultPageUriParameters() {
        super.setDefaultPageUriParameters();
        jsDriverTestRealmLoginPage.setAuthRealm(CORS);
        oauth.realm(CORS);
    }

    @Test
    public void angularCorsProductTest() {
        jsDriverAngularCorsProductPage.navigateTo();
        jsDriverTestRealmLoginPage.form().login("bburke@redhat.com", "password");

        assertCurrentUrlStartsWith(jsDriverAngularCorsProductPage);
        jsDriverAngularCorsProductPage.reloadData();
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("iphone");
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("ipad");
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("ipod");
        waitUntilElement(jsDriverAngularCorsProductPage.getHeaders()).text().contains("\"x-custom1\":\"some-value\"");
        waitUntilElement(jsDriverAngularCorsProductPage.getHeaders()).text().contains("\"www-authenticate\":\"some-value\"");

        jsDriverAngularCorsProductPage.loadRoles();
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("user");

        jsDriverAngularCorsProductPage.addRole();
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("stuff");

        jsDriverAngularCorsProductPage.deleteRole();
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().not().contains("stuff");

        jsDriverAngularCorsProductPage.loadAvailableSocialProviders();
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("twitter");
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("google");
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("linkedin");
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("facebook");
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("stackoverflow");
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("github");
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("microsoft");

        jsDriverAngularCorsProductPage.loadPublicRealmInfo();
        waitUntilElement(jsDriverAngularCorsProductPage.getOutput()).text().contains("Realm name: cors");

        String serverVersion = getAuthServerVersion();
        assertNotNull(serverVersion);

        jsDriverAngularCorsProductPage.navigateTo();
        waitForPageToLoad();

    }

    @Nullable
    private String getAuthServerVersion() {
        DroneUtils.getCurrentDriver().navigate().to(suiteContext.getAuthServerInfo().getContextRoot().toString() +
                "/auth/admin/master/console/#/master/info");
        jsDriverTestRealmLoginPage.form().login("admin", "admin");
        // just get the first list description which is the version
        List<WebElement> elements = jsDriver.findElements(By.xpath(".//dd[@class='pf-c-description-list__description']"));
        if (!elements.isEmpty()) {
            return elements.get(0).getText();
        }
        return null;
    }
}
