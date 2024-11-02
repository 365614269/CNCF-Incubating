package org.keycloak.test.framework.ui.page;

import org.keycloak.test.framework.ui.annotations.InjectPage;
import org.keycloak.test.framework.injection.InstanceContext;
import org.keycloak.test.framework.injection.RequestedInstance;
import org.keycloak.test.framework.injection.Supplier;
import org.openqa.selenium.WebDriver;

import java.lang.reflect.Constructor;

public class PageSupplier  implements Supplier<AbstractPage, InjectPage> {

    @Override
    public Class<InjectPage> getAnnotationClass() {
        return InjectPage.class;
    }

    @Override
    public Class<AbstractPage> getValueType() {
        return AbstractPage.class;
    }

    @Override
    public AbstractPage getValue(InstanceContext<AbstractPage, InjectPage> instanceContext) {
        WebDriver webDriver = instanceContext.getDependency(WebDriver.class);
        return createPage(webDriver, instanceContext.getRequestedValueType());
    }

    @Override
    public boolean compatible(InstanceContext<AbstractPage, InjectPage> a, RequestedInstance<AbstractPage, InjectPage> b) {
        return true;
    }

    private <S extends AbstractPage> S createPage(WebDriver webDriver, Class<S> valueType) {
        try {
            Constructor<S> constructor = valueType.getDeclaredConstructor(WebDriver.class);
            return constructor.newInstance(webDriver);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
