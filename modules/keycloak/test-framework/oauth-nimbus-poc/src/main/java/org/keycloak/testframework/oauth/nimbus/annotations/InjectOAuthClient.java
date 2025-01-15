package org.keycloak.testframework.oauth.nimbus.annotations;

import org.keycloak.testframework.oauth.nimbus.DefaultOAuthClientConfiguration;
import org.keycloak.testframework.realm.ClientConfig;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface InjectOAuthClient {

    Class<? extends ClientConfig> config() default DefaultOAuthClientConfiguration.class;

}
