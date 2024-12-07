package org.keycloak.test.framework.annotations;


import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface InjectAdminClient {

    String ref() default "";

    Mode mode() default Mode.BOOTSTRAP;

    String client() default "";

    String user() default "";

    enum Mode {

        BOOTSTRAP,
        MANAGED_REALM

    }

}
