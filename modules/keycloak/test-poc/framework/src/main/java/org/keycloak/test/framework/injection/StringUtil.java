package org.keycloak.test.framework.injection;

public class StringUtil {

    public static String convertEmptyToNull(String s) {
        return s != null && s.isEmpty() ? null : s;
    }

}
