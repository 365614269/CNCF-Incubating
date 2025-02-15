package org.keycloak.testframework.util;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Assertions;

public class ApiUtil {

    public static String handleCreatedResponse(Response response) {
        try (response) {
            String uuid = getCreatedId(response);
            response.close();
            return uuid;
        }
    }

    public static String getCreatedId(Response response) {
        Assertions.assertEquals(201, response.getStatus());
        String path = response.getLocation().getPath();
        return path.substring(path.lastIndexOf('/') + 1);
    }

}
