/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.quarkus.runtime.integration.resteasy;

import org.jboss.resteasy.reactive.server.core.CurrentRequestManager;
import org.jboss.resteasy.reactive.server.core.ResteasyReactiveRequestContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Resteasy;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.DefaultKeycloakContext;

import io.vertx.core.http.HttpServerRequest;

public final class QuarkusKeycloakContext extends DefaultKeycloakContext {

    private ClientConnection clientConnection;

    public QuarkusKeycloakContext(KeycloakSession session) {
        super(session);
    }

    @Override
    protected HttpRequest createHttpRequest() {
        return new QuarkusHttpRequest(getResteasyReactiveRequestContext());
    }

    @Override
    protected HttpResponse createHttpResponse() {
        return new QuarkusHttpResponse(getSession(), getResteasyReactiveRequestContext());
    }

    @Override
    public ClientConnection getConnection() {
        if (clientConnection == null) {
            ClientConnection contextualObject = Resteasy.getContextData(ClientConnection.class);

            if (contextualObject == null) {
                ResteasyReactiveRequestContext requestContext = getResteasyReactiveRequestContext();
                HttpServerRequest serverRequest = requestContext.unwrap(HttpServerRequest.class);
                clientConnection = new QuarkusClientConnection(serverRequest);
            } else {
                // in case the request is dispatched to a different thread like when using JAX-RS async responses
                // in this case, we expect the client connection available as a contextual data
                clientConnection = contextualObject;
            }
        }

        return clientConnection;
    }

    private ResteasyReactiveRequestContext getResteasyReactiveRequestContext() {
        return CurrentRequestManager.get();
    }
}
