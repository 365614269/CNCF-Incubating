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

import static jakarta.ws.rs.HttpMethod.POST;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.function.Supplier;
import org.jboss.resteasy.reactive.common.model.ResourceClass;
import org.jboss.resteasy.reactive.server.handlers.FormBodyHandler;
import org.jboss.resteasy.reactive.server.model.HandlerChainCustomizer;
import org.jboss.resteasy.reactive.server.model.ServerResourceMethod;
import org.jboss.resteasy.reactive.server.spi.ServerRestHandler;

public final class KeycloakHandlerChainCustomizer implements HandlerChainCustomizer {

    private final CreateSessionHandler TRANSACTIONAL_SESSION_HANDLER = new CreateSessionHandler();

    private final FormBodyHandler formBodyHandler = new FormBodyHandler(true, new Supplier<Executor>() {
        @Override
        public Executor get() {
            // we always run in blocking mode and never run in an event loop thread
            // we don't need to provide an executor to dispatch to a worker thread to parse the body
            return null;
        }
    }, Set.of());

    @Override
    public List<ServerRestHandler> handlers(Phase phase, ResourceClass resourceClass,
            ServerResourceMethod resourceMethod) {
        List<ServerRestHandler> handlers = new ArrayList<>();

        switch (phase) {
            case BEFORE_METHOD_INVOKE:
                if (POST.equalsIgnoreCase(resourceMethod.getHttpMethod())) {
                    handlers.add(formBodyHandler);
                }
                handlers.add(TRANSACTIONAL_SESSION_HANDLER);
                break;
            case AFTER_METHOD_INVOKE:
                handlers.add(new SetResponseContentTypeHandler(resourceMethod.getProduces()));
        }

        return handlers;
    }
}
