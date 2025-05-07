/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.quarkus.runtime.logging;

import io.quarkus.logging.LoggingFilter;

import java.util.Objects;
import java.util.logging.Filter;
import java.util.logging.Level;
import java.util.logging.LogRecord;

/**
 * @author Alexander Schwartz
 */
@LoggingFilter(name = "keycloak-filter")
public final class KeycloakLogFilter implements Filter {
    @Override
    public boolean isLoggable(LogRecord record) {
        // The ARJUNA012125 messages are logged and then thrown.
        // As those messages might later be caught and handled, this is an antipattern so we prevent logging them.
        // https://narayana.zulipchat.com/#narrow/channel/323714-users/topic/Message.20.22ARJUNA012125.22.20implements.20log-and-throw.20antipattern
        if (Objects.equals(record.getLevel(), Level.WARNING) && record.getLoggerName().equals("com.arjuna.ats.arjuna") && record.getMessage().startsWith("ARJUNA012125:")) {
            return false;
        }
        return true;
    }
}
