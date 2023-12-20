/*
 * Copyright 2023 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.keycloak.migration.migrators;

import org.jboss.logging.Logger;
import org.keycloak.migration.ModelVersion;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.keycloak.representations.userprofile.config.UPConfig.UnmanagedAttributePolicy;
import org.keycloak.userprofile.UserProfileProvider;

public class MigrateTo24_0_0 implements Migration {

    private static final Logger LOG = Logger.getLogger(MigrateTo24_0_0.class);
    public static final ModelVersion VERSION = new ModelVersion("24.0.0");
    private static final String REALM_USER_PROFILE_ENABLED = "userProfileEnabled";

    @Override
    public void migrate(KeycloakSession session) {
        session.realms().getRealmsStream().forEach(realm -> migrateRealm(session, realm));
    }

    @Override
    public void migrateImport(KeycloakSession session, RealmModel realm, RealmRepresentation rep, boolean skipUserDependent) {
        migrateRealm(session, realm);
    }

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }

    private void migrateRealm(KeycloakSession session, RealmModel realm) {
        KeycloakContext context = session.getContext();
        try {
            context.setRealm(realm);
            updateUserProfileSettings(session);
        } finally {
            context.setRealm(null);
        }
    }

    private void updateUserProfileSettings(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        boolean isUserProfileEnabled = Boolean.parseBoolean(realm.getAttribute(REALM_USER_PROFILE_ENABLED));

        if (isUserProfileEnabled) {
            // existing realms with user profile enabled does not need any addition migration step
            LOG.debugf("Skipping migration for realm %s. The declarative user profile is already enabled.", realm.getName());
            return;
        }

        // user profile is enabled by default since this version
        realm.setAttribute(REALM_USER_PROFILE_ENABLED, Boolean.TRUE.toString());

        // for backward compatibility in terms of behavior, we enable unmanaged attributes for existing realms
        // that don't have the declarative user profile enabled
        UserProfileProvider provider = session.getProvider(UserProfileProvider.class);
        UPConfig upConfig = provider.getConfiguration();
        upConfig.setUnmanagedAttributePolicy(UnmanagedAttributePolicy.ENABLED);
        provider.setConfiguration(upConfig);

        LOG.debugf("Enabled the declarative user profile to realm %s with support for unmanaged attributes", realm.getName());
    }
}
