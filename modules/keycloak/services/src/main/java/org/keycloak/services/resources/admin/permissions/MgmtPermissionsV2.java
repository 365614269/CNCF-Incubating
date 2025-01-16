/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.services.resources.admin.permissions;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.admin.AdminAuth;

class MgmtPermissionsV2 extends MgmtPermissions {

    private UserPermissionsV2 userPermissions;

    public MgmtPermissionsV2(KeycloakSession session, RealmModel realm) {
        super(session, realm);
    }

    public MgmtPermissionsV2(KeycloakSession session, RealmModel realm, AdminAuth auth) {
        super(session, realm, auth);
    }

    public MgmtPermissionsV2(KeycloakSession session, AdminAuth auth) {
        super(session, auth);
    }

    public MgmtPermissionsV2(KeycloakSession session, RealmModel adminsRealm, UserModel admin) {
        super(session, adminsRealm, admin);
    }

    public MgmtPermissionsV2(KeycloakSession session, RealmModel realm, RealmModel adminsRealm, UserModel admin) {
        super(session, realm, adminsRealm, admin);
    }

    @Override
    public ClientModel getRealmPermissionsClient() {
        return realm.getAdminPermissionsClient();
    }

    @Override
    public UserPermissions users() {
        if (userPermissions != null) return userPermissions;
        userPermissions = new UserPermissionsV2(session, authz, this);
        return userPermissions;
    }
}
