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
package org.keycloak.services.resources.admin.permissions;

import org.jboss.logging.Logger;
import org.keycloak.authorization.AdminPermissionsSchema;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.common.ClientModelIdentity;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.Permission;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.keycloak.services.resources.admin.permissions.AdminPermissionManagement.TOKEN_EXCHANGE;


public class ClientPermissionsV2 extends ClientPermissions {

    private static final Logger logger = Logger.getLogger(ClientPermissionsV2.class);

    public ClientPermissionsV2(KeycloakSession session, RealmModel realm, AuthorizationProvider authz, MgmtPermissionsV2 root) {
        super(session, realm, authz, root);
    }

    @Override
    public boolean canConfigure(ClientModel client) {
        if (canManage(client)) return true;

        return hasPermission(client, AdminPermissionsSchema.CONFIGURE);
    }

    @Override
    public boolean canManage(ClientModel client) {
        if (root.hasOneAdminRole(AdminRoles.MANAGE_CLIENTS)) return true;

        return hasPermission(client, AdminPermissionsSchema.MANAGE);
    }

    @Override
    public boolean canManage() {
        return super.canManage() || hasPermission(AdminPermissionsSchema.MANAGE);
    }

    @Override
    public boolean canView(ClientModel client) {
        if (canView() || canConfigure(client)) {
            return true;
        }

        return hasPermission(client, AdminPermissionsSchema.VIEW);
    }

    @Override
    public boolean canView() {
        return canViewClientDefault() || hasPermission(AdminPermissionsSchema.VIEW);
    }

    @Override
    public boolean canMapRoles(ClientModel client) {
        return hasPermission(client, AdminPermissionsSchema.MAP_ROLES);
    }

    @Override
    public boolean canMapCompositeRoles(ClientModel client) {
        return hasPermission(client, AdminPermissionsSchema.MAP_ROLES_COMPOSITE);
    }

    @Override
    public boolean canMapClientScopeRoles(ClientModel client) {
        return hasPermission(client, AdminPermissionsSchema.MAP_ROLES_CLIENT_SCOPE);
    }

    @Override
    public boolean canManageClientScopes() {
        if (root.hasOneAdminRole(AdminRoles.MANAGE_CLIENTS)) return true;

        return hasPermission(AdminPermissionsSchema.MANAGE);
    }

    @Override
    public boolean canManage(ClientScopeModel clientScope) {
        return canManageClientScopes();
    }

    @Override
    public boolean canView(ClientScopeModel clientScope) {
        if (root.hasOneAdminRole(AdminRoles.VIEW_CLIENTS, AdminRoles.MANAGE_CLIENTS)) return true;

        return hasPermission(AdminPermissionsSchema.VIEW) || hasPermission(AdminPermissionsSchema.MANAGE);
    }

    @Override
    public Set<String> getClientsWithPermission(String scope) {
        if (!root.isAdminSameRealm()) {
            return Collections.emptySet();
        }

        ResourceServer server = root.realmResourceServer();

        if (server == null) {
            return Collections.emptySet();
        }

        Set<String> granted = new HashSet<>();

        resourceStore.findByType(server, AdminPermissionsSchema.CLIENTS_RESOURCE_TYPE, resource -> {
            if (hasGrantedPermission(resource, scope)) {
                granted.add(resource.getName());
            }
        });

        return granted;
    }

    @Override
    public boolean canExchangeTo(ClientModel authorizedClient, ClientModel to, AccessToken token) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public Policy exchangeToPermission(ClientModel client) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public Policy mapRolesPermission(ClientModel client) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public Policy mapRolesClientScopePermission(ClientModel client) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public Policy mapRolesCompositePermission(ClientModel client) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public Policy managePermission(ClientModel client) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public Policy configurePermission(ClientModel client) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public Policy viewPermission(ClientModel client) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public boolean isPermissionsEnabled(ClientModel client) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public void setPermissionsEnabled(ClientModel client, boolean enable) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public Resource resource(ClientModel client) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    @Override
    public Map<String, String> getPermissions(ClientModel client) {
        throw new UnsupportedOperationException("Not supported in V2");
    }

    private boolean hasPermission(ClientModel client, String scope) {
        if (!root.isAdminSameRealm()) {
            return false;
        }
        ResourceServer server = root.realmResourceServer();
        if (server == null) return false;

        Resource resource =  resourceStore.findByName(server, client.getId(), server.getId());
        if (resource == null) {
            // check if there is permission for "all-clients". If so, load its resource and proceed with evaluation
            resource = AdminPermissionsSchema.SCHEMA.getResourceTypeResource(session, server, AdminPermissionsSchema.CLIENTS_RESOURCE_TYPE);

            if (authz.getStoreFactory().getPolicyStore().findByResource(server, resource).isEmpty()) {
                return false;
            }
        }

        Collection<Permission> permissions = root.evaluatePermission(new ResourcePermission(resource, resource.getScopes(), server), server);
        List<String> expectedScopes = Arrays.asList(scope);
        for (Permission permission : permissions) {
            for (String s : permission.getScopes()) {
                if (expectedScopes.contains(s)) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean hasPermission(String scope) {
        if (!root.isAdminSameRealm()) {
            return false;
        }
        ResourceServer server = root.realmResourceServer();
        if (server == null) return false;

        Resource resource = resourceStore.findByName(server, AdminPermissionsSchema.CLIENTS_RESOURCE_TYPE, server.getId());
        if (resource == null) {
            return false;
        }

        Collection<Permission> permissions = root.evaluatePermission(new ResourcePermission(resource, resource.getScopes(), server), server);
        List<String> expectedScopes = Arrays.asList(scope);
        for (Permission permission : permissions) {
            for (String s : permission.getScopes()) {
                if (expectedScopes.contains(s)) {
                    return true;
                }
            }
        }

        return false;
    }

    private EvaluationContext getEvaluationContext(ClientModel authorizedClient, AccessToken token) {
        ClientModelIdentity identity = new ClientModelIdentity(session, authorizedClient, token);
        return new DefaultEvaluationContext(identity, session) {
            @Override
            public Map<String, Collection<String>> getBaseAttributes() {
                Map<String, Collection<String>> attributes = super.getBaseAttributes();
                attributes.put("kc.client.id", List.of(authorizedClient.getClientId()));
                return attributes;
            }
        };
    }

    private boolean hasGrantedPermission(Resource resource, String scope) {
        ResourceServer server = root.realmResourceServer();
        Collection<Permission> permissions = root.evaluatePermission(new ResourcePermission(resource, resource.getScopes(), server), server);
        for (Permission permission : permissions) {
            for (String s : permission.getScopes()) {
                if (scope.equals(s)) {
                    return true;
                }
            }
        }

        return false;
    }
}
