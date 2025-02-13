/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

import org.keycloak.authorization.AdminPermissionsSchema;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ImpersonationConstants;
import org.keycloak.models.UserModel;

import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public interface UserPermissionEvaluator {

    /**
     * Throws ForbiddenException if {@link #canManage()} returns {@code false}.
     */
    void requireManage();

    /**
     * Throws ForbiddenException if {@link #canManage(UserModel)} returns {@code false}.
     */
    void requireManage(UserModel user);

    /**
     * Returns {@code true} if the caller has {@link AdminRoles#MANAGE_USERS} role.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#MANAGE} users.
     */
    boolean canManage();

    /**
     * Returns {@code true} if the caller has {@link AdminRoles#MANAGE_USERS} role.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#MANAGE} the user.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#MANAGE_MEMBERS}
     * of the group chain the user is associated with.
     */
    boolean canManage(UserModel user);

    /**
     * Throws ForbiddenException if {@link #canQuery()} returns {@code false}.
     */
    void requireQuery();

    /**
     * Returns {@code true} if the caller has at least one of {@link AdminRoles#QUERY_USERS},
     * {@link AdminRoles#MANAGE_USERS} or {@link AdminRoles#VIEW_USERS} roles.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#VIEW} or
     * {@link AdminPermissionsSchema#MANAGE} users.
     */
    boolean canQuery();

    /**
     * Throws ForbiddenException if {@link #canView()} returns {@code false}.
     */
    void requireView();

    /**
     * Throws ForbiddenException if {@link #canView(UserModel)} returns {@code false}.
     */
    void requireView(UserModel user);

    /**
     * Returns {@code true} if the caller has one of {@link AdminRoles#MANAGE_USERS} or
     * {@link AdminRoles#VIEW_USERS} roles.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#VIEW} or
     * {@link AdminPermissionsSchema#MANAGE} users.
     */
    boolean canView();

    /**
     * Returns {@code true} if the caller has at least one of {@link AdminRoles#MANAGE_USERS} or
     * {@link AdminRoles#VIEW_USERS} roles.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#VIEW} or
     * {@link AdminPermissionsSchema#MANAGE} the user.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#VIEW_MEMBERS}
     * of the group chain the user is associated with.
     */
    boolean canView(UserModel user);

    /**
     * Throws ForbiddenException if {@link #canImpersonate(UserModel, ClientModel)} returns {@code false}.
     */
    void requireImpersonate(UserModel user);

    /**
     * Returns {@code true} if the caller has the {@link ImpersonationConstants#IMPERSONATION_ROLE}.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#IMPERSONATE} users.
     */
    boolean canImpersonate();

    /**
     * Returns {@code true} if the caller has the {@link ImpersonationConstants#IMPERSONATION_ROLE}.
     * <p/>
     * NOTE: If requester is provided, it's clientId is added to evaluation context.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#IMPERSONATE} the user.
     */
    boolean canImpersonate(UserModel user, ClientModel requester);

    /**
     * Returns Map with information what access the caller for the provided user has.
     */
    Map<String, Boolean> getAccess(UserModel user);

    /**
     * Throws ForbiddenException if {@link #canMapRoles(UserModel)} returns {@code false}.
     */
    void requireMapRoles(UserModel user);

    /**
     * Returns {@code true} if the caller has {@link AdminRoles#MANAGE_USERS} role.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#MANAGE} the user or 
     * {@link AdminPermissionsSchema#MAP_ROLES} of the user.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#MANAGE_MEMBERS}
     * of the group chain the user is associated with.
     */
    boolean canMapRoles(UserModel user);

    /**
     * Throws ForbiddenException if {@link #canManageGroupMembership(UserModel)} returns {@code false}.
     */
    void requireManageGroupMembership(UserModel user);

    /**
     * Returns {@code true} if the caller has {@link AdminRoles#MANAGE_USERS} role.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#MANAGE} the user or 
     * {@link AdminPermissionsSchema#MANAGE_GROUP_MEMBERSHIP} of the user.
     * <p/>
     * Or if it has a permission to {@link AdminPermissionsSchema#MANAGE_MEMBERS}
     * of the group chain the user is associated with.
     */
    boolean canManageGroupMembership(UserModel user);

    @Deprecated
    boolean isImpersonatable(UserModel user, ClientModel requester);
    void grantIfNoPermission(boolean grantIfNoPermission);
}
