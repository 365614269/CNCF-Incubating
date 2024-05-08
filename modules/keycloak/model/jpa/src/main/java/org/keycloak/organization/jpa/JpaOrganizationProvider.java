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

package org.keycloak.organization.jpa;

import static org.keycloak.models.OrganizationModel.ORGANIZATION_ATTRIBUTE;
import static org.keycloak.models.jpa.PaginationUtils.paginateQuery;
import static org.keycloak.utils.StreamsUtil.closing;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;
import jakarta.persistence.TypedQuery;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.GroupProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.ModelException;
import org.keycloak.models.ModelValidationException;
import org.keycloak.models.OrganizationDomainModel;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.jpa.entities.OrganizationDomainEntity;
import org.keycloak.models.jpa.entities.OrganizationEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.utils.StringUtil;

public class JpaOrganizationProvider implements OrganizationProvider {

    private final EntityManager em;
    private final GroupProvider groupProvider;
    private final UserProvider userProvider;
    private final RealmModel realm;

    public JpaOrganizationProvider(KeycloakSession session) {
        em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        groupProvider = session.groups();
        userProvider = session.users();
        realm = session.getContext().getRealm();
        if (realm == null) {
            throw new IllegalArgumentException("Session not bound to a realm");
        }
    }

    @Override
    public OrganizationModel create(String name, Set<String> domains) {
        if (StringUtil.isBlank(name)) {
            throw new ModelValidationException("Name can not be null");
        }

        if (getByName(name) != null) {
            throw new ModelDuplicateException("A organization with the same name already exists.");
        }

        OrganizationEntity entity = new OrganizationEntity();
        entity.setId(KeycloakModelUtils.generateId());

        GroupModel group = createOrganizationGroup(entity.getId());

        entity.setGroupId(group.getId());
        entity.setRealmId(realm.getId());
        entity.setName(name);
        entity.setEnabled(true);

        em.persist(entity);

        OrganizationAdapter adapter = new OrganizationAdapter(realm, entity, this);

        adapter.setDomains(domains.stream().map(OrganizationDomainModel::new).collect(Collectors.toSet()));

        return adapter;
    }

    @Override
    public boolean remove(OrganizationModel organization) {
        OrganizationEntity entity = getEntity(organization.getId());

        GroupModel group = getOrganizationGroup(organization);

        //TODO: won't scale, requires a better mechanism for bulk deleting users
        userProvider.getGroupMembersStream(realm, group).forEach(userModel -> removeMember(organization, userModel));
        groupProvider.removeGroup(realm, group);
        organization.getIdentityProviders().forEach((model) -> removeIdentityProvider(organization, model));

        em.remove(entity);

        return true;
    }

    @Override
    public void removeAll() {
        //TODO: won't scale, requires a better mechanism for bulk deleting organizations within a realm
        getAllStream().forEach(this::remove);
    }

    @Override
    public boolean addMember(OrganizationModel organization, UserModel user) {
        throwExceptionIfObjectIsNull(organization, "Organization");
        throwExceptionIfObjectIsNull(user, "User");

        OrganizationEntity entity = getEntity(organization.getId());
        GroupModel group = groupProvider.getGroupById(realm, entity.getGroupId());

        if (user.isMemberOf(group)) {
            return false;
        }

        if (user.getFirstAttribute(ORGANIZATION_ATTRIBUTE) != null) {
            throw new ModelException("User [" + user.getId() + "] is a member of a different organization");
        }

        user.joinGroup(group);
        user.setSingleAttribute(ORGANIZATION_ATTRIBUTE, entity.getId());

        return true;
    }

    @Override
    public OrganizationModel getById(String id) {
        OrganizationEntity entity = getEntity(id, false);
        return entity == null ? null : new OrganizationAdapter(realm, entity, this);
    }

    @Override
    public OrganizationModel getByDomainName(String domain) {
        TypedQuery<OrganizationDomainEntity> query = em.createNamedQuery("getByName", OrganizationDomainEntity.class);
        query.setParameter("name", domain.toLowerCase());
        try {
            OrganizationDomainEntity entity = query.getSingleResult();
            return new OrganizationAdapter(realm, entity.getOrganization(), this);
        } catch (NoResultException nre) {
            return null;
        }
    }

    @Override
    public Stream<OrganizationModel> getAllStream(String search, Boolean exact, Integer first, Integer max) {
        TypedQuery<OrganizationEntity> query;
        if (StringUtil.isBlank(search)) {
            query = em.createNamedQuery("getByRealm", OrganizationEntity.class);
        } else if (Boolean.TRUE.equals(exact)) {
            query = em.createNamedQuery("getByNameOrDomain", OrganizationEntity.class);
            query.setParameter("search", search);
        } else {
            query = em.createNamedQuery("getByNameOrDomainContained", OrganizationEntity.class);
            query.setParameter("search", search.toLowerCase());
        }
        query.setParameter("realmId", realm.getId());

        return closing(paginateQuery(query, first, max).getResultStream()
                .map(entity -> new OrganizationAdapter(realm, entity, this)));
    }

    @Override
    public Stream<UserModel> getMembersStream(OrganizationModel organization, String search, Boolean exact, Integer first, Integer max) {
        throwExceptionIfObjectIsNull(organization, "Organization");
        GroupModel group = getOrganizationGroup(organization);

        return userProvider.getGroupMembersStream(realm, group, search, exact, first, max);
    }

    @Override
    public UserModel getMemberById(OrganizationModel organization, String id) {
        throwExceptionIfObjectIsNull(organization, "Organization");
        UserModel user = userProvider.getUserById(realm, id);

        if (user == null) {
            return null;
        }

        String orgId = user.getFirstAttribute(ORGANIZATION_ATTRIBUTE);

        if (organization.getId().equals(orgId)) {
            return user;
        }

        return null;
    }

    @Override
    public OrganizationModel getByMember(UserModel member) {
        throwExceptionIfObjectIsNull(member, "User");

        String orgId = member.getFirstAttribute(ORGANIZATION_ATTRIBUTE);

        if (orgId == null) {
            return null;
        }

        return getById(orgId);
    }

    @Override
    public boolean addIdentityProvider(OrganizationModel organization, IdentityProviderModel identityProvider) {
        throwExceptionIfObjectIsNull(organization, "Organization");
        throwExceptionIfObjectIsNull(identityProvider, "Identity provider");

        OrganizationEntity organizationEntity = getEntity(organization.getId());
        String orgId = identityProvider.getOrganizationId();

        if (organizationEntity.getId().equals(orgId)) {
            return false;
        } else if (orgId != null) {
            throw new ModelValidationException("Identity provider already associated with a different organization");
        }

        identityProvider.setOrganizationId(organizationEntity.getId());
        realm.updateIdentityProvider(identityProvider);

        return true;
    }

    @Override
    public Stream<IdentityProviderModel> getIdentityProviders(OrganizationModel organization) {
        throwExceptionIfObjectIsNull(organization, "Organization");
        throwExceptionIfObjectIsNull(organization.getId(), "Organization ID");

        OrganizationEntity organizationEntity = getEntity(organization.getId());

        return realm.getIdentityProvidersStream().filter(model -> organizationEntity.getId().equals(model.getOrganizationId()));
    }

    @Override
    public boolean removeIdentityProvider(OrganizationModel organization, IdentityProviderModel identityProvider) {
        throwExceptionIfObjectIsNull(organization, "Organization");

        OrganizationEntity organizationEntity = getEntity(organization.getId());

        if (!organizationEntity.getId().equals(identityProvider.getOrganizationId())) {
            return false;
        }

        identityProvider.setOrganizationId(null);
        realm.updateIdentityProvider(identityProvider);

        return true;
    }

    @Override
    public boolean isManagedMember(OrganizationModel organization, UserModel member) {
        throwExceptionIfObjectIsNull(organization, "organization");

        if (member == null) {
            return false;
        }

        List<IdentityProviderModel> brokers = organization.getIdentityProviders().toList();

        if (brokers.isEmpty()) {
            return false;
        }

        List<FederatedIdentityModel> federatedIdentities = userProvider.getFederatedIdentitiesStream(realm, member)
                .map(federatedIdentityModel -> realm.getIdentityProviderByAlias(federatedIdentityModel.getIdentityProvider()))
                .filter(brokers::contains)
                .map(m -> userProvider.getFederatedIdentity(realm, member, m.getAlias()))
                .toList();

        return !federatedIdentities.isEmpty();
    }

    @Override
    public boolean removeMember(OrganizationModel organization, UserModel member) {
        throwExceptionIfObjectIsNull(organization, "organization");
        throwExceptionIfObjectIsNull(member, "member");

        OrganizationModel userOrg = getByMember(member);

        if (userOrg == null || !userOrg.equals(organization)) {
            return false;
        }

        if (isManagedMember(organization, member)) {
            userProvider.removeUser(realm, member);
        } else {
            List<String> organizations = member.getAttributes().get(ORGANIZATION_ATTRIBUTE);
            organizations.remove(organization.getId());
            member.setAttribute(ORGANIZATION_ATTRIBUTE, organizations);
            member.leaveGroup(getOrganizationGroup(organization));
        }

        return true;
    }

    @Override
    public boolean isEnabled() {
        return getAllStream().findAny().isPresent();
    }

    @Override
    public void close() {
    }

    /**
     * @throws ModelException if there is no entity with given {@code id}
     */
    private OrganizationEntity getEntity(String id) {
        return getEntity(id, true);
    }

    private OrganizationEntity getEntity(String id, boolean failIfNotFound) {
        OrganizationEntity entity = em.find(OrganizationEntity.class, id);

        if (entity == null) {
            if (failIfNotFound) {
                throw new ModelException("Organization [" + id + "] does not exist");
            }
            return null;
        }

        if (!realm.getId().equals(entity.getRealmId())) {
            throw new ModelException("Organization [" + entity.getId() + "] does not belong to realm [" + realm.getId() + "]");
        }

        return entity;
    }

    private GroupModel createOrganizationGroup(String orgId) {
        GroupModel group = groupProvider.createGroup(realm, null, orgId);
        group.setSingleAttribute(ORGANIZATION_ATTRIBUTE, orgId);

        return group;
    }

    private GroupModel getOrganizationGroup(OrganizationModel organization) {
        throwExceptionIfObjectIsNull(organization, "Organization");
        OrganizationEntity entity = getEntity(organization.getId());

        GroupModel group = groupProvider.getGroupById(realm, entity.getGroupId());

        if (group == null) {
            throw new ModelException("Organization group " + entity.getGroupId() + " not found");
        }

        return group;
    }

    private void throwExceptionIfObjectIsNull(Object object, String objectName) {
        if (object == null) {
            throw new ModelException(String.format("%s cannot be null", objectName));
        }
    }

    private OrganizationEntity getByName(String name) {
        TypedQuery<OrganizationEntity> query = em.createNamedQuery("getByOrgName", OrganizationEntity.class);

        query.setParameter("name", name);
        query.setParameter("realmId", realm.getId());

        try {
            return query.getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }
}
