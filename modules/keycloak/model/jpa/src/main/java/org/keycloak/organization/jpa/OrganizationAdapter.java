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

import org.keycloak.models.GroupModel;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.ModelValidationException;
import org.keycloak.models.OrganizationDomainModel;
import org.keycloak.models.OrganizationModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.JpaModel;
import org.keycloak.models.jpa.entities.OrganizationDomainEntity;
import org.keycloak.models.jpa.entities.OrganizationEntity;
import org.keycloak.organization.OrganizationProvider;
import org.keycloak.utils.EmailValidationUtil;

import java.util.List;

public final class OrganizationAdapter implements OrganizationModel, JpaModel<OrganizationEntity> {

    private final RealmModel realm;
    private final OrganizationEntity entity;
    private final OrganizationProvider provider;
    private GroupModel group;

    public OrganizationAdapter(RealmModel realm, OrganizationEntity entity, OrganizationProvider provider) {
        this.realm = realm;
        this.entity = entity;
        this.provider = provider;
    }

    @Override
    public String getId() {
        return entity.getId();
    }

    RealmModel getRealm() {
        return realm;
    }

    String getGroupId() {
        return entity.getGroupId();
    }

    @Override
    public void setName(String name) {
        entity.setName(name);
    }

    @Override
    public String getName() {
        return entity.getName();
    }

    @Override
    public void setAttributes(Map<String, List<String>> attributes) {
        if (attributes == null) {
            return;
        }
        Set<String> attrsToRemove = getAttributes().keySet();
        attrsToRemove.removeAll(attributes.keySet());
        attrsToRemove.forEach(group::removeAttribute);
        attributes.forEach(group::setAttribute);
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        return getGroup().getAttributes();
    }

    @Override
    public Stream<OrganizationDomainModel> getDomains() {
        return entity.getDomains().stream().map(this::toModel);
    }

    @Override
    public void setDomains(Set<OrganizationDomainModel> domains) {
        if (domains == null || domains.isEmpty()) {
            throw new ModelValidationException("You must provide at least one domain");
        }

        Map<String, OrganizationDomainModel> modelMap = domains.stream()
                .peek(this::validateDomainRepresentation)
                .collect(Collectors.toMap(OrganizationDomainModel::getName, Function.identity()));

        for (OrganizationDomainEntity domainEntity : new HashSet<>(this.entity.getDomains())) {
            // update the existing domain (for now, only the verified flag can be changed).
            if (modelMap.containsKey(domainEntity.getName())) {
                domainEntity.setVerified(modelMap.get(domainEntity.getName()).getVerified());
                modelMap.remove(domainEntity.getName());
            }
            // remove domain that is not found in the new set.
            else {
                this.entity.removeDomain(domainEntity);
            }
        }

        // create the remaining domains.
        for (OrganizationDomainModel model : modelMap.values()) {
            OrganizationDomainEntity domainEntity = new OrganizationDomainEntity();
            domainEntity.setName(model.getName().toLowerCase());
            domainEntity.setVerified(model.getVerified());
            domainEntity.setOrganization(this.entity);
            this.entity.addDomain(domainEntity);
        }
    }

    @Override
    public IdentityProviderModel getIdentityProvider() {
        return provider.getIdentityProvider(this);
    }

    @Override
    public OrganizationEntity getEntity() {
        return entity;
    }

    @Override
    public String toString() {
        return new StringBuilder()
                .append("id=")
                .append(getId())
                .append(",")
                .append("name=")
                .append(getName())
                .append(",")
                .append("realm=")
                .append(getRealm().getName())
                .append(",")
                .append("groupId=")
                .append(getGroupId()).toString();
    }

    private OrganizationDomainModel toModel(OrganizationDomainEntity entity) {
        return new OrganizationDomainModel(entity.getName(), entity.isVerified());
    }

    /**
     * Validates the domain representation. Specifically, the method first checks if the specified domain is valid,
     * and then checks if the domain is not already linked to a different organization.
     *
     * @param domainModel the {@link OrganizationDomainModel} representing the domain being added.
     * @throws {@link ModelValidationException} if the domain is invalid or is already linked to a different organization.
     */
    private void validateDomainRepresentation(OrganizationDomainModel domainModel) {
        String domainName = domainModel.getName();

        // we rely on the same validation util used by the EmailValidator to ensure the domain part is consistently validated.
        if(domainName == null || domainName.isEmpty() || !EmailValidationUtil.isValidEmail("nouser@" + domainName)) {
            throw new ModelValidationException("The specified domain is invalid: " + domainName);
        }
        OrganizationModel orgModel = provider.getByDomainName(domainName);
        if (orgModel != null && !Objects.equals(getId(), orgModel.getId())) {
            throw new ModelValidationException("Domain " + domainName + " is already linked to another organization");
        }
    }

    private GroupModel getGroup() {
        if (group == null) {
            group = realm.getGroupById(getGroupId());
        }
        return group;
    }
}
