package org.keycloak.test.framework.realm;

import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

class Representations {

    private Representations() {
    }

    static RoleRepresentation toRole(String roleName) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(roleName);
        return role;
    }

    static GroupRepresentation toGroup(String groupName) {
        GroupRepresentation group = new GroupRepresentation();
        group.setName(groupName);
        return group;
    }

    static CredentialRepresentation toCredential(String type, String value) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(type);
        credential.setValue(value);
        return credential;
    }

}
