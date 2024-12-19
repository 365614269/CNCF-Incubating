package org.keycloak.test.framework.realm;

import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RolesRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class RealmConfigBuilder {

    private final RealmRepresentation rep;

    private RealmConfigBuilder(RealmRepresentation rep) {
        this.rep = rep;
    }

    public static RealmConfigBuilder create() {
        RealmRepresentation rep = new RealmRepresentation();
        rep.setEnabled(true);
        return new RealmConfigBuilder(rep);
    }

    public static RealmConfigBuilder update(RealmRepresentation rep) {
        return new RealmConfigBuilder(rep);
    }

    public RealmConfigBuilder name(String name) {
        rep.setRealm(name);
        return this;
    }

    public ClientConfigBuilder addClient(String clientId) {
        if (rep.getClients() == null) {
            rep.setClients(new LinkedList<>());
        }
        ClientRepresentation client = new ClientRepresentation();
        rep.getClients().add(client);
        return ClientConfigBuilder.update(client).enabled(true).clientId(clientId);
    }

    public UserConfigBuilder addUser(String username) {
        if (rep.getUsers() == null) {
            rep.setUsers(new LinkedList<>());
        }
        UserRepresentation user = new UserRepresentation();
        rep.getUsers().add(user);
        return UserConfigBuilder.update(user).enabled(true).username(username);
    }

    public RealmConfigBuilder registrationEmailAsUsername(boolean registrationEmailAsUsername) {
        rep.setRegistrationEmailAsUsername(registrationEmailAsUsername);
        return this;
    }

    public RealmConfigBuilder editUsernameAllowed(boolean editUsernameAllowed) {
        rep.setEditUsernameAllowed(editUsernameAllowed);
        return this;
    }

    public RealmConfigBuilder defaultSignatureAlgorithm(String algorithm) {
        rep.setDefaultSignatureAlgorithm(algorithm);
        return this;
    }

    public RealmConfigBuilder adminPermissionsEnabled(boolean enabled) {
        rep.setAdminPermissionsEnabled(enabled);
        return this;
    }

    public RealmConfigBuilder eventsListeners(String... eventListeners) {
        if (rep.getEventsListeners() == null) {
            rep.setEventsListeners(new LinkedList<>());
        }
        rep.getEventsListeners().addAll(List.of(eventListeners));
        return this;
    }

    public RealmConfigBuilder roles(String... roleNames) {
        if (rep.getRoles() == null) {
            rep.setRoles(new RolesRepresentation());
        }
        rep.getRoles().setRealm(Collections.combine(rep.getRoles().getRealm(), Arrays.stream(roleNames).map(Representations::toRole)));
        return this;
    }

    public RealmConfigBuilder groups(String... groupsNames) {
        rep.setGroups(Collections.combine(rep.getGroups(), Arrays.stream(groupsNames).map(Representations::toGroup)));
        return this;
    }

    public RealmConfigBuilder smtp(String host, int port, String from) {
        Map<String, String> config = new HashMap<>();
        config.put("host", host);
        config.put("port", Integer.toString(port));
        config.put("from", from);
        rep.setSmtpServer(config);
        return this;
    }

    public RealmRepresentation build() {
        return rep;
    }

}
