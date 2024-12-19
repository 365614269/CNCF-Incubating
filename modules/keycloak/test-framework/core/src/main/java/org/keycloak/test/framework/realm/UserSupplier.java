package org.keycloak.test.framework.realm;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.test.framework.annotations.InjectUser;
import org.keycloak.test.framework.injection.InstanceContext;
import org.keycloak.test.framework.injection.RequestedInstance;
import org.keycloak.test.framework.injection.Supplier;
import org.keycloak.test.framework.injection.SupplierHelpers;
import org.keycloak.test.framework.util.ApiUtil;

public class UserSupplier implements Supplier<ManagedUser, InjectUser> {

    private static final String USER_UUID_KEY = "userUuid";

    @Override
    public Class<InjectUser> getAnnotationClass() {
        return InjectUser.class;
    }

    @Override
    public Class<ManagedUser> getValueType() {
        return ManagedUser.class;
    }

    @Override
    public ManagedUser getValue(InstanceContext<ManagedUser, InjectUser> instanceContext) {
        ManagedRealm realm = instanceContext.getDependency(ManagedRealm.class, instanceContext.getAnnotation().realmRef());

        UserConfig config = SupplierHelpers.getInstance(instanceContext.getAnnotation().config());
        UserRepresentation userRepresentation = config.configure(UserConfigBuilder.create()).build();

        if (userRepresentation.getUsername() == null) {
            String username = SupplierHelpers.createName(instanceContext);
            userRepresentation.setUsername(username);
        }

        try (Response response = realm.admin().users().create(userRepresentation)) {
            if (Status.CONFLICT.equals(Status.fromStatusCode(response.getStatus()))) {
                throw new IllegalStateException("User already exist with username: " + userRepresentation.getUsername());
            }
            String uuid = ApiUtil.handleCreatedResponse(response);

            instanceContext.addNote(USER_UUID_KEY, uuid);

            UserResource userResource = realm.admin().users().get(uuid);
            userRepresentation.setId(uuid);

            return new ManagedUser(userRepresentation, userResource);
        }
    }

    @Override
    public boolean compatible(InstanceContext<ManagedUser, InjectUser> a, RequestedInstance<ManagedUser, InjectUser> b) {
        return a.getAnnotation().config().equals(b.getAnnotation().config());
    }

    @Override
    public void close(InstanceContext<ManagedUser, InjectUser> instanceContext) {
        instanceContext.getValue().admin().remove();
    }

}
