package org.keycloak.test.framework.realm;

import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.test.framework.annotations.InjectUser;
import org.keycloak.test.framework.injection.InstanceContext;
import org.keycloak.test.framework.injection.RequestedInstance;
import org.keycloak.test.framework.injection.Supplier;
import org.keycloak.test.framework.injection.SupplierHelpers;

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
        ManagedRealm realm = instanceContext.getDependency(ManagedRealm.class);

        UserConfig config = SupplierHelpers.getInstance(instanceContext.getAnnotation().config());
        UserRepresentation userRepresentation = config.getRepresentation();

        if (userRepresentation.getUsername() == null) {
            String username = instanceContext.getRef();
            userRepresentation.setUsername(username);
        }

        Response response = realm.admin().users().create(userRepresentation);
        String uuid = ApiUtil.handleCreatedResponse(response);

        instanceContext.addNote(USER_UUID_KEY, uuid);

        UserResource userResource = realm.admin().users().get(uuid);
        userRepresentation.setId(uuid);

        return new ManagedUser(userRepresentation, userResource);
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
