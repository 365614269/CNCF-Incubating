package org.keycloak.test.framework.realm;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.test.framework.TestRealm;
import org.keycloak.test.framework.injection.InstanceWrapper;
import org.keycloak.test.framework.injection.LifeCycle;
import org.keycloak.test.framework.injection.Registry;
import org.keycloak.test.framework.injection.RequestedInstance;
import org.keycloak.test.framework.injection.Supplier;
import org.keycloak.test.framework.injection.SupplierHelpers;

public class RealmSupplier implements Supplier<RealmResource, TestRealm> {

    private static final String REALM_NAME_KEY = "realmName";

    @Override
    public Class<TestRealm> getAnnotationClass() {
        return TestRealm.class;
    }

    @Override
    public Class<RealmResource> getValueType() {
        return RealmResource.class;
    }

    @Override
    public InstanceWrapper<RealmResource, TestRealm> getValue(Registry registry, TestRealm annotation) {
        InstanceWrapper<RealmResource, TestRealm> wrapper = new InstanceWrapper<>(this, annotation);
        LifeCycle lifecycle = annotation.lifecycle();

        Keycloak adminClient = registry.getDependency(Keycloak.class, wrapper);

        RealmConfig config = SupplierHelpers.getInstance(annotation.config());
        RealmRepresentation realmRepresentation = config.getRepresentation();

        if (realmRepresentation.getRealm() == null) {
            String realmName = lifecycle.equals(LifeCycle.GLOBAL) ? config.getClass().getSimpleName() : registry.getCurrentContext().getRequiredTestClass().getSimpleName();
            realmRepresentation.setRealm(realmName);
        }

        String realmName = realmRepresentation.getRealm();
        wrapper.addNote(REALM_NAME_KEY, realmName);

        adminClient.realms().create(realmRepresentation);

        RealmResource realmResource = adminClient.realm(realmRepresentation.getRealm());
        wrapper.setValue(realmResource, lifecycle);

        return wrapper;
    }

    @Override
    public boolean compatible(InstanceWrapper<RealmResource, TestRealm> a, RequestedInstance<RealmResource, TestRealm> b) {
        return a.getAnnotation().config().equals(b.getAnnotation().config());
    }

    @Override
    public void close(RealmResource realm) {
        realm.remove();
    }

}
