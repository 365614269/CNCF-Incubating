package org.keycloak.test.framework.injection;

import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class InstanceContext<T, A extends Annotation> {

    private final Registry registry;
    private final Supplier<T, A> supplier;
    private final A annotation;
    private final Set<InstanceContext<T, A>> dependencies = new HashSet<>();
    private T value;
    private Class<? extends T> requestedValueType;
    private LifeCycle lifeCycle;
    private final String ref;
    private final Map<String, Object> notes = new HashMap<>();

    public InstanceContext(Registry registry, Supplier<T, A> supplier, A annotation, Class<? extends T> requestedValueType) {
        this.registry = registry;
        this.supplier = supplier;
        this.annotation = annotation;
        this.requestedValueType = requestedValueType;
        this.lifeCycle = supplier.getLifeCycle(annotation);
        this.ref = supplier.getRef(annotation);
    }

    public <D> D getDependency(Class<D> typeClazz) {
        return registry.getDependency(typeClazz, this);
    }

    public Registry getRegistry() {
        return registry;
    }

    void setValue(T value) {
        this.value = value;
    }

    public Supplier<T, A> getSupplier() {
        return supplier;
    }

    public T getValue() {
        return value;
    }

    public Class<? extends T> getRequestedValueType() {
        return requestedValueType;
    }

    public LifeCycle getLifeCycle() {
        return lifeCycle;
    }

    public String getRef() {
        return ref;
    }

    public A getAnnotation() {
        return annotation;
    }

    public Set<InstanceContext<T, A>> getDependencies() {
        return dependencies;
    }

    public void registerDependency(InstanceContext<T, A> instanceContext) {
        dependencies.add(instanceContext);
    }

    public void addNote(String key, Object value) {
        notes.put(key, value);
    }

    @SuppressWarnings("unchecked")
    public <N> N getNote(String key, Class<N> type) {
        return (N) notes.get(key);
    }

}
