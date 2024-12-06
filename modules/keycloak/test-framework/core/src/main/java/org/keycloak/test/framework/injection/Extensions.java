package org.keycloak.test.framework.injection;

import org.keycloak.test.framework.TestFrameworkExtension;
import org.keycloak.test.framework.config.Config;

import java.lang.annotation.Annotation;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;

public class Extensions {

    private final RegistryLogger logger;
    private final ValueTypeAlias valueTypeAlias;
    private final List<Supplier<?, ?>> suppliers;
    private final List<Class<?>> alwaysEnabledValueTypes;

    public Extensions() {
        List<TestFrameworkExtension> extensions = loadExtensions();
        valueTypeAlias = loadValueTypeAlias(extensions);
        logger = new RegistryLogger(valueTypeAlias);
        suppliers = loadSuppliers(extensions, valueTypeAlias);
        alwaysEnabledValueTypes = loadAlwaysEnabledValueTypes(extensions);
    }

    public ValueTypeAlias getValueTypeAlias() {
        return valueTypeAlias;
    }

    public List<Supplier<?, ?>> getSuppliers() {
        return suppliers;
    }

    public List<Class<?>> getAlwaysEnabledValueTypes() {
        return alwaysEnabledValueTypes;
    }

    @SuppressWarnings("unchecked")
    public <T> Supplier<T, ?> findSupplierByType(Class<T> typeClass) {
        return (Supplier<T, ?>) suppliers.stream().filter(s -> s.getValueType().equals(typeClass)).findFirst().orElse(null);
    }

    @SuppressWarnings("unchecked")
    public <T> Supplier<T, ?> findSupplierByAnnotation(Annotation annotation) {
        return (Supplier<T, ?>) suppliers.stream().filter(s -> s.getAnnotationClass().equals(annotation.annotationType())).findFirst().orElse(null);
    }

    private List<TestFrameworkExtension> loadExtensions() {
        List<TestFrameworkExtension> extensions = new LinkedList<>();
        ServiceLoader.load(TestFrameworkExtension.class).iterator().forEachRemaining(extensions::add);
        return extensions;
    }

    private ValueTypeAlias loadValueTypeAlias(List<TestFrameworkExtension> extensions) {
        ValueTypeAlias valueTypeAlias = new ValueTypeAlias();
        extensions.forEach(e -> valueTypeAlias.addAll(e.valueTypeAliases()));
        return valueTypeAlias;
    }

    private List<Supplier<?, ?>> loadSuppliers(List<TestFrameworkExtension> extensions, ValueTypeAlias valueTypeAlias) {
        List<Supplier<?, ?>> suppliers = new LinkedList<>();
        List<Supplier<?, ?>> skippedSuppliers = new LinkedList<>();
        Set<Class<?>> loadedValueTypes = new HashSet<>();

        for (TestFrameworkExtension extension : extensions) {
            for (var supplier : extension.suppliers()) {
                Class<?> valueType = supplier.getValueType();
                String requestedSupplier = Config.getSelectedSupplier(valueType, valueTypeAlias);
                if (supplier.getAlias().equals(requestedSupplier) || (requestedSupplier == null && !loadedValueTypes.contains(valueType))) {
                    suppliers.add(supplier);
                    loadedValueTypes.add(valueType);
                } else {
                    skippedSuppliers.add(supplier);
                }
            }
        }

        logger.logSuppliers(suppliers, skippedSuppliers);

        return suppliers;
    }

    private List<Class<?>> loadAlwaysEnabledValueTypes(List<TestFrameworkExtension> extensions) {
        return extensions.stream().flatMap(s -> s.alwaysEnabledValueTypes().stream()).toList();
    }

}
