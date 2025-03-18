package org.keycloak.compatibility;

import java.util.Optional;

/**
 * Internal class to signal that the provider is not compatible with the previous metadata.
 * <p>
 * It provides information about the provider's ID and the attribute previous and current values.
 */
record ProviderIncompatibleResult(String providerId, String attribute, String previousValue,
                                  String currentValue) implements CompatibilityResult {
    @Override
    public int exitCode() {
        return ExitCode.RECREATE.value();
    }

    @Override
    public Optional<String> errorMessage() {
        return Optional.of("[%s] Rolling Upgrade is not available. '%s.%s' is incompatible: %s -> %s.".formatted(providerId, providerId, attribute, previousValue, currentValue));
    }
}
