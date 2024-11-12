/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.quarkus.runtime.configuration.mappers;

import static java.util.Optional.ofNullable;
import static org.keycloak.quarkus.runtime.Environment.isRebuild;
import static org.keycloak.quarkus.runtime.configuration.Configuration.OPTION_PART_SEPARATOR;
import static org.keycloak.quarkus.runtime.configuration.Configuration.OPTION_PART_SEPARATOR_CHAR;
import static org.keycloak.quarkus.runtime.configuration.Configuration.toCliFormat;
import static org.keycloak.quarkus.runtime.configuration.Configuration.toEnvVarFormat;

import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.stream.Stream;

import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.ConfigValue.ConfigValueBuilder;
import io.smallrye.config.ExpressionConfigSourceInterceptor;
import io.smallrye.config.Expressions;

import org.keycloak.config.DeprecatedMetadata;
import org.keycloak.config.Option;
import org.keycloak.config.OptionBuilder;
import org.keycloak.config.OptionCategory;
import org.keycloak.quarkus.runtime.cli.PropertyException;
import org.keycloak.quarkus.runtime.cli.ShortErrorMessageHandler;
import org.keycloak.quarkus.runtime.configuration.ConfigArgsConfigSource;
import org.keycloak.quarkus.runtime.configuration.Configuration;
import org.keycloak.quarkus.runtime.configuration.KcEnvConfigSource;
import org.keycloak.quarkus.runtime.configuration.KeycloakConfigSourceProvider;
import org.keycloak.quarkus.runtime.Environment;
import org.keycloak.quarkus.runtime.configuration.MicroProfileConfigProvider;
import org.keycloak.utils.StringUtil;

public class PropertyMapper<T> {

    static PropertyMapper<?> IDENTITY = new PropertyMapper<>(
            new OptionBuilder<>(null, String.class).build(),
            null,
            () -> false,
            "",
            null,
            null,
            null,
            null,
            false,
            null,
            null,
            () -> false,
            "") {
        @Override
        public ConfigValue getConfigValue(String name, ConfigSourceInterceptorContext context) {
            return context.proceed(name);
        }
    };

    private final Option<T> option;
    private final String to;
    private BooleanSupplier enabled;
    private String enabledWhen;
    private final BiFunction<String, ConfigSourceInterceptorContext, String> mapper;
    private final String mapFrom;
    private final BiFunction<String, ConfigSourceInterceptorContext, String> parentMapper;
    private final boolean mask;
    private final String paramLabel;
    private final String envVarFormat;
    private final String cliFormat;
    private final BiConsumer<PropertyMapper<T>, ConfigValue> validator;
    private final String description;
    private final BooleanSupplier required;
    private final String requiredWhen;

    PropertyMapper(Option<T> option, String to, BooleanSupplier enabled, String enabledWhen,
                   BiFunction<String, ConfigSourceInterceptorContext, String> mapper,
                   String mapFrom, BiFunction<String, ConfigSourceInterceptorContext, String> parentMapper,
                   String paramLabel, boolean mask, BiConsumer<PropertyMapper<T>, ConfigValue> validator,
                   String description, BooleanSupplier required, String requiredWhen) {
        this.option = option;
        this.to = to == null ? getFrom() : to;
        this.enabled = enabled;
        this.enabledWhen = enabledWhen;
        this.mapper = mapper;
        this.mapFrom = mapFrom;
        this.paramLabel = paramLabel;
        this.mask = mask;
        this.cliFormat = toCliFormat(option.getKey());
        this.required = required;
        this.requiredWhen = requiredWhen;
        this.envVarFormat = toEnvVarFormat(getFrom());
        this.validator = validator;
        this.description = description;
        this.parentMapper = parentMapper;
    }

    ConfigValue getConfigValue(ConfigSourceInterceptorContext context) {
        return getConfigValue(to, context);
    }

    ConfigValue getConfigValue(String name, ConfigSourceInterceptorContext context) {
        String from = getFrom();

        if (to != null && to.endsWith(OPTION_PART_SEPARATOR)) {
            // in case mapping is based on prefixes instead of full property names
            from = name.replace(to.substring(0, to.lastIndexOf('.')), from.substring(0, from.lastIndexOf(OPTION_PART_SEPARATOR_CHAR)));
        }

        if ((isRebuild() || Environment.isRebuildCheck()) && isRunTime()) {
            // during re-aug do not resolve the server runtime properties and avoid they included by quarkus in the default value config source
            return ConfigValue.builder().withName(name).build();
        }

        // try to obtain the value for the property we want to map first
        ConfigValue config = convertValue(context.proceed(from));

        boolean parentValue = false;
        if (mapFrom != null && (config == null || config.getValue() == null)) {
            // if the property we want to map depends on another one, we use the value from the other property to call the mapper
            config = Configuration.getKcConfigValue(mapFrom);
            parentValue = true;
        }

        if (config != null && config.getValue() != null) {
            config = transformValue(name, config, context, parentValue);
        } else {
            String defaultValue = this.option.getDefaultValue().map(Option::getDefaultValueString).orElse(null);
            config = transformValue(name, new ConfigValueBuilder().withName(name)
                    .withValue(defaultValue).withRawValue(defaultValue).build(),
                    context, false);
        }

        if (config != null) {
            return config;
        }

        // now try any defaults from quarkus
        return context.proceed(name);
    }

    public Option<T> getOption() {
        return this.option;
    }

    public void setEnabled(BooleanSupplier enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled.getAsBoolean();
    }

    public Optional<String> getEnabledWhen() {
        return Optional.of(enabledWhen)
                .filter(StringUtil::isNotBlank)
                .map(e -> "Available only when " + e);
    }

    public void setEnabledWhen(String enabledWhen) {
        this.enabledWhen = enabledWhen;
    }

    public boolean isRequired() {
        return required.getAsBoolean();
    }

    public Optional<String> getRequiredWhen() {
        return Optional.of(requiredWhen)
                .filter(StringUtil::isNotBlank)
                .map(e -> "Required when " + e);
    }

    public Class<T> getType() {
        return this.option.getType();
    }

    public String getFrom() {
        return MicroProfileConfigProvider.NS_KEYCLOAK_PREFIX + this.option.getKey();
    }

    public String getDescription() {
        return this.description;
    }

    /**
     * If {@link #isStrictExpectedValues()} is false, custom values can be provided
     * Otherwise, only specified expected values can be used.
     *
     * @return expected values
     */
    public List<String> getExpectedValues() {
        return this.option.getExpectedValues();
    }

    public boolean isStrictExpectedValues() {
        return this.option.isStrictExpectedValues();
    }

    public Optional<T> getDefaultValue() { return this.option.getDefaultValue(); }

    public OptionCategory getCategory() {
        return this.option.getCategory();
    }

    public boolean isHidden() { return this.option.isHidden(); }

    public boolean isBuildTime() {
        return this.option.isBuildTime();
    }

    public boolean isRunTime() {
        return !this.option.isBuildTime();
    }

    public String getTo() {
        return to;
    }

    public String getParamLabel() {
        return paramLabel;
    }

    public String getCliFormat() {
        return cliFormat;
    }

    public String getEnvVarFormat() {
        return envVarFormat;
    }

    boolean isMask() {
        return mask;
    }

    public Optional<DeprecatedMetadata> getDeprecatedMetadata() {
        return option.getDeprecatedMetadata();
    }

    private ConfigValue transformValue(String name, ConfigValue configValue, ConfigSourceInterceptorContext context, boolean parentValue) {
        String value = configValue.getValue();
        String mappedValue = value;

        boolean mapped = false;
        var theMapper = parentValue ? this.parentMapper : this.mapper;
        if (theMapper != null && (!name.equals(getFrom()) || parentValue)) {
            mappedValue = theMapper.apply(value, context);
            mapped = true;
        }

        // defaults and values from transformers may not have been subject to expansion
        if ((mapped || configValue.getConfigSourceName() == null) && mappedValue != null && Expressions.isEnabled() && mappedValue.contains("$")) {
            mappedValue = new ExpressionConfigSourceInterceptor().getValue(
                    new ContextWrapper(context, new ConfigValueBuilder().withName(name).withValue(mappedValue).build()),
                    name).getValue();
        }

        if (value == null && mappedValue == null) {
            return null;
        }

        if (!mapped && name.equals(configValue.getName())) {
            return configValue;
        }

        // by unsetting the ordinal this will not be seen as directly modified by the user
        return configValue.from().withValue(mappedValue).withRawValue(value).withConfigSourceOrdinal(0).build();
    }

    private ConfigValue convertValue(ConfigValue configValue) {
        if (configValue == null) {
            return null;
        }

        return configValue.withValue(ofNullable(configValue.getValue()).map(String::trim).orElse(null));
    }

    private final class ContextWrapper implements ConfigSourceInterceptorContext {
        private final ConfigSourceInterceptorContext context;
        private final ConfigValue value;

        private ContextWrapper(ConfigSourceInterceptorContext context, ConfigValue value) {
            this.context = context;
            this.value = value;
        }

        @Override
        public ConfigValue restart(String name) {
            return context.restart(name);
        }

        @Override
        public ConfigValue proceed(String name) {
            if (name.equals(value.getName())) {
                return value;
            }
            return context.proceed(name);
        }

        @Override
        public Iterator<String> iterateNames() {
            return context.iterateNames();
        }
    }

    public static class Builder<T> {

        private final Option<T> option;
        private String to;
        private BiFunction<String, ConfigSourceInterceptorContext, String> mapper;
        private String mapFrom = null;
        private BiFunction<String, ConfigSourceInterceptorContext, String> parentMapper;
        private boolean isMasked = false;
        private BooleanSupplier isEnabled = () -> true;
        private String enabledWhen = "";
        private String paramLabel;
        private BiConsumer<PropertyMapper<T>, ConfigValue> validator = (mapper, value) -> mapper.validateValues(value, mapper::validateExpectedValues);
        private String description;
        private BooleanSupplier isRequired = () -> false;
        private String requiredWhen = "";

        public Builder(Option<T> option) {
            this.option = option;
            this.description = this.option.getDescription();
        }

        public Builder<T> to(String to) {
            this.to = to;
            return this;
        }

        /**
         * NOTE: This transformer will not apply to the mapFrom value. When using
         * {@link #mapFrom} you generally need a transformer specifically for the parent
         * value, see {@link #mapFrom(Option, BiFunction)}
         * <p>
         * The value passed into the transformer may be null if the property has no value set, and no default
         */
        public Builder<T> transformer(BiFunction<String, ConfigSourceInterceptorContext, String> mapper) {
            this.mapper = mapper;
            return this;
        }

        public Builder<T> paramLabel(String label) {
            this.paramLabel = label;
            return this;
        }

        public Builder<T> mapFrom(Option<?> mapFrom) {
            this.mapFrom = mapFrom.getKey();
            return this;
        }

        public Builder<T> mapFrom(Option<?> mapFrom, BiFunction<String, ConfigSourceInterceptorContext, String> parentMapper) {
            this.mapFrom = mapFrom.getKey();
            this.parentMapper = parentMapper;
            return this;
        }

        public Builder<T> isMasked(boolean isMasked) {
            this.isMasked = isMasked;
            return this;
        }

        public Builder<T> isEnabled(BooleanSupplier isEnabled, String enabledWhen) {
            this.isEnabled = isEnabled;
            this.enabledWhen=enabledWhen;
            return this;
        }

        public Builder<T> isEnabled(BooleanSupplier isEnabled) {
            this.isEnabled = isEnabled;
            return this;
        }

        /**
         * Sets this option as required when the {@link BooleanSupplier} returns {@code true}.
         * <p>
         * The {@code enableWhen} parameter is a message to show with the error message.
         * <p>
         * This check is only run in runtime mode.
         */
        public Builder<T> isRequired(BooleanSupplier isRequired, String requiredWhen) {
            this.requiredWhen = Objects.requireNonNull(requiredWhen);
            assert !requiredWhen.endsWith(".");
            return isRequired(isRequired);
        }

        /**
         * Sets this option as required when the {@link BooleanSupplier} returns {@code true}.
         * <p>
         * This check is only run in runtime mode.
         */
        public Builder<T> isRequired(BooleanSupplier isRequired) {
            this.isRequired = Objects.requireNonNull(isRequired);
            return this;
        }

        /**
         * Set the validator, overwriting the current one.
         */
        public Builder<T> validator(Consumer<String> validator) {
            this.validator = (mapper, value) -> mapper.validateValues(value,
                    (c, v) -> validator.accept(v));
            if (!Objects.equals(this.description, this.option.getDescription())) {
                throw new AssertionError("Overwriting the validator will cause the description modification from addValidateEnabled to be incorrect.");
            }
            return this;
        }

        public Builder<T> addValidator(BiConsumer<PropertyMapper<T>, ConfigValue> validator) {
            var current = this.validator;
            this.validator = (mapper, value) -> {
                Stream.of(current, validator).map(v -> {
                    try {
                        v.accept(mapper, value);
                        return Optional.<PropertyException>empty();
                    } catch (PropertyException e) {
                        return Optional.of(e);
                    }
                }).flatMap(Optional::stream)
                        .reduce((e1, e2) -> new PropertyException(String.format("%s.\n%s", e1.getMessage(), e2.getMessage())))
                        .ifPresent(e -> {
                            throw e;
                        });
            };
            return this;
        }

        /**
         * Similar to {@link #enabledWhen}, but uses the condition as a validator that is added to the current one. This allows the option
         * to appear in help.
         * @return
         */
        public Builder<T> addValidateEnabled(BooleanSupplier isEnabled, String enabledWhen) {
            this.addValidator((mapper, value) -> {
                if (!isEnabled.getAsBoolean()) {
                    throw new PropertyException(mapper.getOption().getKey() + " available only when " + enabledWhen);
                }
            });
            this.description = String.format("%s Available only when %s.", this.description, enabledWhen);
            return this;
        }

        public PropertyMapper<T> build() {
            if (paramLabel == null && Boolean.class.equals(option.getType())) {
                paramLabel = Boolean.TRUE + "|" + Boolean.FALSE;
            }
            return new PropertyMapper<>(option, to, isEnabled, enabledWhen, mapper, mapFrom, parentMapper, paramLabel, isMasked, validator, description, isRequired, requiredWhen);
        }
    }

    public static <T> PropertyMapper.Builder<T> fromOption(Option<T> opt) {
        return new PropertyMapper.Builder<>(opt);
    }

    public void validate(ConfigValue value) {
        if (validator != null) {
            validator.accept(this, value);
        }
    }

    public boolean isList() {
        return getOption().getType() == java.util.List.class;
    }

    public void validateValues(ConfigValue configValue, BiConsumer<ConfigValue, String> singleValidator) {
        String value = configValue.getValue();

        boolean multiValued = isList();
        StringBuilder result = new StringBuilder();

        String[] values = multiValued ? value.split(",") : new String[] { value };
        for (String v : values) {
            if (multiValued && !v.trim().equals(v)) {
                if (!result.isEmpty()) {
                    result.append(".\n");
                }
                result.append("Invalid value for multivalued option ")
                        .append(getOptionAndSourceMessage(configValue))
                        .append(": list value '")
                        .append(v)
                        .append("' should not have leading nor trailing whitespace");
                continue;
            }
            try {
                singleValidator.accept(configValue, v);
            } catch (PropertyException e) {
                if (!result.isEmpty()) {
                    result.append(".\n");
                }
                result.append(e.getMessage());
            }
        }

        if (!result.isEmpty()) {
            throw new PropertyException(result.toString());
        }
    }

    public static boolean isCliOption(ConfigValue configValue) {
        return Optional.ofNullable(configValue.getConfigSourceName()).filter(name -> name.contains(ConfigArgsConfigSource.NAME)).isPresent();
    }

    public static boolean isEnvOption(ConfigValue configValue) {
        return Optional.ofNullable(configValue.getConfigSourceName()).filter(name -> name.contains(KcEnvConfigSource.NAME)).isPresent();
    }

    void validateExpectedValues(ConfigValue configValue, String v) {
        List<String> expectedValues = getExpectedValues();
        if (!expectedValues.isEmpty() && !expectedValues.contains(v) && getOption().isStrictExpectedValues()) {
            throw new PropertyException(
                    String.format("Invalid value for option %s: %s.%s", getOptionAndSourceMessage(configValue), v,
                            ShortErrorMessageHandler.getExpectedValuesMessage(expectedValues)));
        }
    }

    String getOptionAndSourceMessage(ConfigValue configValue) {
        if (isCliOption(configValue)) {
            return String.format("'%s'", this.getCliFormat());
        }
        if (isEnvOption(configValue)) {
            return String.format("'%s'", this.getEnvVarFormat());
        }
        return String.format("'%s' in %s", getFrom(),
                KeycloakConfigSourceProvider.getConfigSourceDisplayName(configValue.getConfigSourceName()));
    }

}
