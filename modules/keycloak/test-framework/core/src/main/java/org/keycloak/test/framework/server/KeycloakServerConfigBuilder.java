package org.keycloak.test.framework.server;

import io.quarkus.maven.dependency.Dependency;
import io.quarkus.maven.dependency.DependencyBuilder;
import io.smallrye.config.SmallRyeConfig;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.keycloak.common.Profile;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class KeycloakServerConfigBuilder {

    private final String command;
    private final Map<String, String> options = new HashMap<>();
    private final Set<String> features = new HashSet<>();
    private final Set<String> featuresDisabled = new HashSet<>();
    private final LogBuilder log = new LogBuilder();
    private final Set<Dependency> dependencies = new HashSet<>();

    private KeycloakServerConfigBuilder(String command) {
        this.command = command;
    }

    public static KeycloakServerConfigBuilder startDev() {
        return new KeycloakServerConfigBuilder("start-dev");
    }

    public KeycloakServerConfigBuilder bootstrapAdminClient(String clientId, String clientSecret) {
        return option("bootstrap-admin-client-id", clientId)
                .option("bootstrap-admin-client-secret", clientSecret);
    }

    public KeycloakServerConfigBuilder cache(String cache) {
        return option("cache", cache);
    }

    public LogBuilder log() {
        return log;
    }

    public KeycloakServerConfigBuilder features(Profile.Feature... features) {
        this.features.addAll(toFeatureStrings(features));
        return this;
    }

    public KeycloakServerConfigBuilder featuresDisabled(Profile.Feature... features) {
        this.featuresDisabled.addAll(toFeatureStrings(features));
        return this;
    }

    public KeycloakServerConfigBuilder options(Map<String, String> options) {
        this.options.putAll(options);
        return this;
    }

    public KeycloakServerConfigBuilder option(String key, String value) {
        options.put(key, value);
        return this;
    }

    public KeycloakServerConfigBuilder dependency(String groupId, String artifactId) {
        dependencies.add(new DependencyBuilder().setGroupId(groupId).setArtifactId(artifactId).build());
        return this;
    }

    public class LogBuilder {

        private Boolean color;
        private String format;
        private String rootLevel;
        private final Map<String, String> categoryLevels = new HashMap<>();
        private final Map<String, String> handlerLevels = new HashMap<>();
        private final Set<String> handlers = new HashSet<>();
        private String syslogEndpoint;

        public LogBuilder handlers(LogHandlers... handlers) {
            this.handlers.addAll(Arrays.stream(handlers).map(l -> l.name().toLowerCase()).collect(Collectors.toSet()));
            return this;
        }

        public LogBuilder handlerLevel(LogHandlers handler, String logLevel) {
            handlerLevels.put(handler.name().toLowerCase(), logLevel);
            return this;
        }

        public LogBuilder categoryLevel(String category, String logLevel) {
            categoryLevels.put(category, logLevel);
            return this;
        }

        public LogBuilder syslogEndpoint(String syslogEndpoint) {
            this.syslogEndpoint = syslogEndpoint;
            return this;
        }

        public LogBuilder fromConfig(SmallRyeConfig config) {
            List<ConfigSource> sources = new LinkedList<>();
            for (ConfigSource source : config.getConfigSources()) {
                if (source.getName().startsWith("EnvConfigSource") || source.getName().equals("KeycloakTestConfig")) {
                    sources.add(source);
                }
            }

            for (ConfigSource source : sources) {
                for (String p : source.getPropertyNames()) {
                    if (p.equals("kc.test.log.console.format") && format == null) {
                        format = source.getValue(p);
                    }
                    if (p.equals("kc.test.console.color") && color == null) {
                        color = Boolean.parseBoolean(source.getValue(p));
                    } else if (p.equals("kc.test.log.level") && rootLevel == null) {
                        rootLevel = source.getValue(p);
                    } else if (p.startsWith("kc.test.log.category.")) {
                        String category = p.split("\"")[1];
                        String level = source.getValue(p);

                        if (!categoryLevels.containsKey(category)) {
                            categoryLevels.put(category, level);
                        }
                    }
                }
            }
            return this;
        }

        private void build() {
            if (!handlers.isEmpty()) {
                option("log", String.join(",", handlers));
            }

            if (!handlerLevels.isEmpty()) {
                handlerLevels.forEach((key, value) -> option("log-" + key + "-level", value));
            }

            if (syslogEndpoint != null) {
                option("log-syslog-endpoint", syslogEndpoint);
            }

            if (format != null) {
                option("log-console-format", format);
            }

            StringBuilder logLevel = new StringBuilder();
            if (rootLevel != null) {
                logLevel.append(rootLevel);
            }

            for (Map.Entry<String, String> e : categoryLevels.entrySet()) {
                if (!logLevel.isEmpty()) {
                    logLevel.append(",");
                }
                logLevel.append(e.getKey());
                logLevel.append(":");
                logLevel.append(e.getValue());
            }

            if (!logLevel.isEmpty()) {
                option("log-level", logLevel.toString());
            }

            if (color != null) {
                option("log-console-color", color.toString());
            }
        }
    }

    public List<String> toArgs() {
        log.build();

        List<String> args = new LinkedList<>();
        args.add(command);
        for (Map.Entry<String, String> e : options.entrySet()) {
            args.add("--" + e.getKey() + "=" + e.getValue());
        }
        if (!features.isEmpty()) {
            args.add("--features=" + String.join(",", features));
        }
        if (!featuresDisabled.isEmpty()) {
            args.add("--features-disabled=" + String.join(",", featuresDisabled));
        }

        return args;
    }

    public Set<Dependency> toDependencies() {
        return dependencies;
    }

    private Set<String> toFeatureStrings(Profile.Feature... features) {
        return Arrays.stream(features).map(f -> f.name().toLowerCase().replace('_', '-')).collect(Collectors.toSet());
    }

    public enum LogHandlers {
        CONSOLE,
        FILE,
        SYSLOG
    }

}
