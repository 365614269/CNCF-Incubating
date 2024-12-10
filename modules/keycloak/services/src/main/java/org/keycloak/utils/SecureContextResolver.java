package org.keycloak.utils;

import org.keycloak.device.DeviceRepresentationProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.account.DeviceRepresentation;

import java.net.URI;
import java.util.function.Supplier;
import java.util.regex.Pattern;

public class SecureContextResolver {

    private static final Pattern LOCALHOST_IPV4 = Pattern.compile("127.\\d{1,3}.\\d{1,3}.\\d{1,3}");
    private static final Pattern LOCALHOST_IPV6 = Pattern.compile("\\[(0{0,4}:){1,7}0{0,3}1\\]");


    /**
     * Determines if a session is within a 'secure context', meaning its origin is considered potentially trustworthy by user-agents.
     *
     * @see <a href="https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts">MDN Web Docs — Secure Contexts</a>
     * @see <a href="https://w3c.github.io/webappsec-secure-contexts/#algorithms">W3C Secure Contexts specification — Is origin potentially trustworthy?</a>
     * @param session The session to check for trustworthiness.
     * @return Whether the session can be considered potentially trustworthy by user-agents.
     */
    public static boolean isSecureContext(KeycloakSession session) {
        URI uri = session.getContext().getUri().getRequestUri();

        // Use a Supplier so the user-agent is evaluated lazily, avoiding unnecessary parsing in production deployments.
        Supplier<DeviceRepresentation> deviceRepresentationSupplier = () -> {
            DeviceRepresentationProvider deviceRepresentationProvider = session.getProvider(DeviceRepresentationProvider.class);
            return deviceRepresentationProvider.deviceRepresentation();
        };

        return isSecureContext(uri, deviceRepresentationSupplier);
    }

    static boolean isSecureContext(URI uri, Supplier<DeviceRepresentation> deviceRepresentationSupplier) {
        if (uri.getScheme().equals("https")) {
            return true;
        }

        DeviceRepresentation deviceRepresentation = deviceRepresentationSupplier.get();
        String browser = deviceRepresentation != null ? deviceRepresentation.getBrowser() : null;

        // Safari has a bug where even a secure context is not able to set cookies with the 'Secure' directive.
        // Hence, we need to assume the worst case scenario and downgrade to an insecure context.
        // See:
        // - https://github.com/keycloak/keycloak/issues/33557
        // - https://webcompat.com/issues/142566
        // - https://bugs.webkit.org/show_bug.cgi?id=232088
        // - https://bugs.webkit.org/show_bug.cgi?id=276313
        if (browser != null && browser.toLowerCase().contains("safari")) {
            return false;
        }

        String host = uri.getHost();

        if (host == null) {
            return false;
        }

        if (isLocalAddress(host)) {
            return true;
        }

        if (host.equals("localhost") || host.equals("localhost.")) {
            return true;
        }

        return host.endsWith(".localhost") || host.endsWith(".localhost.");
    }

    /**
     * Test whether the given address is the localhost
     * @param address
     * @return false if the address is not localhost or not an address value
     */
    public static boolean isLocalAddress(String address) {
        if (address == null) {
            return false;
        }
        // The host matches a CIDR notation of ::1/128
        if (address.startsWith("[")) {
            return LOCALHOST_IPV6.matcher(address).matches();
        }

        // The host matches a CIDR notation of 127.0.0.0/8
        if (LOCALHOST_IPV4.matcher(address).matches()) {
            return true;
        }

        return false;
    }
}
