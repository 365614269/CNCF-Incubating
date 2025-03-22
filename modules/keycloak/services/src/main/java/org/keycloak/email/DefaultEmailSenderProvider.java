/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.email;

import jakarta.mail.internet.MimeUtility;
import org.jboss.logging.Logger;
import org.keycloak.common.enums.HostnameVerificationPolicy;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.truststore.JSSETruststoreConfigurator;

import jakarta.mail.Address;
import jakarta.mail.MessagingException;
import jakarta.mail.Multipart;
import jakarta.mail.Session;
import jakarta.mail.Message;
import jakarta.mail.Transport;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.internet.MimeMessage;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.Properties;

import static org.keycloak.utils.StringUtil.isNotBlank;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class DefaultEmailSenderProvider implements EmailSenderProvider {

    private static final Logger logger = Logger.getLogger(DefaultEmailSenderProvider.class);
    private static final String SUPPORTED_SSL_PROTOCOLS = getSupportedSslProtocols();

    private final Map<EmailAuthenticator.AuthenticatorType, EmailAuthenticator> authenticators;

    private final KeycloakSession session;

    public DefaultEmailSenderProvider(KeycloakSession session, Map<EmailAuthenticator.AuthenticatorType, EmailAuthenticator> authenticators) {
        this.authenticators = authenticators;
        this.session = session;
    }

    @Override
    public void send(Map<String, String> config, UserModel user, String subject, String textBody, String htmlBody) throws EmailException {
        String address = retrieveEmailAddress(user);
        if (address == null) {
            throw new EmailException("No email address configured for the user");
        }
        send(config, address, subject, textBody, htmlBody);
    }

    @Override
    public void send(Map<String, String> config, String address, String subject, String textBody, String htmlBody) throws EmailException {
        Session session = Session.getInstance(buildEmailProperties(config));

        Message message = buildMessage(session, address, subject, config, buildMultipartBody(textBody, htmlBody));

        try(Transport transport = session.getTransport("smtp")) {

            EmailAuthenticator selectedAuthenticator = selectAuthenticatorBasedOnConfig(config);
            selectedAuthenticator.connect(this.session, config, transport);

            transport.sendMessage(message, new InternetAddress[]{new InternetAddress(address)});

        } catch (Exception e) {
            ServicesLogger.LOGGER.failedToSendEmail(e);
            throw new EmailException("Error when attempting to send the email to the server. More information is available in the server log.", e);
        }
    }

    private Properties buildEmailProperties(Map<String, String> config) {
        Properties props = new Properties();

        if (config.containsKey("host")) {
            props.setProperty("mail.smtp.host", config.get("host"));
        }

        if (config.containsKey("port") && config.get("port") != null) {
            props.setProperty("mail.smtp.port", config.get("port"));
        }

        if (isAuthConfigured(config)) {
            props.setProperty("mail.smtp.auth", "true");
        }

        if (isAuthTypeTokenConfigured(config)) {
            props.put("mail.smtp.auth.mechanisms", "XOAUTH2");
        }

        if (isDebugEnabled(config)) {
            props.put("mail.debug", "true");
        }

        if (isSslConfigured(config)) {
            props.setProperty("mail.smtp.ssl.enable", "true");
        }

        if (isStarttlsConfigured(config)) {
            props.setProperty("mail.smtp.starttls.enable", "true");
        }

        if (isSslConfigured(config) || isStarttlsConfigured(config) || isAuthConfigured(config)) {
            props.put("mail.smtp.ssl.protocols", SUPPORTED_SSL_PROTOCOLS);

            setupTruststore(props);
        }

        props.setProperty("mail.smtp.timeout", "10000");
        props.setProperty("mail.smtp.connectiontimeout", "10000");
        props.setProperty("mail.smtp.writetimeout", "10000");

        String envelopeFrom = config.get("envelopeFrom");
        if (isNotBlank(envelopeFrom)) {
            props.setProperty("mail.smtp.from", envelopeFrom);
        }
        return props;
    }

    private Message buildMessage(Session session, String address, String subject, Map<String, String> config, Multipart multipart) throws EmailException {

        String from = config.get("from");
        if (from == null) {
            throw new EmailException("No sender address configured in the realm settings for emails");
        }
        String fromDisplayName = config.get("fromDisplayName");
        String replyTo = config.get("replyTo");
        String replyToDisplayName = config.get("replyToDisplayName");

        try {
            Message msg = new MimeMessage(session);
            msg.setFrom(toInternetAddress(from, fromDisplayName));
            msg.setReplyTo(new Address[]{toInternetAddress(from, fromDisplayName)});

            if (isNotBlank(replyTo)) {
                msg.setReplyTo(new Address[]{toInternetAddress(replyTo, replyToDisplayName)});
            }

            msg.setHeader("To", address);
            msg.setSubject(MimeUtility.encodeText(subject, StandardCharsets.UTF_8.name(), null));
            msg.setContent(multipart);
            msg.saveChanges();
            msg.setSentDate(new Date());

            return msg;
        } catch (UnsupportedEncodingException e) {
            throw new EmailException("Failed to encode email address", e);
        } catch (AddressException e) {
            throw new EmailException("Invalid email address format", e);
        } catch (MessagingException e) {
            throw new EmailException("MessagingException occurred", e);
        }
    }

    private Multipart buildMultipartBody(String textBody, String htmlBody) throws EmailException {
        Multipart multipart = new MimeMultipart("alternative");

        try {
            if (textBody != null) {
                MimeBodyPart textPart = new MimeBodyPart();
                textPart.setText(textBody, "UTF-8");
                multipart.addBodyPart(textPart);
            }

            if (htmlBody != null) {
                MimeBodyPart htmlPart = new MimeBodyPart();
                htmlPart.setContent(htmlBody, "text/html; charset=UTF-8");
                multipart.addBodyPart(htmlPart);
            }
        } catch (MessagingException e) {
            throw new EmailException("Error encoding email body parts", e);
        }

        return multipart;
    }

    private EmailAuthenticator selectAuthenticatorBasedOnConfig(Map<String, String> config) {
        if(isAuthConfigured(config)) {
            String authType = config.getOrDefault("authType", "basic");
            return authenticators.get(EmailAuthenticator.AuthenticatorType.valueOf(authType.toUpperCase()));
        }

        return authenticators.get(EmailAuthenticator.AuthenticatorType.NONE);
    }

    private static boolean isStarttlsConfigured(Map<String, String> config) {
        return "true".equals(config.get("starttls"));
    }

    private static boolean isSslConfigured(Map<String, String> config) {
        return "true".equals(config.get("ssl"));
    }

    private static boolean isDebugEnabled(Map<String, String> config) {
        return "true".equals(config.get("debug"));
    }

    private boolean isAuthConfigured(Map<String, String> config) {
        return "true".equals(config.get("auth"));
    }

    private boolean isAuthTypeTokenConfigured(Map<String, String> config) {
        return "token".equals(config.get("authType"));
    }


    protected InternetAddress toInternetAddress(String email, String displayName) throws UnsupportedEncodingException, AddressException, EmailException {
        if (email == null || "".equals(email.trim())) {
            throw new EmailException("Please provide a valid address", null);
        }
        if (displayName == null || "".equals(displayName.trim())) {
            return new InternetAddress(email);
        }
        return new InternetAddress(email, displayName, "utf-8");
    }

    protected String retrieveEmailAddress(UserModel user) {
        return user.getEmail();
    }

    private void setupTruststore(Properties props) {
        JSSETruststoreConfigurator configurator = new JSSETruststoreConfigurator(session);

        SSLSocketFactory factory = configurator.getSSLSocketFactory();
        if (factory != null) {
            props.put("mail.smtp.ssl.socketFactory", factory);
            if (configurator.getProvider().getPolicy() == HostnameVerificationPolicy.ANY) {
                props.setProperty("mail.smtp.ssl.trust", "*");
                props.put("mail.smtp.ssl.checkserveridentity", Boolean.FALSE.toString()); // this should be the default but seems to be impl specific, so set it explicitly just to be sure
            } else {
                props.put("mail.smtp.ssl.checkserveridentity", Boolean.TRUE.toString());
            }
        }
    }

    @Override
    public void close() {

    }

    private static String getSupportedSslProtocols() {
        try {
            String[] protocols = SSLContext.getDefault().getSupportedSSLParameters().getProtocols();
            if (protocols != null) {
                return String.join(" ", protocols);
            }
        } catch (Exception e) {
            logger.warn("Failed to get list of supported SSL protocols", e);
        }
        return null;
    }

}
