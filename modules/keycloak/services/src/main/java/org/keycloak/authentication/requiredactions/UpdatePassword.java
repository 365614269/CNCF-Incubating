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

package org.keycloak.authentication.requiredactions;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionConfigModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.policy.MaxAuthAgePasswordPolicyProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.userprofile.ValidationException;
import org.keycloak.utils.RequiredActionHelper;
import org.keycloak.validate.ValidationError;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UpdatePassword implements RequiredActionProvider, RequiredActionFactory {

    private static final Logger logger = Logger.getLogger(UpdatePassword.class);

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    public static final String MAX_AUTH_AGE_KEY = "max_auth_age";

    static {
        List<ProviderConfigProperty> properties = ProviderConfigurationBuilder.create() //
                .property() //
                .name(MAX_AUTH_AGE_KEY) //
                .label("Maximum Age of Authentication") //
                .helpText("Configures the duration in seconds this action can be used after the last authentication before the user is required to re-authenticate. " + //
                        "This parameter is used just in the context of AIA when the kc_action parameter is available in the request, which is for instance when user " + //
                        "himself updates his password in the account console. When the 'Maximum Authentication Age' password policy is used in the realm, it's value has " + //
                        "precedence over the value configured here.") //
                .type(ProviderConfigProperty.STRING_TYPE) //
                .defaultValue(MaxAuthAgePasswordPolicyProviderFactory.DEFAULT_MAX_AUTH_AGE) //
                .add() //
                .build();

        CONFIG_PROPERTIES = properties;
    }

    private final KeycloakSession session;

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    /**
     * @deprecated use {@link #UpdatePassword(KeycloakSession)} instead
     */
    @Deprecated
    public UpdatePassword() {
        this(null);
    }

    public UpdatePassword(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        if (!AuthenticatorUtil.isPasswordValidated(context.getAuthenticationSession())) {
            return;
        }
        int daysToExpirePassword = context.getRealm().getPasswordPolicy().getDaysToExpirePassword();
        if (daysToExpirePassword != -1) {
            PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider) context.getSession().getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
            CredentialModel password = passwordProvider.getPassword(context.getRealm(), context.getUser());
            if (password != null) {
                if (password.getCreatedDate() == null) {
                    context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                    logger.debug("User is required to update password");
                } else {
                    long timeElapsed = Time.toMillis(Time.currentTime()) - password.getCreatedDate();
                    long timeToExpire = TimeUnit.DAYS.toMillis(daysToExpirePassword);

                    if (timeElapsed > timeToExpire) {
                        context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                        logger.debug("User is required to update password");
                    }
                }
            }
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        Response challenge = context.form()
                .setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername())
                .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        UserModel user = context.getUser();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        event.event(EventType.UPDATE_PASSWORD);
        String passwordNew = formData.getFirst("password-new");
        String passwordConfirm = formData.getFirst("password-confirm");

        EventBuilder errorEvent = event.clone().event(EventType.UPDATE_PASSWORD_ERROR)
                .client(authSession.getClient())
                .user(authSession.getAuthenticatedUser());

        if (Validation.isBlank(passwordNew)) {
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .addError(new FormMessage(Validation.FIELD_PASSWORD, Messages.MISSING_PASSWORD))
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_MISSING);
            return;
        } else if (!passwordNew.equals(passwordConfirm)) {
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .addError(new FormMessage(Validation.FIELD_PASSWORD_CONFIRM, Messages.NOTMATCH_PASSWORD))
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_CONFIRM_ERROR);
            return;
        }

        if ("on".equals(formData.getFirst("logout-sessions"))) {
            AuthenticatorUtil.logoutOtherSessions(context);
        }

        try {
            user.credentialManager().updateCredential(UserCredentialModel.password(passwordNew, false));
            context.success();
        } catch (ModelException me) {
            errorEvent.detail(Details.REASON, me.getMessage()).error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .setError(me.getMessage(), me.getParameters())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            return;
        } catch (Exception ape) {
            errorEvent.detail(Details.REASON, ape.getMessage()).error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .setError(ape.getMessage())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            return;
        }
    }

    @Override
    public void close() {

    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new UpdatePassword(session);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getDisplayText() {
        return "Update Password";
    }


    @Override
    public String getId() {
        return UserModel.RequiredAction.UPDATE_PASSWORD.name();
    }

    @Override
    public boolean isOneTimeAction() {
        return true;
    }

    @Override
    public int getMaxAuthAge() {

        if (session == null) {
            // session is null, support for legacy implementation, fallback to default maxAuthAge
            return MaxAuthAgePasswordPolicyProviderFactory.DEFAULT_MAX_AUTH_AGE;
        }

        // try password policy
        KeycloakContext keycloakContext = session.getContext();
        RealmModel realm = keycloakContext.getRealm();
        int maxAge = realm.getPasswordPolicy().getMaxAuthAge();
        if (maxAge >= 0) {
            return maxAge;
        }

        // try required action config
        AuthenticationSessionModel authSession = keycloakContext.getAuthenticationSession();
        if (authSession != null) {

            // we need to figure out the alias for the current required action
            String providerId = authSession.getClientNote(Constants.KC_ACTION);
            RequiredActionProviderModel requiredAction = RequiredActionHelper.getRequiredActionByProviderId(realm, providerId);

            if (requiredAction != null) {
                RequiredActionConfigModel configModel = realm.getRequiredActionConfigByAlias(requiredAction.getAlias());
                if (configModel != null && configModel.containsConfigKey(MAX_AUTH_AGE_KEY)) {
                    maxAge = parseMaxAuthAge(configModel);
                    if (maxAge >= 0) {
                        return maxAge;
                    }
                }
            }
        }

        // fallback to default
        return MaxAuthAgePasswordPolicyProviderFactory.DEFAULT_MAX_AUTH_AGE;
    }


    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return List.copyOf(CONFIG_PROPERTIES);
    }

    @Override
    public void validateConfig(KeycloakSession session, RealmModel realm, RequiredActionConfigModel model) {

        int parsedMaxAuthAge;
        try {
            parsedMaxAuthAge = parseMaxAuthAge(model);
        } catch (Exception ex) {
            throw new ValidationException(new ValidationError(getId(), MAX_AUTH_AGE_KEY, "error-invalid-value"));
        }

        if (parsedMaxAuthAge < 0) {
            throw new ValidationException(new ValidationError(getId(), MAX_AUTH_AGE_KEY, "error-number-out-of-range-too-small", 0));
        }
    }

    private int parseMaxAuthAge(RequiredActionConfigModel model) throws NumberFormatException {
        return Integer.parseInt(model.getConfigValue(MAX_AUTH_AGE_KEY));
    }
}
