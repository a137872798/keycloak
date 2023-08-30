package org.keycloak.authentication.authenticators.browser;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * author: xuelei.guo
 * date: 2023/7/24 21:59
 */
public class CustomerUsernamePasswordFormFactory implements AuthenticatorFactory {

    private static final Logger logger = Logger.getLogger(CustomerUsernamePasswordFormFactory.class);
    public static final String PROVIDER_ID = "customer-auth-username-password-form";
    public static final CustomerUsernamePasswordForm SINGLETON = new CustomerUsernamePasswordForm();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }


    @Override
    public void init(Config.Scope config) {
        String loginHtmlName = config.get("LOGIN_HTML_NAME");
        logger.debug("登录页面名称为:" + loginHtmlName);
        SINGLETON.setLoginHtmlName(loginHtmlName);
    }


    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    // 当在flow中添加了表单认证   该认证器只支持required
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Username Password Form";
    }

    @Override
    public String getHelpText() {
        return "Validates a username and password from login form.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

}
