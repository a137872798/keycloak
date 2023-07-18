package org.keycloak.authentication.authenticators.conditional;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.jboss.logging.Logger;

public class ConditionalRoleAuthenticator implements ConditionalAuthenticator {

    public static final ConditionalRoleAuthenticator SINGLETON = new ConditionalRoleAuthenticator();

    private static final Logger logger = Logger.getLogger(ConditionalRoleAuthenticator.class);

    /**
     * 判断是否满足条件
     * @param context
     * @return
     */
    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();

        // 必须要用户和认证配置都有效
        if (user != null && authConfig!=null && authConfig.getConfig()!=null) {
            // 查看配置才知道 要求用户必须具备的角色是什么
            String requiredRole = authConfig.getConfig().get(ConditionalRoleAuthenticatorFactory.CONDITIONAL_USER_ROLE);
            RoleModel role = KeycloakModelUtils.getRoleFromString(realm, requiredRole);
            if (role == null) {
                logger.errorv("Invalid role name submitted: {0}", requiredRole);
                return false;
            }
            // 检测用户是否有该角色
            return user.hasRole(role);
        }
        return false;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not used
    }

    @Override
    public void close() {
        // Does nothing
    }
}
