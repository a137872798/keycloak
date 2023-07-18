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

package org.keycloak.authentication.authenticators.browser;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 通过检测cookie判断用户是否已认证
 */
public class CookieAuthenticator implements Authenticator {

    @Override
    public boolean requiresUser() {
        return false;
    }

    /**
     * 触发认证动作
     * @param context
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {

        // 当登录成功后才会在cookie中设置 KEYCLOAK_IDENTITY
        AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(context.getSession(),
                context.getRealm(), true);
        // 无法获取到cookie信息 attempted 代表尝试过使用该认证器，但是无法处理 这种情况不算失败
        if (authResult == null) {
            context.attempted();
        } else {
            // 代表cookie上有用户信息
            AuthenticationSessionModel clientSession = context.getAuthenticationSession();
            LoginProtocol protocol = context.getSession().getProvider(LoginProtocol.class, clientSession.getProtocol());

            // Cookie re-authentication is skipped if re-authentication is required
            // 判断是否需要重新认证  比如会话已过期
            if (protocol.requireReauthentication(authResult.getSession(), clientSession)) {
                // 标记成已尝试 但是不认为失败
                context.attempted();
            } else {
                context.getSession().setAttribute(AuthenticationManager.SSO_AUTH, "true");

                // 该用户信息未过期 认证成功
                context.setUser(authResult.getUser());
                context.attachUserSession(authResult.getSession());
                context.success();
            }
        }

    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {

    }
}
