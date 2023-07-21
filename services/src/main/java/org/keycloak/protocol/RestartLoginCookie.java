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

package org.keycloak.protocol;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.jboss.logging.Logger;
import org.keycloak.Token;
import org.keycloak.TokenCategory;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.UriInfo;
import java.util.HashMap;
import java.util.Map;

/**
 * This is an an encoded token that is stored as a cookie so that if there is a client timeout, then the authentication session
 * can be restarted.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 代表一个重新登录的token
 */
public class RestartLoginCookie implements Token {
    private static final Logger logger = Logger.getLogger(RestartLoginCookie.class);
    public static final String KC_RESTART = "KC_RESTART";

    @JsonProperty("cid")
    protected String clientId;

    @JsonProperty("pty")
    protected String authMethod;

    @JsonProperty("ruri")
    protected String redirectUri;

    @JsonProperty("act")
    protected String action;

    @JsonProperty("notes")
    protected Map<String, String> notes = new HashMap<>();

    @Deprecated // Backwards compatibility
    @JsonProperty("cs")
    protected String cs;

    public Map<String, String> getNotes() {
        return notes;
    }

    public void setNotes(Map<String, String> notes) {
        this.notes = notes;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public RestartLoginCookie() {
    }

    public RestartLoginCookie(AuthenticationSessionModel authSession) {
        this.action = authSession.getAction();
        this.clientId = authSession.getClient().getClientId();
        this.authMethod = authSession.getProtocol();
        this.redirectUri = authSession.getRedirectUri();
        for (Map.Entry<String, String> entry : authSession.getClientNotes().entrySet()) {
            notes.put(entry.getKey(), entry.getValue());
        }
    }

    /**
     * 添加一个需要重新登录的cookie
     * @param session
     * @param realm
     * @param connection
     * @param uriInfo
     * @param authSession
     */
    public static void setRestartCookie(KeycloakSession session, RealmModel realm, ClientConnection connection, UriInfo uriInfo, AuthenticationSessionModel authSession) {
        // 会话信息转移到cookie中
        RestartLoginCookie restart = new RestartLoginCookie(authSession);
        // 对token进行编码
        String encoded = session.tokens().encode(restart);
        String path = AuthenticationManager.getRealmCookiePath(realm, uriInfo);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);
        // 添加cookie
        CookieHelper.addCookie(KC_RESTART, encoded, path, null, null, -1, secureOnly, true);
    }

    /**
     * 清除KC_RESTART
     * @param realm
     * @param connection
     * @param uriInfo
     */
    public static void expireRestartCookie(RealmModel realm, ClientConnection connection, UriInfo uriInfo) {
        // uri 拼接 realm 生成一个path
        String path = AuthenticationManager.getRealmCookiePath(realm, uriInfo);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);
        // 在该路径下设置一个cookie值
        CookieHelper.addCookie(KC_RESTART, "", path, null, null, 0, secureOnly, true);
    }


    /**
     * 重启认证会话
     * @param session
     * @param realm
     * @param rootSession       相关的root会话
     * @param expectedClientId  期望产生的会话是跟哪个client关联的
     * @return
     * @throws Exception
     */
    public static AuthenticationSessionModel restartSession(KeycloakSession session, RealmModel realm,
                                                            RootAuthenticationSessionModel rootSession, String expectedClientId) throws Exception {

        // 如果存在Restart代表 有个执行到一半的认证
        Cookie cook = session.getContext().getRequestHeaders().getCookies().get(KC_RESTART);
        if (cook ==  null) {
            logger.debug("KC_RESTART cookie doesn't exist");
            return null;
        }
        String encodedCookie = cook.getValue();

        RestartLoginCookie cookie = session.tokens().decode(encodedCookie, RestartLoginCookie.class);
        if (cookie == null) {
            logger.debug("Failed to verify encoded RestartLoginCookie");
            return null;
        }

        // client已经无效
        ClientModel client = realm.getClientByClientId(cookie.getClientId());
        if (client == null) return null;

        // Restart just if client from cookie matches client from the URL.
        // 之前的认证client 与本次不匹配
        if (!client.getClientId().equals(expectedClientId)) {
            logger.debugf("Skip restarting from the KC_RESTART. Clients doesn't match: Cookie client: %s, Requested client: %s", client.getClientId(), expectedClientId);
            return null;
        }

        // Need to create brand new session and setup cookie
        // 生成一个新的root会话
        if (rootSession == null) {
            rootSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, true);
        }

        // 基于该client产生认证会话 设置之前的认证方式和重定向地址等
        AuthenticationSessionModel authSession = rootSession.createAuthenticationSession(client);
        authSession.setProtocol(cookie.getAuthMethod());
        authSession.setRedirectUri(cookie.getRedirectUri());
        authSession.setAction(cookie.getAction());
        for (Map.Entry<String, String> entry : cookie.getNotes().entrySet()) {
            authSession.setClientNote(entry.getKey(), entry.getValue());
        }

        return authSession;
    }

    @Override
    public TokenCategory getCategory() {
        return TokenCategory.INTERNAL;
    }
}
