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

package org.keycloak.services.managers;

import org.jboss.logging.Logger;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.ServerCookie.SameSiteAttributeValue;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.RestartLoginCookie;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.sessions.StickySessionEncoderProvider;

import javax.ws.rs.core.UriInfo;
import java.util.AbstractMap.SimpleEntry;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 该对象可以进行一些认证会话相关的操作
 */
public class AuthenticationSessionManager {

    public static final String AUTH_SESSION_ID = "AUTH_SESSION_ID";

    public static final int AUTH_SESSION_LIMIT = 3;

    private static final Logger log = Logger.getLogger(AuthenticationSessionManager.class);

    private final KeycloakSession session;

    public AuthenticationSessionManager(KeycloakSession session) {
        this.session = session;
    }


    /**
     * Creates a fresh authentication session for the given realm . Optionally sets the browser
     * authentication session cookie {@link #AUTH_SESSION_ID} with the ID of the new session.
     * @param realm
     * @param browserCookie Set the cookie in the browser for the
     * @return
     */
    public RootAuthenticationSessionModel createAuthenticationSession(RealmModel realm, boolean browserCookie) {

        // 生成一个新的root认证会话  与user是一一对应的
        RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions().createRootAuthenticationSession(realm);

        // 需要设置浏览器cookie   对应的值是加密后的root会话id
        if (browserCookie) {
            setAuthSessionCookie(rootAuthSession.getId(), realm);
        }

        return rootAuthSession;
    }


    /**
     * 根据realm 查询当前root会话
     * @param realm
     * @return
     */
    public RootAuthenticationSessionModel getCurrentRootAuthenticationSession(RealmModel realm) {

        // 至多会返回3个认证会话id
        List<String> authSessionCookies = getAuthSessionCookies(realm);

        // 解析后去缓存服务器 反查会话信息
        return authSessionCookies.stream().map(oldEncodedId -> {
            AuthSessionId authSessionId = decodeAuthSessionId(oldEncodedId);
            String sessionId = authSessionId.getDecodedId();

            RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions().getRootAuthenticationSession(realm, sessionId);

            if (rootAuthSession != null) {
                // 当发现sessionid 变化后 重新设置到cookie中
                reencodeAuthSessionCookie(oldEncodedId, authSessionId, realm);
                return rootAuthSession;
            }

            // 找不到会话了 无法返回
            return null;
            // 只返回第一个
        }).filter(authSession -> Objects.nonNull(authSession)).findFirst().orElse(null);
    }


    /**
     * 解析cookie的sessionId 并查询会话  注意这里查询的是用户会话   用户会话是关联client会话的
     * @param realm
     * @return
     */
    public UserSessionModel getUserSessionFromAuthCookie(RealmModel realm) {
        List<String> authSessionCookies = getAuthSessionCookies(realm);

        return authSessionCookies.stream().map(oldEncodedId -> {
            AuthSessionId authSessionId = decodeAuthSessionId(oldEncodedId);
            String sessionId = authSessionId.getDecodedId();

            UserSessionModel userSession = session.sessions().getUserSession(realm, sessionId);

            if (userSession != null) {
                reencodeAuthSessionCookie(oldEncodedId, authSessionId, realm);
                return userSession;
            }

            return null;
        }).filter(authSession -> Objects.nonNull(authSession)).findFirst().orElse(null);
    }


    /**
     * Returns current authentication session if it exists, otherwise returns {@code null}.
     * @param realm
     * @return
     */
    public AuthenticationSessionModel getCurrentAuthenticationSession(RealmModel realm, ClientModel client, String tabId) {
        List<String> authSessionCookies = getAuthSessionCookies(realm);

        return authSessionCookies.stream().map(oldEncodedId -> {
            AuthSessionId authSessionId = decodeAuthSessionId(oldEncodedId);
            String sessionId = authSessionId.getDecodedId();

            // 上面的方法中返回的是root认证会话    当增加了client tabid 条件后    就可以检索到某个认证会话 对应的维度为 user->client
            AuthenticationSessionModel authSession = getAuthenticationSessionByIdAndClient(realm, sessionId, client, tabId);

            if (authSession != null) {
                reencodeAuthSessionCookie(oldEncodedId, authSessionId, realm);
                return authSession;
            }

            return null;
        }).filter(authSession -> Objects.nonNull(authSession)).findFirst().orElse(null);
    }


    /**
     * 生成认证会话时  需要设置cookie的值
     * @param authSessionId decoded authSessionId (without route info attached)
     * @param realm
     */
    public void setAuthSessionCookie(String authSessionId, RealmModel realm) {
        // 生成cookie相关的路径
        UriInfo uriInfo = session.getContext().getUri();

        // 得到应当关联cookie的uri
        String cookiePath = AuthenticationManager.getRealmCookiePath(realm, uriInfo);

        // TODO 先忽略ssl
        boolean sslRequired = realm.getSslRequired().isRequired(session.getContext().getConnection());

        // 如果会话应当有粘性 在sessionId上关联一个节点名
        StickySessionEncoderProvider encoder = session.getProvider(StickySessionEncoderProvider.class);
        String encodedAuthSessionId = encoder.encodeSessionId(authSessionId);

        // 在该path上设置一个cookie值
        CookieHelper.addCookie(AUTH_SESSION_ID, encodedAuthSessionId, cookiePath, null, null, -1, sslRequired, true, SameSiteAttributeValue.NONE);

        log.debugf("Set AUTH_SESSION_ID cookie with value %s", encodedAuthSessionId);
    }


    /**
     * 解密后重新加密 主要是针对粘性会话 后面的route信息可能会变化
     * @param encodedAuthSessionId encoded ID with attached route in cluster environment (EG. "5e161e00-d426-4ea6-98e9-52eb9844e2d7.node1" )
     * @return object with decoded and actually encoded authSessionId
     */
    AuthSessionId decodeAuthSessionId(String encodedAuthSessionId) {
        log.debugf("Found AUTH_SESSION_ID cookie with value %s", encodedAuthSessionId);
        StickySessionEncoderProvider encoder = session.getProvider(StickySessionEncoderProvider.class);
        String decodedAuthSessionId = encoder.decodeSessionId(encodedAuthSessionId);
        String reencoded = encoder.encodeSessionId(decodedAuthSessionId);

        return new AuthSessionId(decodedAuthSessionId, reencoded);
    }


    /**
     * 重新编码发生变化 就要更新cookie中的值
     * @param oldEncodedAuthSessionId
     * @param newAuthSessionId
     * @param realm
     */
    void reencodeAuthSessionCookie(String oldEncodedAuthSessionId, AuthSessionId newAuthSessionId, RealmModel realm) {
        if (!oldEncodedAuthSessionId.equals(newAuthSessionId.getEncodedId())) {
            log.debugf("Route changed. Will update authentication session cookie. Old: '%s', New: '%s'", oldEncodedAuthSessionId,
                    newAuthSessionId.getEncodedId());
            setAuthSessionCookie(newAuthSessionId.getDecodedId(), realm);
        }
    }


    /**
     * 根据realm 查询cookie
     * @param realm
     * @return list of the values of AUTH_SESSION_ID cookies. It is assumed that values could be encoded with route added (EG. "5e161e00-d426-4ea6-98e9-52eb9844e2d7.node1" )
     */
    List<String> getAuthSessionCookies(RealmModel realm) {
        // 获取请求头Cookie中 key为AUTH_SESSION_ID  的value
        Set<String> cookiesVal = CookieHelper.getCookieValue(AUTH_SESSION_ID);

        // 发现有多个会话id
        if (cookiesVal.size() > 1) {
            AuthenticationManager.expireOldAuthSessionCookie(realm, session.getContext().getUri(), session.getContext().getConnection());
        }

        // 最多返回3个认证会话
        List<String> authSessionIds = cookiesVal.stream().limit(AUTH_SESSION_LIMIT).collect(Collectors.toList());

        if (authSessionIds.isEmpty()) {
            log.debugf("Not found AUTH_SESSION_ID cookie");
        }

        return authSessionIds;
    }


    /**
     * 移除某个认证会话所属的 root认证会话
     * @param realm
     * @param authSession
     * @param expireRestartCookie
     */
    public void removeAuthenticationSession(RealmModel realm, AuthenticationSessionModel authSession, boolean expireRestartCookie) {
        RootAuthenticationSessionModel rootAuthSession = authSession.getParentSession();

        log.debugf("Removing authSession '%s'. Expire restart cookie: %b", rootAuthSession.getId(), expireRestartCookie);
        session.authenticationSessions().removeRootAuthenticationSession(realm, rootAuthSession);

        // expire restart cookie
        if (expireRestartCookie) {
            ClientConnection clientConnection = session.getContext().getConnection();
            UriInfo uriInfo = session.getContext().getUri();
            // 添加一个 KC_RESTART cookie
            RestartLoginCookie.expireRestartCookie(realm, clientConnection, uriInfo);
        }
    }


    // Check to see if we already have authenticationSession with same ID
    public UserSessionModel getUserSession(AuthenticationSessionModel authSession) {
        return session.sessions().getUserSession(authSession.getRealm(), authSession.getParentSession().getId());
    }


    // Don't look at cookie. Just lookup authentication session based on the ID and client. Return null if not found
    // 根据cleint 和tabid 查询会话
    public AuthenticationSessionModel getAuthenticationSessionByIdAndClient(RealmModel realm, String authSessionId, ClientModel client, String tabId) {
        RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions().getRootAuthenticationSession(realm, authSessionId);
        return rootAuthSession==null ? null : rootAuthSession.getAuthenticationSession(client, tabId);
    }
}
