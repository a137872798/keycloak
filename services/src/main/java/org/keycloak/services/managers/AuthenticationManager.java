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
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.TokenVerifier.Predicate;
import org.keycloak.TokenVerifier.TokenTypeCheck;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.ConsoleDisplayMode;
import org.keycloak.authentication.DisplayTypeRequiredActionFactory;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionContextResult;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.actiontoken.DefaultActionTokenKey;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ActionTokenKeyModel;
import org.keycloak.models.ActionTokenStoreProvider;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.UserConsentModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.SessionTimeoutHelper;
import org.keycloak.models.utils.SystemClientUtil;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocol.Error;
import org.keycloak.protocol.oidc.BackchannelLogoutResponse;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.services.util.CookieHelper;
import org.keycloak.services.util.P3PHelper;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.TokenUtil;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.common.util.ServerCookie.SameSiteAttributeValue;
import static org.keycloak.services.util.CookieHelper.getCookie;

/**
 * Stateless object that manages authentication
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 处理认证相关的逻辑  并且是无状态对象   该对象被AuthenticationProcessor使用
 */
public class AuthenticationManager {
    public static final String SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS= "SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS";
    public static final String END_AFTER_REQUIRED_ACTIONS = "END_AFTER_REQUIRED_ACTIONS";
    public static final String INVALIDATE_ACTION_TOKEN = "INVALIDATE_ACTION_TOKEN";

    /**
     * Auth session note, which indicates if user session will be persistent (Saved to real persistent store) or
     * transient (transient session will be scoped to single request and hence there is no need to save it in the underlying store)
     */
    public static final String USER_SESSION_PERSISTENT_STATE = "USER_SESSION_PERSISTENT_STATE";

    /**
     * Auth session note on client logout state (when logging out)
     */
    public static final String CLIENT_LOGOUT_STATE = "logout.state.";

    // userSession note with authTime (time when authentication flow including requiredActions was finished)
    public static final String AUTH_TIME = "AUTH_TIME";
    // clientSession note with flag that clientSession was authenticated through SSO cookie
    public static final String SSO_AUTH = "SSO_AUTH";

    protected static final Logger logger = Logger.getLogger(AuthenticationManager.class);

    public static final String FORM_USERNAME = "username";
    // used for auth login
    public static final String KEYCLOAK_IDENTITY_COOKIE = "KEYCLOAK_IDENTITY";
    // used solely to determine is user is logged in
    public static final String KEYCLOAK_SESSION_COOKIE = "KEYCLOAK_SESSION";
    public static final String KEYCLOAK_REMEMBER_ME = "KEYCLOAK_REMEMBER_ME";
    public static final String KEYCLOAK_LOGOUT_PROTOCOL = "KEYCLOAK_LOGOUT_PROTOCOL";

    /**
     * 用于校验JWT类型的
     */
    private static final TokenTypeCheck VALIDATE_IDENTITY_COOKIE = new TokenTypeCheck(TokenUtil.TOKEN_TYPE_KEYCLOAK_ID);

    /**
     * 判断某个realm下的某个用户会话是否有效   主要就是看是否长时间未访问
     * @param realm  领域实体
     * @param userSession  用户会话实体
     * @return
     */
    public static boolean isSessionValid(RealmModel realm, UserSessionModel userSession) {
        // 会话为空 会话无效
        if (userSession == null) {
            logger.debug("No user session");
            return false;
        }

        // 因为会话是有存活时间的  所以需要查看当前时间
        int currentTime = Time.currentTime();

        // Additional time window is added for the case when session was updated in different DC and the update to current DC was postponed
        // 如果设置了 remember me 使用的是不同的时间
        int maxIdle = userSession.isRememberMe() && realm.getSsoSessionIdleTimeoutRememberMe() > 0 ?
            realm.getSsoSessionIdleTimeoutRememberMe() : realm.getSsoSessionIdleTimeout();
        int maxLifespan = userSession.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0 ?
                realm.getSsoSessionMaxLifespanRememberMe() : realm.getSsoSessionMaxLifespan();

        // 判断session是否还有效  代表当前时间距离上次刷新时间 在idle之内 session还有效
        boolean sessionIdleOk = maxIdle > currentTime - userSession.getLastSessionRefresh() - SessionTimeoutHelper.IDLE_TIMEOUT_WINDOW_SECONDS;
        // 当前时间-started时间 小于 lifespan
        boolean sessionMaxOk = maxLifespan > currentTime - userSession.getStarted();
        return sessionIdleOk && sessionMaxOk;
    }

    /**
     * 检测离线会话是否有效
     * @param realm
     * @param userSession
     * @return
     */
    public static boolean isOfflineSessionValid(RealmModel realm, UserSessionModel userSession) {
        if (userSession == null) {
            logger.debug("No offline user session");
            return false;
        }
        int currentTime = Time.currentTime();
        // Additional time window is added for the case when session was updated in different DC and the update to current DC was postponed
        int maxIdle = realm.getOfflineSessionIdleTimeout() + SessionTimeoutHelper.IDLE_TIMEOUT_WINDOW_SECONDS;

        // KEYCLOAK-7688 Offline Session Max for Offline Token
        // 具体判断依据也是时间相关的  不细看了
        if (realm.isOfflineSessionMaxLifespanEnabled()) {
            int max = userSession.getStarted() + realm.getOfflineSessionMaxLifespan();
            return userSession.getLastSessionRefresh() + maxIdle > currentTime && max > currentTime;
        } else {
            return userSession.getLastSessionRefresh() + maxIdle > currentTime;
        }
    }

    /**
     * 清除cookie
     * @param session
     * @param userSession
     * @param realm
     * @param uriInfo
     * @param headers
     * @param connection
     * @return
     */
    public static boolean expireUserSessionCookie(KeycloakSession session, UserSessionModel userSession, RealmModel realm, UriInfo uriInfo, HttpHeaders headers, ClientConnection connection) {
        try {
            // check to see if any identity cookie is set with the same session and expire it if necessary
            // 从请求头中获取 key为KEYCLOAK_IDENTITY的 cookie值
            Cookie cookie = CookieHelper.getCookie(headers.getCookies(), KEYCLOAK_IDENTITY_COOKIE);
            if (cookie == null) return true;

            // 也就是说通过keycloak认证后 应该会产生一个特殊的token  存储在cookie中
            String tokenString = cookie.getValue();

            // 产生校验器 对token进行认证
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class)
              .realmUrl(Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName()))
              .checkActive(false)
              .checkTokenType(false)
              .withChecks(VALIDATE_IDENTITY_COOKIE);

            // 将cookie值解析成token对象 并获取kid值
            String kid = verifier.getHeader().getKeyId();
            // 头部有描述 数据体的加密方式
            String algorithm = verifier.getHeader().getAlgorithm().name();

            SignatureVerifierContext signatureVerifier = session.getProvider(SignatureProvider.class, algorithm).verifier(kid);
            verifier.verifierContext(signatureVerifier);

            // 返回token信息
            AccessToken token = verifier.verify().getToken();
            // 从缓存服务器取到某个会话信息
            // 到这一步简单来说 就是从cookie中取到token信息 token中有sessionid  然后通过id检索session存储服务  拿到session信息
            UserSessionModel cookieSession = session.sessions().getUserSession(realm, token.getSessionState());

            // 会话已经不存在的情况下 代表过期了   id变化的情况 代表cookie所关联的用户会话已经过期了  传入的userSession更具权威性 一旦产生冲突 只认可userSession
            if (cookieSession == null || !cookieSession.getId().equals(userSession.getId())) return true;
            expireIdentityCookie(realm, uriInfo, connection);
            return true;
        } catch (Exception e) {
            return false;
        }

    }

    /**
     * 采用后端登出的方式  会回调客户端提供的接口
     * @param session
     * @param userSession   本次被登出的用户会话
     * @param logoutBroker
     */
    public static void backchannelLogout(KeycloakSession session, UserSessionModel userSession, boolean logoutBroker) {
        backchannelLogout(
                session,
                session.getContext().getRealm(),
                userSession,
                session.getContext().getUri(),
                session.getContext().getConnection(),
                session.getContext().getRequestHeaders(),
                logoutBroker
        );
    }

    /**
     * 请求client的回调接口 通知它用户会话登出
     * @param session
     * @param realm
     * @param userSession
     * @param uriInfo
     * @param connection
     * @param headers
     * @param logoutBroker
     * @return
     */
    public static BackchannelLogoutResponse backchannelLogout(KeycloakSession session, RealmModel realm,
            UserSessionModel userSession, UriInfo uriInfo,
            ClientConnection connection, HttpHeaders headers,
            boolean logoutBroker) {
        return backchannelLogout(session, realm, userSession, uriInfo, connection, headers, logoutBroker, false);
    }

    /**
     * 登出会话
     * @param session
     * @param realm
     * @param userSession
     * @param uriInfo
     * @param connection
     * @param headers
     * @param logoutBroker
     * @param offlineSession
     *
     * @return BackchannelLogoutResponse with logout information
     */
    public static BackchannelLogoutResponse backchannelLogout(KeycloakSession session, RealmModel realm,
            UserSessionModel userSession, UriInfo uriInfo,
            ClientConnection connection, HttpHeaders headers,
            boolean logoutBroker,
            boolean offlineSession) {
        BackchannelLogoutResponse backchannelLogoutResponse = new BackchannelLogoutResponse();

        // 用户会话已经不存在了 登出已经完成  不用真正通知
        if (userSession == null) {
            backchannelLogoutResponse.setLocalLogoutSucceeded(true);
            return backchannelLogoutResponse;
        }

        // 更新状态为登出中
        UserModel user = userSession.getUser();
        if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
            userSession.setState(UserSessionModel.State.LOGGING_OUT);
        }

        logger.debugv("Logging out: {0} ({1}) offline: {2}", user.getUsername(), userSession.getId(),
                userSession.isOffline());

        // 从cookie中清除session信息
        boolean expireUserSessionCookieSucceeded =
                expireUserSessionCookie(session, userSession, realm, uriInfo, headers, connection);

        // 为登出操作生成 会话对象
        final AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
        AuthenticationSessionModel logoutAuthSession =
                createOrJoinLogoutSession(session, realm, asm, userSession, false);

        boolean userSessionOnlyHasLoggedOutClients = false;
        try {
            // 进行后端登出并产生结果
            backchannelLogoutResponse = backchannelLogoutAll(session, realm, userSession, logoutAuthSession, uriInfo,
                    headers, logoutBroker);
            // 所有client都完成登出
            userSessionOnlyHasLoggedOutClients =
                    checkUserSessionOnlyHasLoggedOutClients(realm, userSession, logoutAuthSession);
        } finally {
            // 登出操作完成就可以移除会话了
            RootAuthenticationSessionModel rootAuthSession = logoutAuthSession.getParentSession();
            rootAuthSession.removeAuthenticationSessionByTabId(logoutAuthSession.getTabId());
        }

        userSession.setState(UserSessionModel.State.LOGGED_OUT);

        // TODO
        if (offlineSession) {
            new UserSessionManager(session).revokeOfflineUserSession(userSession);

            // Check if "online" session still exists and remove it too
            UserSessionModel onlineUserSession = session.sessions().getUserSession(realm, userSession.getId());
            if (onlineUserSession != null) {
                session.sessions().removeUserSession(realm, onlineUserSession);
            }
        } else {
            session.sessions().removeUserSession(realm, userSession);
        }
        backchannelLogoutResponse
                .setLocalLogoutSucceeded(expireUserSessionCookieSucceeded && userSessionOnlyHasLoggedOutClients);
        return backchannelLogoutResponse;
    }

    /**
     * 创建一个登出会话
     * @param session
     * @param realm
     * @param asm
     * @param userSession
     * @param browserCookie  是否要从cookie中查询会话
     * @return
     */
    private static AuthenticationSessionModel createOrJoinLogoutSession(KeycloakSession session, RealmModel realm, final AuthenticationSessionManager asm, UserSessionModel userSession, boolean browserCookie) {
        // Account management client is used as a placeholder
        // 得到 account client  在新建一个realm时 会自动为其创建account client
        ClientModel client = SystemClientUtil.getSystemClient(realm);

        String authSessionId;
        RootAuthenticationSessionModel rootLogoutSession = null;
        boolean browserCookiePresent = false;

        // Try to lookup current authSessionId from browser cookie. If doesn't exists, use the same as current userSession
        // 从cookie中找到关联的root认证会话
        if (browserCookie) {
            rootLogoutSession = asm.getCurrentRootAuthenticationSession(realm);
        }
        if (rootLogoutSession != null) {
            authSessionId = rootLogoutSession.getId();
            browserCookiePresent = true;
        } else {
            // 用户sessionId 与root认证id 是一样的
            authSessionId = userSession.getId();
            rootLogoutSession = session.authenticationSessions().getRootAuthenticationSession(realm, authSessionId);
        }

        // 首次创建
        if (rootLogoutSession == null) {
            rootLogoutSession = session.authenticationSessions().createRootAuthenticationSession(realm, authSessionId);
        }
        if (browserCookie && !browserCookiePresent) {
            // Update cookie if needed  将sessionId保存在cookie中
            asm.setAuthSessionCookie(authSessionId, realm);
        }

        // See if we have logoutAuthSession inside current rootSession. Create new if not
        // 检查当前是否已经有登出会话了
        Optional<AuthenticationSessionModel> found = rootLogoutSession.getAuthenticationSessions().values().stream().filter((AuthenticationSessionModel authSession) -> {
            return client.equals(authSession.getClient()) && Objects.equals(AuthenticationSessionModel.Action.LOGGING_OUT.name(), authSession.getAction());

        }).findFirst();

        // 没有的话创建一个登出会话
        AuthenticationSessionModel logoutAuthSession = found.isPresent() ? found.get() : rootLogoutSession.createAuthenticationSession(client);
        // 设置当前在执行的会话
        session.getContext().setAuthenticationSession(logoutAuthSession);

        logoutAuthSession.setAction(AuthenticationSessionModel.Action.LOGGING_OUT.name());
        return logoutAuthSession;
    }

    /**
     * 后端登出
     * @param session
     * @param realm
     * @param userSession
     * @param logoutAuthSession
     * @param uriInfo
     * @param headers
     * @param logoutBroker
     * @return
     */
    private static BackchannelLogoutResponse backchannelLogoutAll(KeycloakSession session, RealmModel realm,
            UserSessionModel userSession, AuthenticationSessionModel logoutAuthSession, UriInfo uriInfo,
            HttpHeaders headers, boolean logoutBroker) {

        // 维护每个client登出的结果
        BackchannelLogoutResponse backchannelLogoutResponse = new BackchannelLogoutResponse();

        // 遍历所有客户端会话
        for (AuthenticatedClientSessionModel clientSession : userSession.getAuthenticatedClientSessions().values()) {
            Response clientSessionLogoutResponse =
                    backchannelLogoutClientSession(session, realm, clientSession, logoutAuthSession, uriInfo, headers);

            // 回调url
            String backchannelLogoutUrl =
                    OIDCAdvancedConfigWrapper.fromClientModel(clientSession.getClient()).getBackchannelLogoutUrl();

            BackchannelLogoutResponse.DownStreamBackchannelLogoutResponse downStreamBackchannelLogoutResponse =
                    new BackchannelLogoutResponse.DownStreamBackchannelLogoutResponse();
            downStreamBackchannelLogoutResponse.setWithBackchannelLogoutUrl(backchannelLogoutUrl != null);
            
            if (clientSessionLogoutResponse != null) {
                downStreamBackchannelLogoutResponse.setResponseCode(clientSessionLogoutResponse.getStatus());
            } else {
                downStreamBackchannelLogoutResponse.setResponseCode(null);
            }
            backchannelLogoutResponse.addClientResponses(downStreamBackchannelLogoutResponse);
        }

        // 代表还需要登出broker
        if (logoutBroker) {
            String brokerId = userSession.getNote(Details.IDENTITY_PROVIDER);
            if (brokerId != null) {
                IdentityProvider identityProvider = IdentityBrokerService.getIdentityProvider(session, realm, brokerId);
                try {
                    identityProvider.backchannelLogout(session, userSession, uriInfo, realm);
                } catch (Exception e) {
                    logger.warn("Exception at broker backchannel logout for broker " + brokerId, e);
                    backchannelLogoutResponse.setLocalLogoutSucceeded(false);
                }
            }
        }

        return backchannelLogoutResponse;
    }

    /**
     * Checks that all sessions have been removed from the user session. The list of logged out clients is determined from
     * the {@code logoutAuthSession} auth session notes.
     * @param realm
     * @param userSession
     * @param logoutAuthSession
     * @return {@code true} when all clients have been logged out, {@code false} otherwise
     * 检查是否已经从用户会话下删除了所有会话
     */
    private static boolean checkUserSessionOnlyHasLoggedOutClients(RealmModel realm,
      UserSessionModel userSession, AuthenticationSessionModel logoutAuthSession) {

        // 获取该用户会话关联的所有client会话   本身在创建client会话时 就是要传入userSession的  所以可以查询
        final Map<String, AuthenticatedClientSessionModel> acs = userSession.getAuthenticatedClientSessions();

        // 代表这些client的会话还未登出
        Set<AuthenticatedClientSessionModel> notLoggedOutSessions = acs.entrySet().stream()
                //  一旦发现有client未登出
          .filter(me -> ! Objects.equals(AuthenticationSessionModel.Action.LOGGED_OUT, getClientLogoutAction(logoutAuthSession, me.getKey())))
                // 发现client此时还未执行登出动作
          .filter(me -> ! Objects.equals(AuthenticationSessionModel.Action.LOGGED_OUT.name(), me.getValue().getAction()))
                // 采用的协议 比如oidc
          .filter(me -> Objects.nonNull(me.getValue().getProtocol()))   // Keycloak service-like accounts
          .map(Map.Entry::getValue)
          .collect(Collectors.toSet());

        boolean allClientsLoggedOut = notLoggedOutSessions.isEmpty();

        if (! allClientsLoggedOut) {
            logger.warnf("Some clients have been not been logged out for user %s in %s realm: %s",
              userSession.getUser().getUsername(), realm.getName(),
              notLoggedOutSessions.stream()
                .map(AuthenticatedClientSessionModel::getClient)
                .map(ClientModel::getClientId)
                .sorted()
                .collect(Collectors.joining(", "))
            );
        } else if (logger.isDebugEnabled()) {
            logger.debugf("All clients have been logged out for user %s in %s realm, session %s",
              userSession.getUser().getUsername(), realm.getName(), userSession.getId());
        }

        return allClientsLoggedOut;
    }

    /**
     * Logs out the given client session and records the result into {@code logoutAuthSession} if set.
     * 
     * @param session
     * @param realm
     * @param clientSession
     * @param logoutAuthSession auth session used for recording result of logout. May be {@code null}
     * @param uriInfo
     * @param headers
     * @return {@code http status OK} if the client was or is already being logged out, {@code null} if it is
     *         not known how to log it out and no request is made, otherwise the response of the logout request.
     *         采用后端登出的方式
     */
    private static Response backchannelLogoutClientSession(KeycloakSession session, RealmModel realm,
            AuthenticatedClientSessionModel clientSession, AuthenticationSessionModel logoutAuthSession,
            UriInfo uriInfo, HttpHeaders headers) {
        UserSessionModel userSession = clientSession.getUserSession();
        ClientModel client = clientSession.getClient();

        if (client.isFrontchannelLogout()
                || AuthenticationSessionModel.Action.LOGGED_OUT.name().equals(clientSession.getAction())) {
            return null;
        }

        final AuthenticationSessionModel.Action logoutState = getClientLogoutAction(logoutAuthSession, client.getId());

        if (logoutState == AuthenticationSessionModel.Action.LOGGED_OUT
                || logoutState == AuthenticationSessionModel.Action.LOGGING_OUT) {
            return Response.ok().build();
        }

        if (!client.isEnabled()) {
            return null;
        }

        try {
            setClientLogoutAction(logoutAuthSession, client.getId(), AuthenticationSessionModel.Action.LOGGING_OUT);

            String authMethod = clientSession.getProtocol();
            if (authMethod == null) return Response.ok().build(); // must be a keycloak service like account

            logger.debugv("backchannel logout to: {0}", client.getClientId());
            LoginProtocol protocol = session.getProvider(LoginProtocol.class, authMethod);
            protocol.setRealm(realm)
                    .setHttpHeaders(headers)
                    .setUriInfo(uriInfo);

            // 唯一区别
            Response clientSessionLogout = protocol.backchannelLogout(userSession, clientSession);

            setClientLogoutAction(logoutAuthSession, client.getId(), AuthenticationSessionModel.Action.LOGGED_OUT);

            return clientSessionLogout;
        } catch (Exception ex) {
            ServicesLogger.LOGGER.failedToLogoutClient(ex);
            return Response.serverError().build();
        }
    }

    /**
     * 通过前端登出
     * @param session
     * @param realm
     * @param clientSession
     * @param logoutAuthSession
     * @param uriInfo
     * @param headers
     * @return
     */
    private static Response frontchannelLogoutClientSession(KeycloakSession session, RealmModel realm,
      AuthenticatedClientSessionModel clientSession, AuthenticationSessionModel logoutAuthSession,
      UriInfo uriInfo, HttpHeaders headers) {

        // 用户会话
        UserSessionModel userSession = clientSession.getUserSession();
        ClientModel client = clientSession.getClient();

        // 不支持前端登出 或者已登出 不需要处理
        if (! client.isFrontchannelLogout() || AuthenticationSessionModel.Action.LOGGED_OUT.name().equals(clientSession.getAction())) {
            return null;
        }

        final AuthenticationSessionModel.Action logoutState = getClientLogoutAction(logoutAuthSession, client.getId());

        if (logoutState == AuthenticationSessionModel.Action.LOGGED_OUT || logoutState == AuthenticationSessionModel.Action.LOGGING_OUT) {
            return null;
        }

        try {
            setClientLogoutAction(logoutAuthSession, client.getId(), AuthenticationSessionModel.Action.LOGGING_OUT);

            String authMethod = clientSession.getProtocol();
            if (authMethod == null) return null; // must be a keycloak service like account

            logger.debugv("frontchannel logout to: {0}", client.getClientId());
            LoginProtocol protocol = session.getProvider(LoginProtocol.class, authMethod);
            protocol.setRealm(realm)
                    .setHttpHeaders(headers)
                    .setUriInfo(uriInfo);

            // 调用协议api
            Response response = protocol.frontchannelLogout(userSession, clientSession);
            if (response != null) {
                logger.debug("returning frontchannel logout request to client");
                // setting this to logged out cuz I'm not sure protocols can always verify that the client was logged out or not

                setClientLogoutAction(logoutAuthSession, client.getId(), AuthenticationSessionModel.Action.LOGGED_OUT);

                return response;
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.failedToLogoutClient(e);
        }

        return null;
    }

    /**
     * Sets logout state of the particular client into the {@code logoutAuthSession}
     * @param logoutAuthSession logoutAuthSession. May be {@code null} in which case this is a no-op.
     * @param clientUuid Client. Must not be {@code null}
     * @param action
     * 设置某个client此时的登出状态
     */
    public static void setClientLogoutAction(AuthenticationSessionModel logoutAuthSession, String clientUuid, AuthenticationSessionModel.Action action) {
        if (logoutAuthSession != null && clientUuid != null) {
            logoutAuthSession.setAuthNote(CLIENT_LOGOUT_STATE + clientUuid, action.name());
        }
    }

    /**
     * Returns the logout state of the particular client as per the {@code logoutAuthSession}
     * @param logoutAuthSession logoutAuthSession. May be {@code null} in which case this is a no-op.
     * @param clientUuid Internal ID of the client. Must not be {@code null}
     * @return State if it can be determined, {@code null} otherwise.
     * 获取某个client此时的登出状态  比如正在登出 或者已登出
     */
    public static AuthenticationSessionModel.Action getClientLogoutAction(AuthenticationSessionModel logoutAuthSession, String clientUuid) {
        if (logoutAuthSession == null || clientUuid == null) {
            return null;
        }

        String state = logoutAuthSession.getAuthNote(CLIENT_LOGOUT_STATE + clientUuid);
        return state == null ? null : AuthenticationSessionModel.Action.valueOf(state);
    }

    /**
     * Logout all clientSessions of this user and client
     *
     * 用户在某个client采用的是后端登录
     * @param session
     * @param realm
     * @param user
     * @param client
     * @param uriInfo
     * @param headers
     */
    public static void backchannelLogoutUserFromClient(KeycloakSession session, RealmModel realm, UserModel user, ClientModel client, UriInfo uriInfo, HttpHeaders headers) {
        session.sessions().getUserSessionsStream(realm, user)
                .map(userSession -> userSession.getAuthenticatedClientSessionByClient(client.getId()))
                .filter(Objects::nonNull)
                .collect(Collectors.toList()) // collect to avoid concurrent modification.
                .forEach(clientSession -> {
                    backchannelLogoutClientSession(session, realm, clientSession, null, uriInfo, headers);
                    clientSession.setAction(AuthenticationSessionModel.Action.LOGGED_OUT.name());
                    TokenManager.dettachClientSession(clientSession);
                });
    }

    /**
     * 发出一个登出操作
     * @param session
     * @param realm
     * @param userSession
     * @param uriInfo
     * @param connection
     * @param headers
     * @param initiatingIdp
     * @return
     */
    public static Response browserLogout(KeycloakSession session,
                                         RealmModel realm,
                                         UserSessionModel userSession,
                                         UriInfo uriInfo,
                                         ClientConnection connection,
                                         HttpHeaders headers,
                                         String initiatingIdp) {
        if (userSession == null) return null;

        if (logger.isDebugEnabled()) {
            UserModel user = userSession.getUser();
            logger.debugv("Logging out: {0} ({1})", user.getUsername(), userSession.getId());
        }

        // 开始执行登出逻辑 状态变更为 loggingout
        if (userSession.getState() != UserSessionModel.State.LOGGING_OUT) {
            userSession.setState(UserSessionModel.State.LOGGING_OUT);
        }

        final AuthenticationSessionManager asm = new AuthenticationSessionManager(session);
        // 创建一个登出用会话 以及为context设置登出会话
        AuthenticationSessionModel logoutAuthSession = createOrJoinLogoutSession(session, realm, asm, userSession, true);

        // 触发登出操作
        Response response = browserLogoutAllClients(userSession, session, realm, headers, uriInfo, logoutAuthSession);
        // 提前产生结果 登出操作未全部完成 返回response
        if (response != null) {
            return response;
        }

        // 登出操作全部完成
        String brokerId = userSession.getNote(Details.IDENTITY_PROVIDER);
        // TODO
        if (brokerId != null && !brokerId.equals(initiatingIdp)) {
            IdentityProvider identityProvider = IdentityBrokerService.getIdentityProvider(session, realm, brokerId);
            response = identityProvider.keycloakInitiatedBrowserLogout(session, userSession, uriInfo, realm);
            if (response != null) {
                return response;
            }
        }

        // 做收尾工作 比如清理会话
        return finishBrowserLogout(session, realm, userSession, uriInfo, connection, headers);
    }

    /**
     * 找到所有未登出的会话 根据前端登出/后端登出的方式处理
     * @param userSession
     * @param session
     * @param realm
     * @param headers
     * @param uriInfo
     * @param logoutAuthSession
     * @return
     */
    private static Response browserLogoutAllClients(UserSessionModel userSession, KeycloakSession session, RealmModel realm, HttpHeaders headers, UriInfo uriInfo, AuthenticationSessionModel logoutAuthSession) {
        // 未登出的所有client
        Map<Boolean, List<AuthenticatedClientSessionModel>> acss = userSession.getAuthenticatedClientSessions().values().stream()
          .filter(clientSession -> ! Objects.equals(AuthenticationSessionModel.Action.LOGGED_OUT.name(), clientSession.getAction()))
          .filter(clientSession -> clientSession.getProtocol() != null)
          .collect(Collectors.partitioningBy(clientSession -> clientSession.getClient().isFrontchannelLogout()));

        // 得到所有采用后端登出方式的client
        final List<AuthenticatedClientSessionModel> backendLogoutSessions = acss.get(false) == null ? Collections.emptyList() : acss.get(false);
        backendLogoutSessions.forEach(acs -> backchannelLogoutClientSession(session, realm, acs, logoutAuthSession, uriInfo, headers));

        // 前端登出要使用重定向
        final List<AuthenticatedClientSessionModel> redirectClients = acss.get(true) == null ? Collections.emptyList() : acss.get(true);
        for (AuthenticatedClientSessionModel nextRedirectClient : redirectClients) {
            // 一旦产生结果直接返回
            Response response = frontchannelLogoutClientSession(session, realm, nextRedirectClient, logoutAuthSession, uriInfo, headers);
            if (response != null) {
                return response;
            }
        }

        return null;
    }

    /**
     * 登出操作完成后触发
     * @param session
     * @param realm
     * @param userSession
     * @param uriInfo
     * @param connection
     * @param headers
     * @return
     */
    public static Response finishBrowserLogout(KeycloakSession session, RealmModel realm, UserSessionModel userSession, UriInfo uriInfo, ClientConnection connection, HttpHeaders headers) {
        final AuthenticationSessionManager asm = new AuthenticationSessionManager(session);

        // 产生一个登出用的会话
        AuthenticationSessionModel logoutAuthSession = createOrJoinLogoutSession(session, realm, asm, userSession, true);

        // 检查该用户是否在所有client都完成登出  仅打印日志
        checkUserSessionOnlyHasLoggedOutClients(realm, userSession, logoutAuthSession);

        // 既然要触发登出了 就要把cookie的值清理掉
        expireIdentityCookie(realm, uriInfo, connection);
        expireRememberMeCookie(realm, uriInfo, connection);

        // 一旦cookie中的token 被清理后 就认为登出完成
        userSession.setState(UserSessionModel.State.LOGGED_OUT);
        String method = userSession.getNote(KEYCLOAK_LOGOUT_PROTOCOL);
        EventBuilder event = new EventBuilder(realm, session, connection);
        LoginProtocol protocol = session.getProvider(LoginProtocol.class, method);
        protocol.setRealm(realm)
                .setHttpHeaders(headers)
                .setUriInfo(uriInfo)
                .setEventBuilder(event);
        // 触发协议后续逻辑
        Response response = protocol.finishLogout(userSession);

        // 一个user session的remove 会关联到所有client session的移除
        session.sessions().removeUserSession(realm, userSession);
        // 移除root会话
        session.authenticationSessions().removeRootAuthenticationSession(realm, logoutAuthSession.getParentSession());
        return response;
    }


    /**
     * 将会话加工成一个token
     * @param keycloakSession
     * @param realm
     * @param user
     * @param session
     * @param issuer
     * @return
     */
    public static IdentityCookieToken createIdentityToken(KeycloakSession keycloakSession, RealmModel realm, UserModel user, UserSessionModel session, String issuer) {
        IdentityCookieToken token = new IdentityCookieToken();
        token.id(KeycloakModelUtils.generateId());
        token.issuedNow();
        token.subject(user.getId());
        token.issuer(issuer);
        token.type(TokenUtil.TOKEN_TYPE_KEYCLOAK_ID);

        // token 关联会话id
        if (session != null) {
            token.setSessionState(session.getId());
        }

        // 设置token过期时间
        if (session != null && session.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0) {
            token.expiration(Time.currentTime() + realm.getSsoSessionMaxLifespanRememberMe());
        } else if (realm.getSsoSessionMaxLifespan() > 0) {
            token.expiration(Time.currentTime() + realm.getSsoSessionMaxLifespan());
        }

        String stateChecker = (String) keycloakSession.getAttribute("state_checker");
        if (stateChecker == null) {
            stateChecker = Base64Url.encode(KeycloakModelUtils.generateSecret());
            keycloakSession.setAttribute("state_checker", stateChecker);
        }
        token.getOtherClaims().put("state_checker", stateChecker);

        return token;
    }

    /**
     * 为登录用户生成一个cookie
     * @param keycloakSession
     * @param realm
     * @param user
     * @param session
     * @param uriInfo
     * @param connection
     */
    public static void createLoginCookie(KeycloakSession keycloakSession, RealmModel realm, UserModel user, UserSessionModel session, UriInfo uriInfo, ClientConnection connection) {
        // 生成存储cookie的路径
        String cookiePath = getIdentityCookiePath(realm, uriInfo);
        String issuer = Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName());

        // 将session加工成一个token
        IdentityCookieToken identityCookieToken = createIdentityToken(keycloakSession, realm, user, session, issuer);
        String encoded = keycloakSession.tokens().encode(identityCookieToken);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);

        // 总计要将2个东西加入到cookie中

        // cookie 存活时间
        int maxAge = NewCookie.DEFAULT_MAX_AGE;
        if (session != null && session.isRememberMe()) {
            maxAge = realm.getSsoSessionMaxLifespanRememberMe() > 0 ? realm.getSsoSessionMaxLifespanRememberMe() : realm.getSsoSessionMaxLifespan();
        }
        logger.debugv("Create login cookie - name: {0}, path: {1}, max-age: {2}", KEYCLOAK_IDENTITY_COOKIE, cookiePath, maxAge);
        CookieHelper.addCookie(KEYCLOAK_IDENTITY_COOKIE, encoded, cookiePath, null, null, maxAge, secureOnly, true, SameSiteAttributeValue.NONE);
        //builder.cookie(new NewCookie(cookieName, encoded, cookiePath, null, null, maxAge, secureOnly));// todo httponly , true);

        String sessionCookieValue = realm.getName() + "/" + user.getId();
        if (session != null) {
            sessionCookieValue += "/" + session.getId();
        }
        // THIS SHOULD NOT BE A HTTPONLY COOKIE!  It is used for OpenID Connect Iframe Session support!
        // Max age should be set to the max lifespan of the session as it's used to invalidate old-sessions on re-login
        int sessionCookieMaxAge = session.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0 ? realm.getSsoSessionMaxLifespanRememberMe() : realm.getSsoSessionMaxLifespan();
        CookieHelper.addCookie(KEYCLOAK_SESSION_COOKIE, sessionCookieValue, cookiePath, null, null, sessionCookieMaxAge, secureOnly, false, SameSiteAttributeValue.NONE);
        P3PHelper.addP3PHeader();
    }

    /**
     * 创建 remember的cookie
     * @param realm
     * @param username
     * @param uriInfo
     * @param connection
     */
    public static void createRememberMeCookie(RealmModel realm, String username, UriInfo uriInfo, ClientConnection connection) {
        String path = getIdentityCookiePath(realm, uriInfo);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);
        // remember me cookie should be persistent (hardcoded to 365 days for now)
        //NewCookie cookie = new NewCookie(KEYCLOAK_REMEMBER_ME, "true", path, null, null, realm.getCentralLoginLifespan(), secureOnly);// todo httponly , true);
        CookieHelper.addCookie(KEYCLOAK_REMEMBER_ME, "username:" + username, path, null, null, 31536000, secureOnly, true);
    }

    /**
     * 返回cookie中被remember me的用户
     * @param realm
     * @param headers
     * @return
     */
    public static String getRememberMeUsername(RealmModel realm, HttpHeaders headers) {
        if (realm.isRememberMe()) {
            Cookie cookie = headers.getCookies().get(AuthenticationManager.KEYCLOAK_REMEMBER_ME);
            if (cookie != null) {
                String value = cookie.getValue();
                String[] s = value.split(":");
                if (s[0].equals("username") && s.length == 2) {
                    return s[1];
                }
            }
        }
        return null;
    }

    /**
     * 清除IdentityCookie的值
     * @param realm
     * @param uriInfo
     * @param connection
     */
    public static void expireIdentityCookie(RealmModel realm, UriInfo uriInfo, ClientConnection connection) {
        logger.debug("Expiring identity cookie");
        // 生成定位到某个realm的path
        String path = getIdentityCookiePath(realm, uriInfo);
        expireCookie(realm, KEYCLOAK_IDENTITY_COOKIE, path, true, connection, SameSiteAttributeValue.NONE);
        expireCookie(realm, KEYCLOAK_SESSION_COOKIE, path, false, connection, SameSiteAttributeValue.NONE);

        // 应该是兼容性代码
        String oldPath = getOldCookiePath(realm, uriInfo);
        expireCookie(realm, KEYCLOAK_IDENTITY_COOKIE, oldPath, true, connection, SameSiteAttributeValue.NONE);
        expireCookie(realm, KEYCLOAK_SESSION_COOKIE, oldPath, false, connection, SameSiteAttributeValue.NONE);
    }
    public static void expireOldIdentityCookie(RealmModel realm, UriInfo uriInfo, ClientConnection connection) {
        logger.debug("Expiring old identity cookie with wrong path");

        String oldPath = getOldCookiePath(realm, uriInfo);
        expireCookie(realm, KEYCLOAK_IDENTITY_COOKIE, oldPath, true, connection, SameSiteAttributeValue.NONE);
        expireCookie(realm, KEYCLOAK_SESSION_COOKIE, oldPath, false, connection, SameSiteAttributeValue.NONE);
    }


    public static void expireRememberMeCookie(RealmModel realm, UriInfo uriInfo, ClientConnection connection) {
        logger.debug("Expiring remember me cookie");
        String path = getIdentityCookiePath(realm, uriInfo);
        String cookieName = KEYCLOAK_REMEMBER_ME;
        expireCookie(realm, cookieName, path, true, connection, null);
    }

    /**
     * 使得一些过期会话从cookie中移除
     * @param realm
     * @param uriInfo
     * @param connection
     */
    public static void expireOldAuthSessionCookie(RealmModel realm, UriInfo uriInfo, ClientConnection connection) {
        logger.debugv("Expire {1} cookie .", AuthenticationSessionManager.AUTH_SESSION_ID);

        // 得到绑定cookie的path
        String oldPath = getOldCookiePath(realm, uriInfo);
        // 使得该path相关的某些cookie失效
        expireCookie(realm, AuthenticationSessionManager.AUTH_SESSION_ID, oldPath, true, connection, SameSiteAttributeValue.NONE);
    }

    protected static String getIdentityCookiePath(RealmModel realm, UriInfo uriInfo) {
        return getRealmCookiePath(realm, uriInfo);
    }

    /**
     * cookie会绑定在某个uri上 这里就是生成uri  因为uri需要跟realm挂钩
     * @param realm
     * @param uriInfo
     * @return
     */
    public static String getRealmCookiePath(RealmModel realm, UriInfo uriInfo) {
        URI uri = RealmsResource.realmBaseUrl(uriInfo).build(realm.getName());
        // KEYCLOAK-5270
        return uri.getRawPath() + "/";
    }

    public static String getOldCookiePath(RealmModel realm, UriInfo uriInfo) {
        URI uri = RealmsResource.realmBaseUrl(uriInfo).build(realm.getName());
        return uri.getRawPath();
    }

    public static String getAccountCookiePath(RealmModel realm, UriInfo uriInfo) {
        URI uri = RealmsResource.accountUrl(uriInfo.getBaseUriBuilder()).build(realm.getName());
        return uri.getRawPath();
    }

    /**
     * 使得cookie失效
     * @param realm
     * @param cookieName
     * @param path
     * @param httpOnly
     * @param connection
     * @param sameSite
     */
    public static void expireCookie(RealmModel realm, String cookieName, String path, boolean httpOnly, ClientConnection connection, SameSiteAttributeValue sameSite) {
        logger.debugf("Expiring cookie: %s path: %s", cookieName, path);
        boolean secureOnly = realm.getSslRequired().isRequired(connection);;
        CookieHelper.addCookie(cookieName, "", path, null, "Expiring cookie", 0, secureOnly, httpOnly, sameSite);
    }

    // 核心方法 验证会话
    public AuthResult authenticateIdentityCookie(KeycloakSession session, RealmModel realm) {
        return authenticateIdentityCookie(session, realm, true);
    }

    public static AuthResult authenticateIdentityCookie(KeycloakSession session, RealmModel realm, boolean checkActive) {
        // 请求头中允许多个cookie 这里根据key锁定唯一一个
        Cookie cookie = CookieHelper.getCookie(session.getContext().getRequestHeaders().getCookies(), KEYCLOAK_IDENTITY_COOKIE);
        // 无法从请求头中提取出cookie 认为认证失败
        if (cookie == null || "".equals(cookie.getValue())) {
            logger.debugv("Could not find cookie: {0}", KEYCLOAK_IDENTITY_COOKIE);
            return null;
        }

        // 这里的cookie是一个token值
        String tokenString = cookie.getValue();
        // 验证token有效性
        AuthResult authResult = verifyIdentityToken(session, realm, session.getContext().getUri(), session.getContext().getConnection(), checkActive, false, null, true, tokenString, session.getContext().getRequestHeaders(), VALIDATE_IDENTITY_COOKIE);
        // 验证失败 清除cookie的值
        if (authResult == null) {
            expireIdentityCookie(realm, session.getContext().getUri(), session.getContext().getConnection());
            expireOldIdentityCookie(realm, session.getContext().getUri(), session.getContext().getConnection());
            return null;
        }

        // token有效 更新最近访问时间
        authResult.getSession().setLastSessionRefresh(Time.currentTime());
        return authResult;
    }


    /**
     * 当认证流程结束后  进行重定向
     * @param session
     * @param realm
     * @param userSession
     * @param clientSessionCtx
     * @param request
     * @param uriInfo
     * @param clientConnection
     * @param event
     * @param authSession
     * @return
     */
    public static Response redirectAfterSuccessfulFlow(KeycloakSession session, RealmModel realm, UserSessionModel userSession,
                                                       ClientSessionContext clientSessionCtx,
                                                HttpRequest request, UriInfo uriInfo, ClientConnection clientConnection,
                                                EventBuilder event, AuthenticationSessionModel authSession) {
        // 获取协议对象
        LoginProtocol protocolImpl = session.getProvider(LoginProtocol.class, authSession.getProtocol());
        // 进行属性填充
        protocolImpl.setRealm(realm)
                .setHttpHeaders(request.getHttpHeaders())
                .setUriInfo(uriInfo)
                .setEventBuilder(event);
        return redirectAfterSuccessfulFlow(session, realm, userSession, clientSessionCtx, request, uriInfo, clientConnection, event, authSession, protocolImpl);

    }

    /**
     * 认证流程成功后
     * @param session
     * @param realm
     * @param userSession
     * @param clientSessionCtx
     * @param request
     * @param uriInfo
     * @param clientConnection
     * @param event
     * @param authSession
     * @param protocol
     * @return
     */
    public static Response redirectAfterSuccessfulFlow(KeycloakSession session, RealmModel realm, UserSessionModel userSession,
                                                       ClientSessionContext clientSessionCtx,
                                                       HttpRequest request, UriInfo uriInfo, ClientConnection clientConnection,
                                                       EventBuilder event, AuthenticationSessionModel authSession, LoginProtocol protocol) {
        // 获取session
        Cookie sessionCookie = getCookie(request.getHttpHeaders().getCookies(), AuthenticationManager.KEYCLOAK_SESSION_COOKIE);
        if (sessionCookie != null) {

            String[] split = sessionCookie.getValue().split("/");
            if (split.length >= 3) {
                String oldSessionId = split[2];
                // 新发生的认证动作产生了新的session值 需要删除原来的session值 以及相关的会话
                if (!oldSessionId.equals(userSession.getId())) {
                    UserSessionModel oldSession = session.sessions().getUserSession(realm, oldSessionId);
                    if (oldSession != null) {
                        logger.debugv("Removing old user session: session: {0}", oldSessionId);
                        session.sessions().removeUserSession(realm, oldSession);
                    }
                }
            }
        }

        // Updates users locale if required
        // TODO 新的用户可能使用不同的语言环境
        session.getContext().resolveLocale(userSession.getUser());

        // refresh the cookies!
        // 基于新的会话产生session值 设置到cookie中
        createLoginCookie(session, realm, userSession.getUser(), userSession, uriInfo, clientConnection);

        // 更新用户会话为 已登录
        if (userSession.getState() != UserSessionModel.State.LOGGED_IN) userSession.setState(UserSessionModel.State.LOGGED_IN);

        if (userSession.isRememberMe()) {
            // 创建一个 remember me 的cookie
            createRememberMeCookie(realm, userSession.getLoginUsername(), uriInfo, clientConnection);
        } else {
            // 清除 remember me cookie
            expireRememberMeCookie(realm, uriInfo, clientConnection);
        }

        AuthenticatedClientSessionModel clientSession = clientSessionCtx.getClientSession();

        // Update userSession note with authTime. But just if flag SSO_AUTH is not set
        boolean isSSOAuthentication = "true".equals(session.getAttribute(SSO_AUTH));
        if (isSSOAuthentication) {
            clientSession.setNote(SSO_AUTH, "true");
        } else {
            // 非单点登录的情况下 设置认证时间
            int authTime = Time.currentTime();
            userSession.setNote(AUTH_TIME, String.valueOf(authTime));
            clientSession.removeNote(SSO_AUTH);
        }

        // The user has successfully logged in and we can clear his/her previous login failure attempts.
        // 重置防暴力破解的参数
        logSuccess(session, authSession);

        return protocol.authenticated(authSession, userSession, clientSessionCtx);

    }

    public static String getSessionIdFromSessionCookie(KeycloakSession session) {
        Cookie cookie = getCookie(session.getContext().getRequestHeaders().getCookies(), KEYCLOAK_SESSION_COOKIE);
        if (cookie == null || "".equals(cookie.getValue())) {
            logger.debugv("Could not find cookie: {0}", KEYCLOAK_SESSION_COOKIE);
            return null;
        }

        String[] parts = cookie.getValue().split("/", 3);
        if (parts.length != 3) {
            logger.debugv("Cannot parse session value from: {0}", KEYCLOAK_SESSION_COOKIE);
            return null;
        }
        return parts[2];
    }

    /**
     * 判断是否为单点登录认证
     * @param clientSession
     * @return
     */
    public static boolean isSSOAuthentication(AuthenticatedClientSessionModel clientSession) {
        String ssoAuth = clientSession.getNote(SSO_AUTH);
        return Boolean.parseBoolean(ssoAuth);
    }


    /**
     * 尝试完结认证操作
     * @param session
     * @param authSession
     * @param clientConnection
     * @param request
     * @param uriInfo
     * @param event
     * @return
     */
    public static Response nextActionAfterAuthentication(KeycloakSession session, AuthenticationSessionModel authSession,
                                                  ClientConnection clientConnection,
                                                  HttpRequest request, UriInfo uriInfo, EventBuilder event) {

        // 执行认证action
        Response requiredAction = actionRequired(session, authSession, request, event);
        if (requiredAction != null) return requiredAction;

        // 中途没有产生response 代表认证成功了  进行一些收尾工作
        return finishedRequiredActions(session, authSession, null, clientConnection, request, uriInfo, event);

    }


    /**
     * 重定向到执行认证action的地方
     * @param session
     * @param realm
     * @param authSession
     * @param uriInfo
     * @param requiredAction
     * @return
     */
    public static Response redirectToRequiredActions(KeycloakSession session, RealmModel realm, AuthenticationSessionModel authSession, UriInfo uriInfo, String requiredAction) {
        // redirect to non-action url so browser refresh button works without reposting past data
        ClientSessionCode<AuthenticationSessionModel> accessCode = new ClientSessionCode<>(session, realm, authSession);
        accessCode.setAction(AuthenticationSessionModel.Action.REQUIRED_ACTIONS.name());

        // 更新认证相关会话的信息 代表此时正在进行认证相关的操作
        authSession.setAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH, LoginActionsService.REQUIRED_ACTION);
        authSession.setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, requiredAction);

        UriBuilder uriBuilder = LoginActionsService.loginActionsBaseUrl(uriInfo)
                .path(LoginActionsService.REQUIRED_ACTION);

        // 插入参数
        if (requiredAction != null) {
            uriBuilder.queryParam(Constants.EXECUTION, requiredAction);
        }
        uriBuilder.queryParam(Constants.CLIENT_ID, authSession.getClient().getClientId());
        uriBuilder.queryParam(Constants.TAB_ID, authSession.getTabId());

        // 设置root级别的认证会话id
        if (uriInfo.getQueryParameters().containsKey(LoginActionsService.AUTH_SESSION_ID)) {
            uriBuilder.queryParam(LoginActionsService.AUTH_SESSION_ID, authSession.getParentSession().getId());

        }

        URI redirect = uriBuilder.build(realm.getName());
        // 重定向到执行认证的页面
        return Response.status(302).location(redirect).build();

    }


    /**
     * 触发某个行为 并产生结果
     * @param session
     * @param authSession
     * @param userSession
     * @param clientConnection
     * @param request
     * @param uriInfo
     * @param event
     * @return
     */
    public static Response finishedRequiredActions(KeycloakSession session, AuthenticationSessionModel authSession, UserSessionModel userSession,
                                                   ClientConnection clientConnection, HttpRequest request, UriInfo uriInfo, EventBuilder event) {
        String actionTokenKeyToInvalidate = authSession.getAuthNote(INVALIDATE_ACTION_TOKEN);
        if (actionTokenKeyToInvalidate != null) {
            // 将string转换成token的key
            ActionTokenKeyModel actionTokenKey = DefaultActionTokenKey.from(actionTokenKeyToInvalidate);
            
            if (actionTokenKey != null) {
                ActionTokenStoreProvider actionTokenStore = session.getProvider(ActionTokenStoreProvider.class);
                // 通过null 覆盖token
                actionTokenStore.put(actionTokenKey, null); // Token is invalidated
            }
        }

        // 代表认证动作都已经完成  并且需要一些额外操作
        if (authSession.getAuthNote(END_AFTER_REQUIRED_ACTIONS) != null) {
            LoginFormsProvider infoPage = session.getProvider(LoginFormsProvider.class).setAuthenticationSession(authSession)
                    .setSuccess(Messages.ACCOUNT_UPDATED);
            if (authSession.getAuthNote(SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS) != null) {
                if (authSession.getRedirectUri() != null) {
                    // 在page中设置redirectUri   代表着一般认证完成后需要重定向到某个uri
                    infoPage.setAttribute("pageRedirectUri", authSession.getRedirectUri());
                }
            } else {
                // 代表不需要重定向
                infoPage.setAttribute(Constants.SKIP_LINK, true);
            }

            // 生成响应结果
            Response response = infoPage
                    .createInfoPage();

            // 看来认证会话是认证过程中使用的会话   与client session/user session是不一样的  一旦认证动作完成后 认证会话就不再需要了
            new AuthenticationSessionManager(session).removeAuthenticationSession(authSession.getRealm(), authSession, true);

            return response;
        }

        // 不需要额外操作的情况下
        RealmModel realm = authSession.getRealm();

        // 完成了认证 产生client级别的会话对象
        ClientSessionContext clientSessionCtx = AuthenticationProcessor.attachSession(authSession, userSession, session, realm, clientConnection, event);
        userSession = clientSessionCtx.getClientSession().getUserSession();

        // 设置用户会话
        event.event(EventType.LOGIN);
        event.session(userSession);
        event.success();
        // 这里是通用逻辑 也是要进行重定向的
        return redirectAfterSuccessfulFlow(session, realm, userSession, clientSessionCtx, request, uriInfo, clientConnection, event, authSession);
    }

    // Return null if action is not required. Or the name of the requiredAction in case it is required.
    // 返回下个认证action
    public static String nextRequiredAction(final KeycloakSession session, final AuthenticationSessionModel authSession,
                                            final HttpRequest request, final EventBuilder event) {
        final RealmModel realm = authSession.getRealm();
        final UserModel user = authSession.getAuthenticatedUser();
        final ClientModel client = authSession.getClient();

        // 评估所有要处理的action 并设置到user中
        evaluateRequiredActionTriggers(session, authSession, request, event, realm, user);

        // 在评估后返回第一个action
        Optional<String> reqAction = user.getRequiredActionsStream().findFirst();
        if (reqAction.isPresent()) {
            return reqAction.get();
        }

        // 也是返回第一个
        if (!authSession.getRequiredActions().isEmpty()) {
            return authSession.getRequiredActions().iterator().next();
        }

        // 普通的action遍历完后 还有个kc_action
        String kcAction = authSession.getClientNote(Constants.KC_ACTION);
        if (kcAction != null) {
            return kcAction;
        }

        if (client.isConsentRequired()) {

            UserConsentModel grantedConsent = getEffectiveGrantedConsent(session, authSession);

            // See if any clientScopes need to be approved on consent screen
            List<ClientScopeModel> clientScopesToApprove = getClientScopesToApproveOnConsentScreen(realm, grantedConsent, authSession);
            // 代表还需要用户为client授权
            if (!clientScopesToApprove.isEmpty()) {
                return CommonClientSessionModel.Action.OAUTH_GRANT.name();
            }

            String consentDetail = (grantedConsent != null) ? Details.CONSENT_VALUE_PERSISTED_CONSENT : Details.CONSENT_VALUE_NO_CONSENT_REQUIRED;
            event.detail(Details.CONSENT, consentDetail);
        } else {
            event.detail(Details.CONSENT, Details.CONSENT_VALUE_NO_CONSENT_REQUIRED);
        }
        return null;

    }


    /**
     * 获取用户已经同意的client
     * @param session
     * @param authSession
     * @return
     */
    private static UserConsentModel getEffectiveGrantedConsent(KeycloakSession session, AuthenticationSessionModel authSession) {
        // If prompt=consent, we ignore existing persistent consent
        String prompt = authSession.getClientNote(OIDCLoginProtocol.PROMPT_PARAM);
        // 这种情况 忽略存储在持久层的 用户认可client数据
        if (TokenUtil.hasPrompt(prompt, OIDCLoginProtocol.PROMPT_VALUE_CONSENT)) {
            return null;
        } else {
            final RealmModel realm = authSession.getRealm();
            final UserModel user = authSession.getAuthenticatedUser();
            final ClientModel client = authSession.getClient();

            // 查询该用户是否已经支持client的信息
            return session.users().getConsentByClient(realm, user.getId(), client.getId());
        }
    }


    /**
     *
     * @param session
     * @param authSession
     * @param request
     * @param event
     * @return
     */
    public static Response actionRequired(final KeycloakSession session, final AuthenticationSessionModel authSession,
                                                         final HttpRequest request, final EventBuilder event) {
        final RealmModel realm = authSession.getRealm();
        final UserModel user = authSession.getAuthenticatedUser();
        final ClientModel client = authSession.getClient();

        // 先评估需要进行哪些认证动作  需要的会加入到user中
        evaluateRequiredActionTriggers(session, authSession, request, event, realm, user);

        logger.debugv("processAccessCode: go to oauth page?: {0}", client.isConsentRequired());

        event.detail(Details.CODE_ID, authSession.getParentSession().getId());

        // 拿到上一步返回的认证动作
        Stream<String> requiredActions = user.getRequiredActionsStream();
        // 执行认证动作得到结果
        Response action = executionActions(session, authSession, request, event, realm, user, requiredActions);
        if (action != null) return action;

        // executionActions() method should remove any duplicate actions that might be in the clientSession
        // 执行过的action 会被remove掉  所以如果还有剩余就有执行的必要
        action = executionActions(session, authSession, request, event, realm, user, authSession.getRequiredActions().stream());
        if (action != null) return action;

        // 需要认可
        if (client.isConsentRequired()) {

            // 得到用户认可client的对象
            UserConsentModel grantedConsent = getEffectiveGrantedConsent(session, authSession);

            // 返回其他需要认可的client
            List<ClientScopeModel> clientScopesToApprove = getClientScopesToApproveOnConsentScreen(realm, grantedConsent, authSession);

            // Skip grant screen if everything was already approved by this user
            if (clientScopesToApprove.size() > 0) {
                String execution = AuthenticatedClientSessionModel.Action.OAUTH_GRANT.name();

                ClientSessionCode<AuthenticationSessionModel> accessCode = new ClientSessionCode<>(session, realm, authSession);
                accessCode.setAction(AuthenticatedClientSessionModel.Action.REQUIRED_ACTIONS.name());
                authSession.setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, execution);

                // 产生一个授权页面 示意用户为该client授权
                return session.getProvider(LoginFormsProvider.class)
                        .setAuthenticationSession(authSession)
                        .setExecution(execution)
                        .setClientSessionCode(accessCode.getOrGenerateCode())
                        .setAccessRequest(clientScopesToApprove)
                        .createOAuthGrant();
            } else {
                // 要么就是已经认可过所有要求 要么就是不需要认可  (grantedConsent为null 代表用户还未认可 同时没有进入上面的分支代表 client需要的认可scope为空 也就是不需要认可)
                String consentDetail = (grantedConsent != null) ? Details.CONSENT_VALUE_PERSISTED_CONSENT : Details.CONSENT_VALUE_NO_CONSENT_REQUIRED;
                event.detail(Details.CONSENT, consentDetail);
            }
        } else {
            event.detail(Details.CONSENT, Details.CONSENT_VALUE_NO_CONSENT_REQUIRED);
        }
        return null;

    }

    /**
     *
     * @param realm
     * @param grantedConsent  描述用户已经授权的client
     * @param authSession
     * @return
     */
    private static List<ClientScopeModel> getClientScopesToApproveOnConsentScreen(RealmModel realm, UserConsentModel grantedConsent,
                                                                                  AuthenticationSessionModel authSession) {
        // Client Scopes to be displayed on consent screen
        List<ClientScopeModel> clientScopesToDisplay = new LinkedList<>();

        for (String clientScopeId : authSession.getClientScopes()) {
            // 根据id精准的读取出每个scope
            ClientScopeModel clientScope = KeycloakModelUtils.findClientScopeById(realm, authSession.getClient(), clientScopeId);

            if (clientScope == null || !clientScope.isDisplayOnConsentScreen()) {
                continue;
            }

            // Check if consent already granted by user
            // 还未通过授权的 clientScope需要返回
            if (grantedConsent == null || !grantedConsent.isClientScopeGranted(clientScope)) {
                clientScopesToDisplay.add(clientScope);
            }
        }

        return clientScopesToDisplay;
    }


    /**
     * 为认证会话设置client_scope
     * @param authSession
     */
    public static void setClientScopesInSession(AuthenticationSessionModel authSession) {

        // 认证会话关联client root认证会话关联user
        ClientModel client = authSession.getClient();
        UserModel user = authSession.getAuthenticatedUser();

        // todo scope param protocol independent
        String scopeParam = authSession.getClientNote(OAuth2Constants.SCOPE);

        // 从tokenManager中找到client关联的一组scope
        Set<String> requestedClientScopes = TokenManager.getRequestedClientScopes(scopeParam, client)
                .map(ClientScopeModel::getId).collect(Collectors.toSet());

        // 设置client_scope
        authSession.setClientScopes(requestedClientScopes);
    }

    /**
     * 生成一个认证动作对象
     * @param context
     * @return
     */
    public static RequiredActionProvider createRequiredAction(RequiredActionContextResult context) {
        String display = context.getAuthenticationSession().getAuthNote(OAuth2Constants.DISPLAY);
        if (display == null) return context.getFactory().create(context.getSession());

        // TODO 忽略 display
        if (context.getFactory() instanceof DisplayTypeRequiredActionFactory) {
            RequiredActionProvider provider = ((DisplayTypeRequiredActionFactory)context.getFactory()).createDisplay(context.getSession(), display);
            if (provider != null) return provider;
        }
        // todo create a provider for handling lack of display support
        if (OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(display)) {
            context.getAuthenticationSession().removeAuthNote(OAuth2Constants.DISPLAY);
            throw new AuthenticationFlowException(AuthenticationFlowError.DISPLAY_NOT_SUPPORTED, ConsoleDisplayMode.browserContinue(context.getSession(), context.getUriInfo().getRequestUri().toString()));

        } else {
            return context.getFactory().create(context.getSession());
        }
    }

    /**
     *
     * @param session
     * @param authSession
     * @param request
     * @param event
     * @param realm
     * @param user
     * @param requiredActions   描述需要进行的所有认证操作
     * @return
     */
    protected static Response executionActions(KeycloakSession session, AuthenticationSessionModel authSession,
                                               HttpRequest request, EventBuilder event, RealmModel realm, UserModel user,
                                               Stream<String> requiredActions) {

        // 先执行所有普通的action

        // 此时已经执行完所有action了
        Optional<Response> response = sortRequiredActionsByPriority(realm, requiredActions)
                .map(model -> executeAction(session, authSession, model, request, event, realm, user, false))
                .filter(Objects::nonNull).findFirst();
        // 已经产生结果了  比如前面的action失败 会直接返回
        if (response.isPresent())
            return response.get();

        // 执行 kc_action

        String kcAction = authSession.getClientNote(Constants.KC_ACTION);
        if (kcAction != null) {
            Optional<RequiredActionProviderModel> requiredAction = realm.getRequiredActionProvidersStream()
                    .filter(m -> Objects.equals(m.getProviderId(), kcAction))
                    .findFirst();
            if (requiredAction.isPresent()) {
                return executeAction(session, authSession, requiredAction.get(), request, event, realm, user, true);
            }

            logger.debugv("Requested action {0} not configured for realm", kcAction);
            setKcActionStatus(kcAction, RequiredActionContext.KcActionStatus.ERROR, authSession);
        }

        return null;
    }

    /**
     *
     * @param session
     * @param authSession  认证会话  对应user->client
     * @param model        此时要执行的某个认证动作
     * @param request      对应的请求参数
     * @param event
     * @param realm
     * @param user
     * @param kcActionExecution  简单理解 该标识为true时 initiatedActionSupport 必须为supported
     * @return
     */
    private static Response executeAction(KeycloakSession session, AuthenticationSessionModel authSession, RequiredActionProviderModel model,
                                          HttpRequest request, EventBuilder event, RealmModel realm, UserModel user, boolean kcActionExecution) {

        // 找到该认证action对应的工厂
        RequiredActionFactory factory = (RequiredActionFactory) session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, model.getProviderId());
        if (factory == null) {
            throw new RuntimeException("Unable to find factory for Required Action: " + model.getProviderId() + " did you forget to declare it in a META-INF/services file?");
        }
        RequiredActionContextResult context = new RequiredActionContextResult(authSession, realm, event, session, request, user, factory);
        RequiredActionProvider actionProvider = null;
        try {
            actionProvider = createRequiredAction(context);
        } catch (AuthenticationFlowException e) {
            if (e.getResponse() != null) {
                return e.getResponse();
            }
            throw e;
        }

        if (kcActionExecution) {
            // provider不需要进行一些init操作
            if (actionProvider.initiatedActionSupport() == InitiatedActionSupport.NOT_SUPPORTED) {
                logger.debugv("Requested action {0} does not support being invoked with kc_action", factory.getId());
                setKcActionStatus(factory.getId(), RequiredActionContext.KcActionStatus.ERROR, authSession);
                return null;
                // 该provider不可用 设置异常状态
            } else if (!model.isEnabled()) {
                logger.debugv("Requested action {0} is disabled and can't be invoked with kc_action", factory.getId());
                setKcActionStatus(factory.getId(), RequiredActionContext.KcActionStatus.ERROR, authSession);
                return null;
            } else {
                // 设置成执行中
                authSession.setClientNote(Constants.KC_ACTION_EXECUTING, factory.getId());
            }
        }

        // 如果对应的provider有需要 则会返回给用户需要展示的内容   简单理解 当这步完成后status已经被修改了
        actionProvider.requiredActionChallenge(context);

        // action执行失败
        if (context.getStatus() == RequiredActionContext.Status.FAILURE) {

            // 简单理解就是OIDC
            LoginProtocol protocol = context.getSession().getProvider(LoginProtocol.class, context.getAuthenticationSession().getProtocol());
            protocol.setRealm(context.getRealm())
                    .setHttpHeaders(context.getHttpRequest().getHttpHeaders())
                    .setUriInfo(context.getUriInfo())
                    .setEventBuilder(event);
            Response response = protocol.sendError(context.getAuthenticationSession(), Error.CONSENT_DENIED);
            event.error(Errors.REJECTED_BY_USER);
            return response;
        }

        // 代表处于认证中吧
        else if (context.getStatus() == RequiredActionContext.Status.CHALLENGE) {
            // 设置认证会话此时在执行的provider
            authSession.setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, model.getProviderId());
            return context.getChallenge();
        }

        // 认证成功
        else if (context.getStatus() == RequiredActionContext.Status.SUCCESS) {
            event.clone().event(EventType.CUSTOM_REQUIRED_ACTION).detail(Details.CUSTOM_REQUIRED_ACTION, factory.getId()).success();
            // don't have to perform the same action twice, so remove it from both the user and session required actions
            // 认证动作已经完成 不需要记录了
            authSession.getAuthenticatedUser().removeRequiredAction(factory.getId());
            authSession.removeRequiredAction(factory.getId());
            // 设置成功状态
            setKcActionStatus(factory.getId(), RequiredActionContext.KcActionStatus.SUCCESS, authSession);
        }

        return null;
    }

    /**
     * 对所有要执行的认证动作进行排序
     * @param realm
     * @param requiredActions
     * @return
     */
    private static Stream<RequiredActionProviderModel> sortRequiredActionsByPriority(RealmModel realm, Stream<String> requiredActions) {
        return requiredActions.map(action -> {
                    // 通过名称匹配  找到对应的provider
                    RequiredActionProviderModel model = realm.getRequiredActionProviderByAlias(action);
                    if (model == null) {
                        logger.warnv("Could not find configuration for Required Action {0}, did you forget to register it?", action);
                    }
                    return model;
                })
                .filter(Objects::nonNull)
                .filter(RequiredActionProviderModel::isEnabled)
                .sorted(RequiredActionProviderModel.RequiredActionComparator.SINGLETON);
    }

    /**
     * 将所有需要的认证动作加入到 userModel中  这里是评估哪些动作是必要的
     * @param session
     * @param authSession
     * @param request
     * @param event
     * @param realm
     * @param user
     */
    public static void evaluateRequiredActionTriggers(final KeycloakSession session, final AuthenticationSessionModel authSession,
                                                      final HttpRequest request, final EventBuilder event,
                                                      final RealmModel realm, final UserModel user) {
        // see if any required actions need triggering, i.e. an expired password
        realm.getRequiredActionProvidersStream()
                .filter(RequiredActionProviderModel::isEnabled)
                // 找到对应的工厂
                .map(model -> toRequiredActionFactory(session, model))
                .forEachOrdered(f -> evaluateRequiredAction(session, authSession, request, event, realm, user, f));
    }

    /**
     * 评估是否要触发这个认证动作
     * @param session
     * @param authSession
     * @param request
     * @param event
     * @param realm
     * @param user
     * @param factory
     */
    private static void evaluateRequiredAction(final KeycloakSession session, final AuthenticationSessionModel authSession,
                                        final HttpRequest request, final EventBuilder event, final RealmModel realm,
                                        final UserModel user, RequiredActionFactory factory) {
        RequiredActionProvider provider = factory.create(session);
        RequiredActionContextResult result = new RequiredActionContextResult(authSession, realm, event, session, request, user, factory) {
            // 下面这几个方法都是不应该被触发的

            @Override
            public void challenge(Response response) {
                throw new RuntimeException("Not allowed to call challenge() within evaluateTriggers()");
            }

            @Override
            public void failure() {
                throw new RuntimeException("Not allowed to call failure() within evaluateTriggers()");
            }

            @Override
            public void success() {
                throw new RuntimeException("Not allowed to call success() within evaluateTriggers()");
            }

            @Override
            public void ignore() {
                throw new RuntimeException("Not allowed to call ignore() within evaluateTriggers()");
            }
        };

        // 评估是否需要触发这个动作 如果需要会触发userModel.addRequiredAction
        provider.evaluateTriggers(result);
    }

    /**
     * 返回可以生成 RequiredActionProvider 的工厂 意味着这些action 在认证阶段必须完成
     * @param session
     * @param model
     * @return
     */
    private static RequiredActionFactory toRequiredActionFactory(KeycloakSession session, RequiredActionProviderModel model) {
        RequiredActionFactory factory = (RequiredActionFactory) session.getKeycloakSessionFactory()
                .getProviderFactory(RequiredActionProvider.class, model.getProviderId());
        if (factory == null) {
            throw new RuntimeException("Unable to find factory for Required Action: "
                    + model.getProviderId() + " did you forget to declare it in a META-INF/services file?");
        }
        return factory;
    }

    /**
     * 验证token有效性
     * @param session  存储本次交互需要的各种信息
     * @param realm    本次相关的领域  会关联领域配置  用户/角色
     * @param uriInfo
     * @param connection
     * @param checkActive
     * @param checkTokenType
     * @param checkAudience
     * @param isCookie
     * @param tokenString
     * @param headers
     * @param additionalChecks  需要通过的额外检查
     * @return
     */
    public static AuthResult verifyIdentityToken(KeycloakSession session, RealmModel realm, UriInfo uriInfo, ClientConnection connection, boolean checkActive, boolean checkTokenType,
                                                 String checkAudience, boolean isCookie, String tokenString, HttpHeaders headers, Predicate<? super AccessToken>... additionalChecks) {
        try {
            // TODO 验证的逻辑先忽略
            // 生成一个校验器
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenString, AccessToken.class)
              .withDefaultChecks()
              .realmUrl(Urls.realmIssuer(uriInfo.getBaseUri(), realm.getName()))
              .checkActive(checkActive)
              .checkTokenType(checkTokenType)
              .withChecks(additionalChecks);

            if (checkAudience != null) {
                verifier.audience(checkAudience);
            }

            String kid = verifier.getHeader().getKeyId();
            String algorithm = verifier.getHeader().getAlgorithm().name();

            SignatureVerifierContext signatureVerifier = session.getProvider(SignatureProvider.class, algorithm).verifier(kid);
            verifier.verifierContext(signatureVerifier);


            // 验证完毕 获取token
            AccessToken token = verifier.verify().getToken();
            // 要求token还有效
            if (checkActive) {
                if (!token.isActive() || token.getIssuedAt() < realm.getNotBefore()) {
                    logger.debug("Identity cookie expired");
                    return null;
                }
            }

            UserSessionModel userSession = null;
            UserModel user = null;
            // token上无会话状态  只能从token上解析出用户信息 而没有session信息
            if (token.getSessionState() == null) {
                user = TokenManager.lookupUserFromStatelessToken(session, realm, token);
                // 检查用户是否可用 以及token是否过期
                if (!isUserValid(session, realm, user, token)) {
                    return null;
                }
            } else {
                // 有会话状态的token
                userSession = session.sessions().getUserSession(realm, token.getSessionState());
                if (userSession != null) {
                    user = userSession.getUser();
                    if (!isUserValid(session, realm, user, token)) {
                        return null;
                    }
                }
            }

            // isSessionValid 代表会话已经超时
            if (token.getSessionState() != null && !isSessionValid(realm, userSession)) {
                // Check if accessToken was for the offline session.
                // TODO 检查离线会话
                if (!isCookie) {
                    UserSessionModel offlineUserSession = session.sessions().getOfflineUserSession(realm, token.getSessionState());
                    if (isOfflineSessionValid(realm, offlineUserSession)) {
                        user = offlineUserSession.getUser();
                        return new AuthResult(user, offlineUserSession, token);
                    }
                }

                if (userSession != null) backchannelLogout(session, realm, userSession, uriInfo, connection, headers, true);
                logger.debug("User session not active");
                return null;
            }

            // 至此已经确保 session/user的有效性了   将token的状态检查器 转移到session中
            session.setAttribute("state_checker", token.getOtherClaims().get("state_checker"));

            return new AuthResult(user, userSession, token);
        } catch (VerificationException e) {
            logger.debugf("Failed to verify identity token: %s", e.getMessage());
        }
        return null;
    }

    /**
     * 判断用户是否有效
     * @param session
     * @param realm
     * @param user
     * @param token
     * @return
     */
    private static boolean isUserValid(KeycloakSession session, RealmModel realm, UserModel user, AccessToken token) {
        if (user == null || !user.isEnabled()) {
            logger.debug("Unknown user in identity token");
            return false;
        }

        // 获取user的一个属性 叫做 not_before    当token的iat小于该值时  认为用户无效
        int userNotBefore = session.users().getNotBeforeOfUser(realm, user);
        if (token.getIssuedAt() < userNotBefore) {
            logger.debug("User notBefore newer than token");
            return false;
        }

        return true;
    }

    /**
     * 描述认证状态
     */
    public enum AuthenticationStatus {
        SUCCESS,
        // 账户临时不可用 应该就是防止暴力破解的
        ACCOUNT_TEMPORARILY_DISABLED, ACCOUNT_DISABLED,
        // 应该是代表还需要进行的认证动作
        ACTIONS_REQUIRED, INVALID_USER, INVALID_CREDENTIALS, MISSING_PASSWORD, MISSING_TOTP, FAILED
    }

    /**
     * 对应一个认证结果
     */
    public static class AuthResult {
        private final UserModel user;
        private final UserSessionModel session;
        private final AccessToken token;

        public AuthResult(UserModel user, UserSessionModel session, AccessToken token) {
            this.user = user;
            this.session = session;
            this.token = token;
        }

        public UserSessionModel getSession() {
            return session;
        }

        public UserModel getUser() {
            return user;
        }

        public AccessToken getToken() {
            return token;
        }
    }

    /**
     * 设置keycloak的状态
     * @param executedProviderId  本次操作的actionId
     * @param status  描述本次的动作是成功了 取消 还是失败
     * @param authSession
     */
    public static void setKcActionStatus(String executedProviderId, RequiredActionContext.KcActionStatus status, AuthenticationSessionModel authSession) {
        // clientNote 就是一个map
        // 当本次传入的provider 与action的name一致时
        if (executedProviderId.equals(authSession.getClientNote(Constants.KC_ACTION))) {
            // 更新action状态
            authSession.setClientNote(Constants.KC_ACTION_STATUS, status.name().toLowerCase());
            // 应该是代表执行完毕了   所以移除掉action信息  仅保留状态
            authSession.removeClientNote(Constants.KC_ACTION);
            authSession.removeClientNote(Constants.KC_ACTION_EXECUTING);
        }
    }

    /**
     * 代表登录成功
     * @param session
     * @param authSession
     */
    public static void logSuccess(KeycloakSession session, AuthenticationSessionModel authSession) {
        // 从当前上下文可以知道 请求对应的realm
        RealmModel realm = session.getContext().getRealm();
        // 防止暴力破解？
        if (realm.isBruteForceProtected()) {
            // 拿到会话信息后 尝试检索用户数据
            UserModel user = lookupUserForBruteForceLog(session, realm, authSession);
            if (user != null) {
                // 因为登录成功了 可以解除防暴力登录的限制了   比如 错误次数可以重置了
                BruteForceProtector bruteForceProtector = session.getProvider(BruteForceProtector.class);
                bruteForceProtector.successfulLogin(realm, user, session.getContext().getConnection());
            }
        }
    }

    /**
     * 从会话信息中解析出用户信息
     * @param session
     * @param realm
     * @param authenticationSession
     * @return
     */
    public static UserModel lookupUserForBruteForceLog(KeycloakSession session, RealmModel realm, AuthenticationSessionModel authenticationSession) {
        // 认证会话上是有用户id的  然后通过realm+uid 查找用户
        UserModel user = authenticationSession.getAuthenticatedUser();
        if (user != null) return user;

        // 尝试使用username查询
        String username = authenticationSession.getAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME);
        if (username != null) {
            return KeycloakModelUtils.findUserByNameOrEmail(session, realm, username);
        }

        return null;
    }

}
