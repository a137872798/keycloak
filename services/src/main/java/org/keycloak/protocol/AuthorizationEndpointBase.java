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

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.AuthenticationFlowResolver;
import org.keycloak.protocol.LoginProtocol.Error;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionCrossDCManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

/**
 * Common base class for Authorization REST endpoints implementation, which have to be implemented by each protocol.
 *
 * @author Vlastimil Elias (velias at redhat dot com)
 * 认证基类
 */
public abstract class AuthorizationEndpointBase {

    private static final Logger logger = Logger.getLogger(AuthorizationEndpointBase.class);

    public static final String APP_INITIATED_FLOW = "APP_INITIATED_FLOW";

    protected RealmModel realm;
    protected EventBuilder event;

    /**
     * 包含了认证流程相关的方法
     */
    protected AuthenticationManager authManager;

    @Context
    protected HttpHeaders headers;
    @Context
    protected HttpRequest httpRequest;
    @Context
    protected KeycloakSession session;
    @Context
    protected ClientConnection clientConnection;

    public AuthorizationEndpointBase(RealmModel realm, EventBuilder event) {
        this.realm = realm;
        this.event = event;
    }

    /**
     * 根据相关参数生成一个认证处理器
     * @param authSession
     * @param flowId  通过id可以找到对应的认证流
     * @param flowPath
     * @return
     */
    protected AuthenticationProcessor createProcessor(AuthenticationSessionModel authSession, String flowId, String flowPath) {
        AuthenticationProcessor processor = new AuthenticationProcessor();
        processor.setAuthenticationSession(authSession)
                .setFlowPath(flowPath)
                .setFlowId(flowId)
                .setBrowserFlow(true)
                .setConnection(clientConnection)
                .setEventBuilder(event)
                .setRealm(realm)
                .setSession(session)
                .setUriInfo(session.getContext().getUri())
                .setRequest(httpRequest);

        // 设置当前流程path
        authSession.setAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH, flowPath);

        return processor;
    }

    /**
     * Common method to handle browser authentication request in protocols unified way.
     *
     * @param authSession for current request
     * @param protocol handler for protocol used to initiate login
     * @param isPassive set to true if login should be passive (without login screen shown)
     * @param redirectToAuthentication if true redirect to flow url.  If initial call to protocol is a POST, you probably want to do this.  This is so we can disable the back button on browser
     * @return response to be returned to the browser
     * 处理通过浏览器认证的情况
     */
    protected Response handleBrowserAuthenticationRequest(AuthenticationSessionModel authSession, LoginProtocol protocol, boolean isPassive, boolean redirectToAuthentication) {
        // 加载浏览器相关的认证流对象
        AuthenticationFlowModel flow = getAuthenticationFlow(authSession);

        String flowId = flow.getId();
        // 生成认证处理器
        AuthenticationProcessor processor = createProcessor(authSession, flowId, LoginActionsService.AUTHENTICATE_PATH);
        event.detail(Details.CODE_ID, authSession.getParentSession().getId());

        // 被动登录  被动登录意味着只是检查用户是否已登录
        if (isPassive) {
            // OIDC prompt == NONE or SAML 2 IsPassive flag
            // This means that client is just checking if the user is already completely logged in.
            // We cancel login if any authentication action or required action is required
            try {
                // 此时已经进行过认证了
                Response challenge = processor.authenticateOnly();

                // 返回null是正常情况 代表流程可以继续
                if (challenge == null) {
                    // nothing to do - user is already authenticated;
                } else {
                    // KEYCLOAK-8043: forward the request with prompt=none to the default provider.
                    // 代表需要跳转
                    if ("true".equals(authSession.getAuthNote(AuthenticationProcessor.FORWARDED_PASSIVE_LOGIN))) {
                        // 添加一个KC_RESTART的cookie 值为本次会话编码后的数据
                        RestartLoginCookie.setRestartCookie(session, realm, clientConnection, session.getContext().getUri(), authSession);

                        // 重定向回认证页
                        if (redirectToAuthentication) {
                            return processor.redirectToFlow();
                        }
                        // no need to trigger authenticate, just return the challenge we got from authenticateOnly.
                        // 直接返回结果
                        return challenge;
                    }
                    else {
                        // 不需要跳转的情况下 返回错误信息
                        Response response = protocol.sendError(authSession, Error.PASSIVE_LOGIN_REQUIRED);
                        return response;
                    }
                }

                // 此时认为认证已经通过 为会话设置client_scope
                AuthenticationManager.setClientScopesInSession(authSession);

                // 代表认证结束后 还需要进行一些工作  而被动登录是不支持的
                if (processor.nextRequiredAction() != null) {
                    Response response = protocol.sendError(authSession, Error.PASSIVE_INTERACTION_REQUIRED);
                    return response;
                }

            } catch (Exception e) {
                return processor.handleBrowserException(e);
            }
            // 成功通过认证流程
            return processor.finishAuthentication(protocol);
        } else {

            // 主动发起认证流程
            try {
                // 也要设置一个KC_RESTART cookie
                RestartLoginCookie.setRestartCookie(session, realm, clientConnection, session.getContext().getUri(), authSession);
                if (redirectToAuthentication) {
                    // 重定向到认证地址
                    return processor.redirectToFlow();
                }
                // 执行认证流程
                return processor.authenticate();
            } catch (Exception e) {
                return processor.handleBrowserException(e);
            }
        }
    }

    /**
     * 从认证会话中解析出认证流
     * @param authSession
     * @return
     */
    protected AuthenticationFlowModel getAuthenticationFlow(AuthenticationSessionModel authSession) {
        return AuthenticationFlowResolver.resolveBrowserFlow(authSession);
    }

    protected void checkSsl() {
        if (!session.getContext().getUri().getBaseUri().getScheme().equals("https") && realm.getSslRequired().isRequired(clientConnection)) {
            event.error(Errors.SSL_REQUIRED);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.HTTPS_REQUIRED);
        }
    }

    protected void checkRealm() {
        if (!realm.isEnabled()) {
            event.error(Errors.REALM_DISABLED);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.REALM_NOT_ENABLED);
        }
    }

    /**
     * 创建一个认证会话对象
     * @param client
     * @param requestState
     * @return
     */
    protected AuthenticationSessionModel createAuthenticationSession(ClientModel client, String requestState) {
        // 该方法包含与认证会话交互的api
        AuthenticationSessionManager manager = new AuthenticationSessionManager(session);

        // 从cookie上解析root sessionId 并查询session
        RootAuthenticationSessionModel rootAuthSession = manager.getCurrentRootAuthenticationSession(realm);

        AuthenticationSessionModel authSession;

        if (rootAuthSession != null) {
            // 在root下关联一个子认证会话
            authSession = rootAuthSession.createAuthenticationSession(client);

            logger.debugf("Sent request to authz endpoint. Root authentication session with ID '%s' exists. Client is '%s' . Created new authentication session with tab ID: %s",
                    rootAuthSession.getId(), client.getClientId(), authSession.getTabId());
        } else {
            // TODO 尝试从其他数据中心获取 先忽略
            UserSessionCrossDCManager userSessionCrossDCManager = new UserSessionCrossDCManager(session);
            UserSessionModel userSession = userSessionCrossDCManager.getUserSessionIfExistsRemotely(manager, realm);

            if (userSession != null) {
                UserModel user = userSession.getUser();
                if (user != null && !user.isEnabled()) {
                    authSession = createNewAuthenticationSession(manager, client);

                    AuthenticationManager.backchannelLogout(session, userSession, true);
                } else {
                    String userSessionId = userSession.getId();
                    rootAuthSession = session.authenticationSessions().createRootAuthenticationSession(realm, userSessionId);
                    authSession = rootAuthSession.createAuthenticationSession(client);
                    logger.debugf("Sent request to authz endpoint. We don't have root authentication session with ID '%s' but we have userSession." +
                            "Re-created root authentication session with same ID. Client is: %s . New authentication session tab ID: %s", userSessionId, client.getClientId(), authSession.getTabId());
                }
            } else {
                // 正常情况下创建一个新的root认证会话 以及一个子认证会话
                authSession = createNewAuthenticationSession(manager, client);
            }
        }

        // 为登录器设置认证会话
        session.getProvider(LoginFormsProvider.class).setAuthenticationSession(authSession);

        return authSession;

    }

    /**
     * 创建新的认证会话
     * @param manager
     * @param client
     * @return
     */
    private AuthenticationSessionModel createNewAuthenticationSession(AuthenticationSessionManager manager, ClientModel client) {
        RootAuthenticationSessionModel rootAuthSession = manager.createAuthenticationSession(realm, true);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        logger.debugf("Sent request to authz endpoint. Created new root authentication session with ID '%s' . Client: %s . New authentication session tab ID: %s",
                rootAuthSession.getId(), client.getClientId(), authSession.getTabId());
        return authSession;
    }
}