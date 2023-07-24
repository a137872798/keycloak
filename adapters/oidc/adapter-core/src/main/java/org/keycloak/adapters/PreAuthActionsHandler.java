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

package org.keycloak.adapters;

import java.security.PublicKey;

import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.adapters.authentication.ClientCredentialsProvider;
import org.keycloak.adapters.authentication.JWTClientCredentialsProvider;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.spi.UserSessionManagement;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.adapters.action.AdminAction;
import org.keycloak.representations.adapters.action.LogoutAction;
import org.keycloak.representations.adapters.action.PushNotBeforeAction;
import org.keycloak.representations.adapters.action.TestAvailabilityAction;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 在认证前起作用的处理器
 */
public class PreAuthActionsHandler {

    private static final Logger log = Logger.getLogger(PreAuthActionsHandler.class);

    /**
     * 通过该对象可以对会话进行登出操作
     */
    protected UserSessionManagement userSessionManagement;

    /**
     * 包含了创建 deployment 需要的各种属性
     */
    protected AdapterDeploymentContext deploymentContext;
    protected KeycloakDeployment deployment;
    protected HttpFacade facade;

    public PreAuthActionsHandler(UserSessionManagement userSessionManagement, AdapterDeploymentContext deploymentContext, HttpFacade facade) {
        this.userSessionManagement = userSessionManagement;
        this.deploymentContext = deploymentContext;
        this.facade = facade;
    }

    protected boolean resolveDeployment() {
        deployment = deploymentContext.resolveDeployment(facade);
        // 代表deployment的配置不正确 无法处理
        if (!deployment.isConfigured()) {
            log.warn("can't take request, adapter not configured");
            facade.getResponse().sendError(403, "adapter not configured");
            return false;
        }
        return true;
    }

    /**
     * 通过该方法处理请求
     *
     * @return
     */
    public boolean handleRequest() {
        String requestUri = facade.getRequest().getURI();
        log.debugv("adminRequest {0}", requestUri);

        // 当发现是一个跨域请求时 使用deployment替换部分参数
        if (preflightCors()) {
            return true;
        }
        // 发现是k_logout请求后 直接在这里登出
        if (requestUri.endsWith(AdapterConstants.K_LOGOUT)) {
            if (!resolveDeployment()) return true;
            handleLogout();
            return true;
            // 只是更新not-before属性
        } else if (requestUri.endsWith(AdapterConstants.K_PUSH_NOT_BEFORE)) {
            if (!resolveDeployment()) return true;
            handlePushNotBefore();
            return true;
            // 做简单测试
        } else if (requestUri.endsWith(AdapterConstants.K_TEST_AVAILABLE)) {
            if (!resolveDeployment()) return true;
            handleTestAvailable();
            return true;
            // TODO
        } else if (requestUri.endsWith(AdapterConstants.K_JWKS)) {
            if (!resolveDeployment()) return true;
            handleJwksRequest();
            return true;
        }
        return false;
    }

    /**
     * 处理跨域请求
     *
     * @return
     */
    public boolean preflightCors() {
        // don't need to resolve deployment on cors requests.  Just need to know local cors config.
        KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);
        if (!deployment.isCors()) return false;
        log.debugv("checkCorsPreflight {0}", facade.getRequest().getURI());
        if (!facade.getRequest().getMethod().equalsIgnoreCase("OPTIONS")) {
            return false;
        }
        String origin = facade.getRequest().getHeader(CorsHeaders.ORIGIN);
        if (origin == null || origin.equals("null")) {
            log.debug("checkCorsPreflight: no origin header");
            return false;
        }
        log.debug("Preflight request returning");
        facade.getResponse().setStatus(200);
        facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");

        // 替换掉跨域配置
        String requestMethods = facade.getRequest().getHeader(CorsHeaders.ACCESS_CONTROL_REQUEST_METHOD);
        if (requestMethods != null) {
            if (deployment.getCorsAllowedMethods() != null) {
                requestMethods = deployment.getCorsAllowedMethods();
            }
            facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_METHODS, requestMethods);
        }
        String allowHeaders = facade.getRequest().getHeader(CorsHeaders.ACCESS_CONTROL_REQUEST_HEADERS);
        if (allowHeaders != null) {
            if (deployment.getCorsAllowedHeaders() != null) {
                allowHeaders = deployment.getCorsAllowedHeaders();
            }
            facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_ALLOW_HEADERS, allowHeaders);
        }
        if (deployment.getCorsMaxAge() > -1) {
            facade.getResponse().setHeader(CorsHeaders.ACCESS_CONTROL_MAX_AGE, Integer.toString(deployment.getCorsMaxAge()));
        }
        return true;
    }

    /**
     * 在请求到达下游前 直接触发logout
     */
    protected void handleLogout() {
        if (log.isTraceEnabled()) {
            log.trace("K_LOGOUT sent");
        }
        try {
            JWSInput token = verifyAdminRequest();
            // token校验失败 直接返回   校验token的时候有一个公钥
            if (token == null) {
                return;
            }
            LogoutAction action = JsonSerialization.readValue(token.getContent(), LogoutAction.class);

            // 认证失败无法完成登出动作
            if (!validateAction(action)) return;

            // 执行登出操作  将会话从manager移除
            if (action.getAdapterSessionIds() != null) {
                userSessionManagement.logoutHttpSessions(action.getAdapterSessionIds());
            } else {
                // 让所有会话失效
                log.debugf("logout of all sessions for application '%s'", action.getResource());
                if (action.getNotBefore() > deployment.getNotBefore()) {
                    deployment.updateNotBefore(action.getNotBefore());
                }
                userSessionManagement.logoutAll();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    protected void handlePushNotBefore() {
        if (log.isTraceEnabled()) {
            log.trace("K_PUSH_NOT_BEFORE sent");
        }
        try {
            JWSInput token = verifyAdminRequest();
            if (token == null) {
                return;
            }
            PushNotBeforeAction action = JsonSerialization.readValue(token.getContent(), PushNotBeforeAction.class);
            if (!validateAction(action)) return;
            deployment.updateNotBefore(action.getNotBefore());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected void handleTestAvailable() {
        if (log.isTraceEnabled()) {
            log.trace("K_TEST_AVAILABLE sent");
        }
        try {
            JWSInput token = verifyAdminRequest();
            if (token == null) {
                return;
            }
            TestAvailabilityAction action = JsonSerialization.readValue(token.getContent(), TestAvailabilityAction.class);
            validateAction(action);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 从请求上剥离出 JWT
     *
     * @return
     * @throws Exception
     */
    protected JWSInput verifyAdminRequest() throws Exception {
        if (!facade.getRequest().isSecure() && deployment.getSslRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            log.warn("SSL is required for adapter admin action");
            facade.getResponse().sendError(403, "ssl required");
            return null;
        }

        // 请求体是一个token
        String token = StreamUtil.readString(facade.getRequest().getInputStream());
        if (token == null) {
            log.warn("admin request failed, no token");
            facade.getResponse().sendError(403, "no token");
            return null;
        }

        try {
            // Check just signature. Other things checked in validateAction
            TokenVerifier tokenVerifier = AdapterTokenVerifier.createVerifier(token, deployment, false, JsonWebToken.class);
            tokenVerifier.verify();
            return new JWSInput(token);
        } catch (VerificationException ignore) {
            log.warn("admin request failed, unable to verify token: " + ignore.getMessage());
            if (log.isDebugEnabled()) {
                log.debug(ignore.getMessage(), ignore);
            }

            facade.getResponse().sendError(403, "token failed verification");
            return null;
        }
    }


    /**
     * 验证收到的登出逻辑是否有效
     *
     * @param action
     * @return
     */
    protected boolean validateAction(AdminAction action) {
        if (!action.validate()) {
            log.warn("admin request failed, not validated" + action.getAction());
            facade.getResponse().sendError(400, "Not validated");
            return false;
        }

        // 每个指令有一个超时时间 超过该时间 指令被认为无效
        if (action.isExpired()) {
            log.warn("admin request failed, expired token");
            facade.getResponse().sendError(400, "Expired token");
            return false;
        }

        // 资源不匹配
        if (!deployment.getResourceName().equals(action.getResource())) {
            log.warn("Resource name does not match");
            facade.getResponse().sendError(400, "Resource name does not match");
            return false;

        }
        return true;
    }

    protected void handleJwksRequest() {
        try {
            JSONWebKeySet jwks = new JSONWebKeySet();
            ClientCredentialsProvider clientCredentialsProvider = deployment.getClientAuthenticator();

            // For now, just get signature key from JWT provider. We can add more if we support encryption etc.
            if (clientCredentialsProvider instanceof JWTClientCredentialsProvider) {
                PublicKey publicKey = ((JWTClientCredentialsProvider) clientCredentialsProvider).getPublicKey();
                JWK jwk = JWKBuilder.create().rs256(publicKey);
                jwks.setKeys(new JWK[]{jwk});
            } else {
                jwks.setKeys(new JWK[]{});
            }

            facade.getResponse().setStatus(200);
            facade.getResponse().setHeader("Content-Type", "application/json");
            JsonSerialization.writeValueToStream(facade.getResponse().getOutputStream(), jwks);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
