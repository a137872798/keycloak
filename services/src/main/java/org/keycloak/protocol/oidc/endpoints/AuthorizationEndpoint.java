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

package org.keycloak.protocol.oidc.endpoints;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.locale.LocaleSelectorProvider;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequestParserProcessor;
import org.keycloak.protocol.oidc.utils.OIDCRedirectUriBuilder;
import org.keycloak.protocol.oidc.utils.OIDCResponseMode;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.DefaultClientPolicyManager;
import org.keycloak.services.clientpolicy.context.AuthorizationRequestContext;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.TokenUtil;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * 基于OIDC协议的认证对象
 * keycloak作为服务端 暴露实现oidc协议相关的接口
 */
public class AuthorizationEndpoint extends AuthorizationEndpointBase {

    private static final Logger logger = Logger.getLogger(AuthorizationEndpoint.class);

    public static final String CODE_AUTH_TYPE = "code";

    /**
     * Prefix used to store additional HTTP GET params from original client request into {@link AuthenticationSessionModel} note to be available later in Authenticators, RequiredActions etc. Prefix is used to
     * prevent collisions with internally used notes.
     *
     * @see AuthenticationSessionModel#getClientNote(String)
     */
    public static final String LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX = "client_request_param_";

    // https://tools.ietf.org/html/rfc7636#section-4.2
    private static final Pattern VALID_CODE_CHALLENGE_PATTERN = Pattern.compile("^[0-9a-zA-Z\\-\\.~_]+$");

    private enum Action {
        REGISTER, CODE, FORGOT_CREDENTIALS
    }

    /**
     * 创建客户端
     */
    private ClientModel client;
    private AuthenticationSessionModel authenticationSession;

    private Action action;
    private OIDCResponseType parsedResponseType;
    private OIDCResponseMode parsedResponseMode;

    private AuthorizationEndpointRequest request;
    private String redirectUri;

    public AuthorizationEndpoint(RealmModel realm, EventBuilder event) {
        super(realm, event);
        event.event(EventType.LOGIN);
    }

    // 下面2个方法对应 /auth接口  也就是oidc的认证接口

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response buildPost() {
        logger.trace("Processing @POST request");
        return process(httpRequest.getDecodedFormParameters());
    }
    @GET
    public Response buildGet() {
        logger.trace("Processing @GET request");
        return process(session.getContext().getUri().getQueryParameters());
    }

    /**
     * 处理认证请求
     * @param params  从req中解析出的表单参数
     * @return
     */
    private Response process(MultivaluedMap<String, String> params) {
        String clientId = AuthorizationEndpointRequestParserProcessor.getClientId(event, session, params);

        checkSsl();
        checkRealm();
        checkClient(clientId);

        // 简单来说就是将params的参数转移到req中
        request = AuthorizationEndpointRequestParserProcessor.parseRequest(event, session, client, params);

        // 检验重定向地址有效性
        checkRedirectUri();
        // 检查响应类型
        Response errorResponse = checkResponseType();
        // 代表已经出现异常了
        if (errorResponse != null) {
            return errorResponse;
        }

        // req解析出错
        if (request.getInvalidRequestMessage() != null) {
            event.error(Errors.INVALID_REQUEST);
            // 设置异常参数 调用req中指定的redirect_uri
            return redirectErrorToClient(parsedResponseMode, Errors.INVALID_REQUEST, request.getInvalidRequestMessage());
        }

        // 请求的scope中不包含openid  要打印日志
        if (!TokenUtil.isOIDCRequest(request.getScope())) {
            ServicesLogger.LOGGER.oidcScopeMissing();
        }

        // 携带了错误的scope
        if (!TokenManager.isValidScope(request.getScope(), client)) {
            ServicesLogger.LOGGER.invalidParameter(OIDCLoginProtocol.SCOPE_PARAM);
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(parsedResponseMode, OAuthErrorException.INVALID_SCOPE, "Invalid scopes: " + request.getScope());
        }

        // 检查请求参数是否满足oidc协议
        errorResponse = checkOIDCParams();
        if (errorResponse != null) {
            return errorResponse;
        }

        // https://tools.ietf.org/html/rfc7636#section-4
        // PKCE是Oauth2的拓展 主要是针对public类型的client code可能被拦截 导致被恶意访问   解决办法就是在授权时额外传入 code_challenge+code_challenge_method2个参数
        // 而在验证通过获取资源时 额外传入code_verifier
        errorResponse = checkPKCEParams();
        if (errorResponse != null) {
            return errorResponse;
        }

        try {
            // 生成一个context对象 并交给client_policy
            // TODO 先忽略 clientPolicy
            session.clientPolicy().triggerOnEvent(new AuthorizationRequestContext(parsedResponseType, request, redirectUri, params));
        } catch (ClientPolicyException cpe) {
            return redirectErrorToClient(parsedResponseMode, cpe.getError(), cpe.getErrorDetail());
        }

        // 认证会话  在认证过程中起作用的会话
        authenticationSession = createAuthenticationSession(client, request.getState());
        // 把req信息填充到认证会话中
        updateAuthenticationSession();

        // So back button doesn't work 设置响应头
        CacheControlUtil.noBackButtonCacheControlHeader();
        switch (action) {
            case REGISTER:
                return buildRegister();
            case FORGOT_CREDENTIALS:
                return buildForgotCredential();
            case CODE:
                // auth 走这条分支
                return buildAuthorizationCodeAuthorizationResponse();
        }

        throw new RuntimeException("Unknown action " + action);
    }

    public AuthorizationEndpoint register() {
        event.event(EventType.REGISTER);
        action = Action.REGISTER;

        if (!realm.isRegistrationAllowed()) {
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.REGISTRATION_NOT_ALLOWED);
        }

        return this;
    }

    public AuthorizationEndpoint forgotCredentials() {
        event.event(EventType.RESET_PASSWORD);
        action = Action.FORGOT_CREDENTIALS;

        if (!realm.isResetPasswordAllowed()) {
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.RESET_CREDENTIAL_NOT_ALLOWED);
        }

        return this;
    }

    /**
     * 检查客户端id 是否有效
     * @param clientId
     */
    private void checkClient(String clientId) {
        if (clientId == null) {
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.MISSING_PARAMETER, OIDCLoginProtocol.CLIENT_ID_PARAM);
        }

        event.client(clientId);

        client = realm.getClientByClientId(clientId);
        if (client == null) {
            event.error(Errors.CLIENT_NOT_FOUND);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.CLIENT_NOT_FOUND);
        }

        // client已经被禁用
        if (!client.isEnabled()) {
            event.error(Errors.CLIENT_DISABLED);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.CLIENT_DISABLED);
        }

        // bearerOnly的client不允许通过该对象进行认证
        if (client.isBearerOnly()) {
            event.error(Errors.NOT_ALLOWED);
            throw new ErrorPageException(session, authenticationSession, Response.Status.FORBIDDEN, Messages.BEARER_ONLY);
        }

        // 只支持处理oidc协议
        String protocol = client.getProtocol();
        if (protocol == null) {
            logger.warnf("Client '%s' doesn't have protocol set. Fallback to openid-connect. Please fix client configuration", clientId);
            protocol = OIDCLoginProtocol.LOGIN_PROTOCOL;
        }
        if (!protocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            event.error(Errors.INVALID_CLIENT);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, "Wrong client protocol.");
        }

        session.getContext().setClient(client);
    }

    /**
     * 检验返回值类型
     * @return
     */
    private Response checkResponseType() {
        String responseType = request.getResponseType();

        if (responseType == null) {
            ServicesLogger.LOGGER.missingParameter(OAuth2Constants.RESPONSE_TYPE);
            event.error(Errors.INVALID_REQUEST);
            // 要求请求参数必须携带 response_type
            return redirectErrorToClient(OIDCResponseMode.QUERY, OAuthErrorException.INVALID_REQUEST, "Missing parameter: response_type");
        }

        event.detail(Details.RESPONSE_TYPE, responseType);

        try {
            parsedResponseType = OIDCResponseType.parse(responseType);
            // 当action还未设置时 默认使用Code
            if (action == null) {
                action = Action.CODE;
            }
        } catch (IllegalArgumentException iae) {
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(OIDCResponseMode.QUERY, OAuthErrorException.UNSUPPORTED_RESPONSE_TYPE, null);
        }

        // 解析响应模式
        OIDCResponseMode parsedResponseMode = null;
        try {
            parsedResponseMode = OIDCResponseMode.parse(request.getResponseMode(), parsedResponseType);
        } catch (IllegalArgumentException iae) {
            ServicesLogger.LOGGER.invalidParameter(OIDCLoginProtocol.RESPONSE_MODE_PARAM);
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(OIDCResponseMode.QUERY, OAuthErrorException.INVALID_REQUEST, "Invalid parameter: response_mode");
        }

        event.detail(Details.RESPONSE_MODE, parsedResponseMode.toString().toLowerCase());

        // Disallowed by OIDC specs
        if (parsedResponseType.isImplicitOrHybridFlow() && parsedResponseMode == OIDCResponseMode.QUERY) {
            ServicesLogger.LOGGER.responseModeQueryNotAllowed();
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(OIDCResponseMode.QUERY, OAuthErrorException.INVALID_REQUEST, "Response_mode 'query' not allowed for implicit or hybrid flow");
        }

        // 代表标准流被禁用
        if ((parsedResponseType.hasResponseType(OIDCResponseType.CODE) || parsedResponseType.hasResponseType(OIDCResponseType.NONE)) && !client.isStandardFlowEnabled()) {
            ServicesLogger.LOGGER.flowNotAllowed("Standard");
            event.error(Errors.NOT_ALLOWED);
            return redirectErrorToClient(parsedResponseMode, OAuthErrorException.UNAUTHORIZED_CLIENT, "Client is not allowed to initiate browser login with given response_type. Standard flow is disabled for the client.");
        }

        if (parsedResponseType.isImplicitOrHybridFlow() && !client.isImplicitFlowEnabled()) {
            ServicesLogger.LOGGER.flowNotAllowed("Implicit");
            event.error(Errors.NOT_ALLOWED);
            return redirectErrorToClient(parsedResponseMode, OAuthErrorException.UNAUTHORIZED_CLIENT, "Client is not allowed to initiate browser login with given response_type. Implicit flow is disabled for the client.");
        }

        this.parsedResponseMode = parsedResponseMode;

        return null;
    }

    /**
     * 检查OIDC参数
     * @return
     */
    private Response checkOIDCParams() {
        // If request is not OIDC request, but pure OAuth2 request and response_type is just 'token', then 'nonce' is not mandatory
        // 如果是oidc请求 scope中会携带openid
        boolean isOIDCRequest = TokenUtil.isOIDCRequest(request.getScope());
        // response是token类型的话  是正常的
        if (!isOIDCRequest && parsedResponseType.toString().equals(OIDCResponseType.TOKEN)) {
            return null;
        }

        // 这种类型必须要Nonce
        if (parsedResponseType.isImplicitOrHybridFlow() && request.getNonce() == null) {
            ServicesLogger.LOGGER.missingParameter(OIDCLoginProtocol.NONCE_PARAM);
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(parsedResponseMode, OAuthErrorException.INVALID_REQUEST, "Missing parameter: nonce");
        }

        return null;
    }

    // https://tools.ietf.org/html/rfc7636#section-4
    private Response checkPKCEParams() {
        // PKCE模式下必须设置中2个参数
        String codeChallenge = request.getCodeChallenge();
        String codeChallengeMethod = request.getCodeChallengeMethod();

        // PKCE not adopted to OAuth2 Implicit Grant and OIDC Implicit Flow,
        // adopted to OAuth2 Authorization Code Grant and OIDC Authorization Code Flow, Hybrid Flow
        // Namely, flows using authorization code.
        // 隐式类型 不需要处理
        if (parsedResponseType.isImplicitFlow()) return null;

        String pkceCodeChallengeMethod = OIDCAdvancedConfigWrapper.fromClientModel(client).getPkceCodeChallengeMethod();
        Response response = null;
        if (pkceCodeChallengeMethod != null && !pkceCodeChallengeMethod.isEmpty()) {
            response = checkParamsForPkceEnforcedClient(codeChallengeMethod, pkceCodeChallengeMethod, codeChallenge);
        } else {
            // if PKCE Activation is OFF, execute the codes implemented in KEYCLOAK-2604
            response = checkParamsForPkceNotEnforcedClient(codeChallengeMethod, pkceCodeChallengeMethod, codeChallenge);
        }
        return response;
    }

    // https://tools.ietf.org/html/rfc7636#section-4
    private boolean isValidPkceCodeChallenge(String codeChallenge) {
        if (codeChallenge.length() < OIDCLoginProtocol.PKCE_CODE_CHALLENGE_MIN_LENGTH) {
            logger.debugf("PKCE codeChallenge length under lower limit , codeChallenge = %s", codeChallenge);
            return false;
        }
        if (codeChallenge.length() > OIDCLoginProtocol.PKCE_CODE_CHALLENGE_MAX_LENGTH) {
            logger.debugf("PKCE codeChallenge length over upper limit , codeChallenge = %s", codeChallenge);
            return false;
        }
        Matcher m = VALID_CODE_CHALLENGE_PATTERN.matcher(codeChallenge);
        return m.matches();
    }

    private Response checkParamsForPkceEnforcedClient(String codeChallengeMethod, String pkceCodeChallengeMethod, String codeChallenge) {
        // check whether code challenge method is specified
        if (codeChallengeMethod == null) {
            logger.info("PKCE enforced Client without code challenge method.");
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(parsedResponseMode, OAuthErrorException.INVALID_REQUEST, "Missing parameter: code_challenge_method");
        }
        // check whether specified code challenge method is configured one in advance
        if (!codeChallengeMethod.equals(pkceCodeChallengeMethod)) {
            logger.info("PKCE enforced Client code challenge method is not configured one.");
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(parsedResponseMode, OAuthErrorException.INVALID_REQUEST, "Invalid parameter: code challenge method is not configured one");
        }
        // check whether code challenge is specified
        if (codeChallenge == null) {
            logger.info("PKCE supporting Client without code challenge");
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(parsedResponseMode, OAuthErrorException.INVALID_REQUEST, "Missing parameter: code_challenge");
        }
        // check whether code challenge is formatted along with the PKCE specification
        if (!isValidPkceCodeChallenge(codeChallenge)) {
            logger.infof("PKCE supporting Client with invalid code challenge specified in PKCE, codeChallenge = %s", codeChallenge);
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(parsedResponseMode, OAuthErrorException.INVALID_REQUEST, "Invalid parameter: code_challenge");
        }
        return null;
    }

    private Response checkParamsForPkceNotEnforcedClient(String codeChallengeMethod, String pkceCodeChallengeMethod, String codeChallenge) {
        if (codeChallenge == null && codeChallengeMethod != null) {
            logger.info("PKCE supporting Client without code challenge");
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(parsedResponseMode, OAuthErrorException.INVALID_REQUEST, "Missing parameter: code_challenge");
        }

        // based on code_challenge value decide whether this client(RP) supports PKCE
        if (codeChallenge == null) {
            logger.debug("PKCE non-supporting Client");
            return null;
        }

        if (codeChallengeMethod != null) {
            // https://tools.ietf.org/html/rfc7636#section-4.2
            // plain or S256
            if (!codeChallengeMethod.equals(OIDCLoginProtocol.PKCE_METHOD_S256) && !codeChallengeMethod.equals(OIDCLoginProtocol.PKCE_METHOD_PLAIN)) {
                logger.infof("PKCE supporting Client with invalid code challenge method not specified in PKCE, codeChallengeMethod = %s", codeChallengeMethod);
                event.error(Errors.INVALID_REQUEST);
                return redirectErrorToClient(parsedResponseMode, OAuthErrorException.INVALID_REQUEST, "Invalid parameter: code_challenge_method");
            }
        } else {
            // https://tools.ietf.org/html/rfc7636#section-4.3
            // default code_challenge_method is plane
            codeChallengeMethod = OIDCLoginProtocol.PKCE_METHOD_PLAIN;
        }

        if (!isValidPkceCodeChallenge(codeChallenge)) {
            logger.infof("PKCE supporting Client with invalid code challenge specified in PKCE, codeChallenge = %s", codeChallenge);
            event.error(Errors.INVALID_REQUEST);
            return redirectErrorToClient(parsedResponseMode, OAuthErrorException.INVALID_REQUEST, "Invalid parameter: code_challenge");
        }

        return null;
    }

    private Response redirectErrorToClient(OIDCResponseMode responseMode, String error, String errorDescription) {
        // 将异常消息作为参数
        OIDCRedirectUriBuilder errorResponseBuilder = OIDCRedirectUriBuilder.fromUri(redirectUri, responseMode)
                .addParam(OAuth2Constants.ERROR, error);

        if (errorDescription != null) {
            errorResponseBuilder.addParam(OAuth2Constants.ERROR_DESCRIPTION, errorDescription);
        }

        if (request.getState() != null) {
            errorResponseBuilder.addParam(OAuth2Constants.STATE, request.getState());
        }

        return errorResponseBuilder.build();
    }

    /**
     * 检查重定向地址
     */
    private void checkRedirectUri() {
        String redirectUriParam = request.getRedirectUriParam();
        // 要求scope中携带  openid
        boolean isOIDCRequest = TokenUtil.isOIDCRequest(request.getScope());

        event.detail(Details.REDIRECT_URI, redirectUriParam);

        // redirect_uri parameter is required per OpenID Connect, but optional per OAuth2
        redirectUri = RedirectUtils.verifyRedirectUri(session, redirectUriParam, client, isOIDCRequest);
        if (redirectUri == null) {
            event.error(Errors.INVALID_REDIRECT_URI);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.INVALID_PARAMETER, OIDCLoginProtocol.REDIRECT_URI_PARAM);
        }
    }


    /**
     * 对子认证会话做一些属性填充
     */
    private void updateAuthenticationSession() {
        authenticationSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authenticationSession.setRedirectUri(redirectUri);
        authenticationSession.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
        authenticationSession.setClientNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM, request.getResponseType());
        authenticationSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, request.getRedirectUriParam());
        authenticationSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));

        if (request.getState() != null) authenticationSession.setClientNote(OIDCLoginProtocol.STATE_PARAM, request.getState());
        if (request.getNonce() != null) authenticationSession.setClientNote(OIDCLoginProtocol.NONCE_PARAM, request.getNonce());
        if (request.getMaxAge() != null) authenticationSession.setClientNote(OIDCLoginProtocol.MAX_AGE_PARAM, String.valueOf(request.getMaxAge()));
        if (request.getScope() != null) authenticationSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, request.getScope());
        if (request.getLoginHint() != null) authenticationSession.setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, request.getLoginHint());
        if (request.getPrompt() != null) authenticationSession.setClientNote(OIDCLoginProtocol.PROMPT_PARAM, request.getPrompt());
        if (request.getIdpHint() != null) authenticationSession.setClientNote(AdapterConstants.KC_IDP_HINT, request.getIdpHint());
        if (request.getAction() != null) authenticationSession.setClientNote(Constants.KC_ACTION, request.getAction());
        if (request.getResponseMode() != null) authenticationSession.setClientNote(OIDCLoginProtocol.RESPONSE_MODE_PARAM, request.getResponseMode());
        if (request.getClaims()!= null) authenticationSession.setClientNote(OIDCLoginProtocol.CLAIMS_PARAM, request.getClaims());
        if (request.getAcr() != null) authenticationSession.setClientNote(OIDCLoginProtocol.ACR_PARAM, request.getAcr());
        if (request.getDisplay() != null) authenticationSession.setAuthNote(OAuth2Constants.DISPLAY, request.getDisplay());
        if (request.getUiLocales() != null) authenticationSession.setAuthNote(LocaleSelectorProvider.CLIENT_REQUEST_LOCALE, request.getUiLocales());

        // https://tools.ietf.org/html/rfc7636#section-4
        if (request.getCodeChallenge() != null) authenticationSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, request.getCodeChallenge());
        if (request.getCodeChallengeMethod() != null) authenticationSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM, request.getCodeChallengeMethod());

        if (request.getAdditionalReqParams() != null) {
            for (String paramName : request.getAdditionalReqParams().keySet()) {
                authenticationSession.setClientNote(LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + paramName, request.getAdditionalReqParams().get(paramName));
            }
        }
    }


    /**
     * 处理认证请求
     * @return
     */
    private Response buildAuthorizationCodeAuthorizationResponse() {
        this.event.event(EventType.LOGIN);
        // 设置认证类型为授权码认证
        authenticationSession.setAuthNote(Details.AUTH_TYPE, CODE_AUTH_TYPE);

        // prompt 用来指示授权服务器是否引导EU重新认证和同意授权  是一个可选和多选的参数
        // - none 代表如果用户没有预先授权/或登录  直接返回错误
        // - login 提示用户去登录
        // - consent 提示用户进行授权
        // - select_account 针对多个账户的情况可以进行选择
        return handleBrowserAuthenticationRequest(authenticationSession, new OIDCLoginProtocol(session, realm, session.getContext().getUri(), headers, event), TokenUtil.hasPrompt(request.getPrompt(), OIDCLoginProtocol.PROMPT_VALUE_NONE), false);
    }

    /**
     * 本次需要进行的是注册
     * @return
     */
    private Response buildRegister() {
        // 清理之前的cookie信息 相当于上个人的登录痕迹被清理了
        authManager.expireIdentityCookie(realm, session.getContext().getUri(), clientConnection);

        // 返回注册用的flow
        AuthenticationFlowModel flow = realm.getRegistrationFlow();
        String flowId = flow.getId();

        AuthenticationProcessor processor = createProcessor(authenticationSession, flowId, LoginActionsService.REGISTRATION_PATH);
        authenticationSession.setClientNote(APP_INITIATED_FLOW, LoginActionsService.REGISTRATION_PATH);

        return processor.authenticate();
    }

    /**
     * 忘记密码 逻辑类似 除了获取的flow不同
     * @return
     */
    private Response buildForgotCredential() {
        authManager.expireIdentityCookie(realm, session.getContext().getUri(), clientConnection);

        AuthenticationFlowModel flow = realm.getResetCredentialsFlow();
        String flowId = flow.getId();

        AuthenticationProcessor processor = createProcessor(authenticationSession, flowId, LoginActionsService.RESET_CREDENTIALS_PATH);
        authenticationSession.setClientNote(APP_INITIATED_FLOW, LoginActionsService.RESET_CREDENTIALS_PATH);

        return processor.authenticate();
    }

}
