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

package org.keycloak.protocol.oidc;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenCategory;
import org.keycloak.TokenVerifier;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.HashProvider;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.migration.migrators.MigrationUtils;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.TokenRevocationStoreProvider;
import org.keycloak.models.UserConsentModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenResponseMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.LogoutToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionCrossDCManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.services.util.MtlsHoKTokenUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.TokenUtil;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import static org.keycloak.representations.IDToken.NONCE;
import static org.keycloak.representations.IDToken.PHONE_NUMBER;

/**
 * Stateless object that creates tokens and manages oauth access codes
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * token管理器 包含创建和验证逻辑
 */
public class TokenManager {
    private static final Logger logger = Logger.getLogger(TokenManager.class);
    private static final String JWT = "JWT";

    /**
     * token验证器
     */
    public static class TokenValidation {

        // 提供用户信息的对象
        public final UserModel user;
        // 用户会话相关的对象
        public final UserSessionModel userSession;
        // 维护client会话相关的
        public final ClientSessionContext clientSessionCtx;
        // 在原有token上拓展了很多字段
        public final AccessToken newToken;

        public TokenValidation(UserModel user, UserSessionModel userSession, ClientSessionContext clientSessionCtx, AccessToken newToken) {
            this.user = user;
            this.userSession = userSession;
            this.clientSessionCtx = clientSessionCtx;
            this.newToken = newToken;
        }
    }

    /**
     * 对token进行验证  不同种类的token 都使用这个方法
     * @param session
     * @param uriInfo  描述请求url信息
     * @param connection  描述local/remote地址信息
     * @param realm    领域信息
     * @param oldToken  外表与access一致
     * @param headers   请求头
     * @return
     * @throws OAuthErrorException
     */
    public TokenValidation validateToken(KeycloakSession session, UriInfo uriInfo, ClientConnection connection, RealmModel realm,
                                         RefreshToken oldToken, HttpHeaders headers) throws OAuthErrorException {
        UserSessionModel userSession = null;

        // 离线token
        boolean offline = TokenUtil.TOKEN_TYPE_OFFLINE.equals(oldToken.getType());

        // TODO
        if (offline) {

            UserSessionManager sessionManager = new UserSessionManager(session);
            userSession = sessionManager.findOfflineUserSession(realm, oldToken.getSessionState());
            if (userSession != null) {

                // Revoke timeouted offline userSession
                if (!AuthenticationManager.isOfflineSessionValid(realm, userSession)) {
                    sessionManager.revokeOfflineUserSession(userSession);
                    throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Offline session not active", "Offline session not active");
                }

            } else {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Offline user session not found", "Offline user session not found");
            }
        } else {
            // Find userSession regularly for online tokens
            userSession = session.sessions().getUserSession(realm, oldToken.getSessionState());

            // 检查会话是否还有效  会话也有过期时间
            if (!AuthenticationManager.isSessionValid(realm, userSession)) {
                // 定期刷新token 也顺带检查了会话的有效性  当发现会话失效时 触发后端登出
                AuthenticationManager.backchannelLogout(session, realm, userSession, uriInfo, connection, headers, true);
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Session not active", "Session not active");
            }
        }

        // 会话的用户信息无效 或者无用户信息
        UserModel user = userSession.getUser();
        if (user == null) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token", "Unknown user");
        }

        if (!user.isEnabled()) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "User disabled", "User disabled");
        }

        // 用户信息发生变化  token失效
        if (oldToken.getIssuedAt() + 1 < userSession.getStarted()) {
            logger.debug("Refresh toked issued before the user session started");
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Refresh toked issued before the user session started");
        }


        ClientModel client = session.getContext().getClient();
        AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());

        // Can theoretically happen in cross-dc environment. Try to see if userSession with our client is available in remoteCache
        // TODO 先忽略 DC
        if (clientSession == null) {
            userSession = new UserSessionCrossDCManager(session).getUserSessionWithClient(realm, userSession.getId(), offline, client.getId());
            if (userSession != null) {
                clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
            } else {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Session doesn't have required client", "Session doesn't have required client");
            }
        }

        // client id 不匹配
        if (!client.getClientId().equals(oldToken.getIssuedFor())) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Unmatching clients", "Unmatching clients");
        }

        try {
            // 也是要求token记录的是最新值
            TokenVerifier.createWithoutSignature(oldToken)
                    .withChecks(NotBeforeCheck.forModel(client), NotBeforeCheck.forModel(session, realm, user))
                    .verify();
        } catch (VerificationException e) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Stale token");
        }

        // Setup clientScopes from refresh token to the context
        String oldTokenScope = oldToken.getScope();

        // Case when offline token is migrated from previous version
        // TODO
        if (oldTokenScope == null && userSession.isOffline()) {
            logger.debugf("Migrating offline token of user '%s' for client '%s' of realm '%s'", user.getUsername(), client.getClientId(), realm.getName());
            MigrationUtils.migrateOldOfflineToken(session, realm, client, user);
            oldTokenScope = OAuth2Constants.OFFLINE_ACCESS;
        }

        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(clientSession, oldTokenScope, session);

        // Check user didn't revoke granted consent
        // 验证token上的scope  此时client能否提供
        if (!verifyConsentStillAvailable(session, user, client, clientSessionCtx.getClientScopesStream())) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_SCOPE, "Client no longer has requested consent from user");
        }

        clientSessionCtx.setAttribute(OIDCLoginProtocol.NONCE_PARAM, oldToken.getNonce());

        // recreate token.
        // 创建一个新的accessToken
        AccessToken newToken = createClientAccessToken(session, realm, client, user, userSession, clientSessionCtx);

        return new TokenValidation(user, userSession, clientSessionCtx, newToken);
    }

    /**
     * Checks if the token is valid. Intended usage is for token introspection endpoints as the session last refresh
     * is updated if the token was valid. This is used to keep the session alive when long lived tokens are used.
     *
     * @param session
     * @param realm
     * @param token
     * @return
     * @throws OAuthErrorException
     */
    public boolean checkTokenValidForIntrospection(KeycloakSession session, RealmModel realm, AccessToken token) throws OAuthErrorException {
        ClientModel client = realm.getClientByClientId(token.getIssuedFor());
        if (client == null || !client.isEnabled()) {
            return false;
        }

        try {
            TokenVerifier.createWithoutSignature(token)
                    .withChecks(NotBeforeCheck.forModel(client), TokenVerifier.IS_ACTIVE)
                    .verify();
        } catch (VerificationException e) {
            return false;
        }

        TokenRevocationStoreProvider revocationStore = session.getProvider(TokenRevocationStoreProvider.class);
        if (revocationStore.isRevoked(token.getId())) {
            return false;
        }

        boolean valid = false;

        // Tokens without sessions are considered valid. Signature check and revocation check are sufficient checks for them
        if (token.getSessionState() == null) {
            UserModel user = lookupUserFromStatelessToken(session, realm, token);
            valid = isUserValid(session, realm, token, user);
        } else {

            UserSessionModel userSession = new UserSessionCrossDCManager(session).getUserSessionWithClient(realm, token.getSessionState(), false, client.getId());

            if (AuthenticationManager.isSessionValid(realm, userSession)) {
                valid = isUserValid(session, realm, token, userSession.getUser());
            } else {
                userSession = new UserSessionCrossDCManager(session).getUserSessionWithClient(realm, token.getSessionState(), true, client.getId());
                if (AuthenticationManager.isOfflineSessionValid(realm, userSession)) {
                    valid = isUserValid(session, realm, token, userSession.getUser());
                }
            }

            if (valid && (token.getIssuedAt() + 1 < userSession.getStarted())) {
                valid = false;
            }

            if (valid) {
                userSession.setLastSessionRefresh(Time.currentTime());
            }
        }

        return valid;
    }

    private boolean isUserValid(KeycloakSession session, RealmModel realm, AccessToken token, UserModel user) {
        if (user == null) {
            return false;
        }
        if (!user.isEnabled()) {
            return false;
        }
        try {
            TokenVerifier.createWithoutSignature(token)
                    .withChecks(NotBeforeCheck.forModel(session ,realm, user))
                    .verify();
        } catch (VerificationException e) {
            return false;
        }
        return true;
    }

    /**
     * Lookup user from the "stateless" token. Stateless token is the token without sessionState filled (token doesn't belong to any userSession)
     * 针对无会话的token  解析出用户信息
     */
    public static UserModel lookupUserFromStatelessToken(KeycloakSession session, RealmModel realm, AccessToken token) {
        // Try to lookup user based on "sub" claim. It should work for most cases with some rare exceptions (EG. OIDC "pairwise" subjects)
        UserModel user = session.users().getUserById(realm, token.getSubject());
        if (user != null) {
            return user;
        }

        // Fallback to lookup user based on username (preferred_username claim)
        if (token.getPreferredUsername() != null) {
            user = session.users().getUserByUsername(realm, token.getPreferredUsername());
            if (user != null) {
                return user;
            }
        }

        return user;
    }


    /**
     * 刷新token
     * @param session
     * @param uriInfo
     * @param connection
     * @param realm
     * @param authorizedClient
     * @param encodedRefreshToken  之前用code兑换token时一并返回的 refreshToken 需要使用他刷新token
     * @param event
     * @param headers
     * @param request
     * @return
     * @throws OAuthErrorException
     */
    public RefreshResult refreshAccessToken(KeycloakSession session, UriInfo uriInfo, ClientConnection connection, RealmModel realm, ClientModel authorizedClient,
                                            String encodedRefreshToken, EventBuilder event, HttpHeaders headers, HttpRequest request) throws OAuthErrorException {

        // 先验证 refresh_token 有效性   同时还要校验是否过期
        RefreshToken refreshToken = verifyRefreshToken(session, realm, authorizedClient, request, encodedRefreshToken, true);

        event.user(refreshToken.getSubject()).session(refreshToken.getSessionState())
                .detail(Details.REFRESH_TOKEN_ID, refreshToken.getId())
                .detail(Details.REFRESH_TOKEN_TYPE, refreshToken.getType());

        // 验证的同时 产生了一个新的accessToken   并且包装进一个TokenValidation中
        TokenValidation validation = validateToken(session, uriInfo, connection, realm, refreshToken, headers);
        AuthenticatedClientSessionModel clientSession = validation.clientSessionCtx.getClientSession();

        // validate authorizedClient is same as validated client
        if (!clientSession.getClient().getId().equals(authorizedClient.getId())) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token. Token client and authorized client don't match");
        }

        // 判断refresh token 是否超出了使用上线 或者已经过时   会抛出异常
        validateTokenReuse(session, realm, refreshToken, validation);

        int currentTime = Time.currentTime();
        // 刷新token 等用于续约会话
        clientSession.setTimestamp(currentTime);
        validation.userSession.setLastSessionRefresh(currentTime);

        if (refreshToken.getAuthorization() != null) {
            validation.newToken.setAuthorization(refreshToken.getAuthorization());
        }

        // 填充新的token 以及新的refresh token
        AccessTokenResponseBuilder responseBuilder = responseBuilder(realm, authorizedClient, event, session, validation.userSession, validation.clientSessionCtx)
                .accessToken(validation.newToken)
                .generateRefreshToken();

        if (validation.newToken.getAuthorization() != null) {
            responseBuilder.getRefreshToken().setAuthorization(validation.newToken.getAuthorization());
        }

        // KEYCLOAK-6771 Certificate Bound Token
        // https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-3.1
        // bind refreshed access and refresh token with Client Certificate
        // TODO
        AccessToken.CertConf certConf = refreshToken.getCertConf();
        if (certConf != null) {
            responseBuilder.getAccessToken().setCertConf(certConf);
            responseBuilder.getRefreshToken().setCertConf(certConf);
        }

        // 如果是OIDC协议 总要带上这个ID token
        String scopeParam = clientSession.getNote(OAuth2Constants.SCOPE);
        if (TokenUtil.isOIDCRequest(scopeParam)) {
            responseBuilder.generateIDToken();
        }

        AccessTokenResponse res = responseBuilder.build();

        return new RefreshResult(res, TokenUtil.TOKEN_TYPE_OFFLINE.equals(refreshToken.getType()));
    }

    /**
     * 验证token能否复用
     * @param session
     * @param realm
     * @param refreshToken
     * @param validation
     * @throws OAuthErrorException
     */
    private void validateTokenReuse(KeycloakSession session, RealmModel realm, RefreshToken refreshToken,
            TokenValidation validation) throws OAuthErrorException {

        // refresh token 需要被撤销
        if (realm.isRevokeRefreshToken()) {
            AuthenticatedClientSessionModel clientSession = validation.clientSessionCtx.getClientSession();

            int clusterStartupTime = session.getProvider(ClusterProvider.class).getClusterStartupTime();

            if (clientSession.getCurrentRefreshToken() != null &&
                    !refreshToken.getId().equals(clientSession.getCurrentRefreshToken()) &&
                    refreshToken.getIssuedAt() < clientSession.getTimestamp() &&
                    clusterStartupTime <= clientSession.getTimestamp()) {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Stale token");
            }

            // 设置client会话此时使用的 refresh token
            if (!refreshToken.getId().equals(clientSession.getCurrentRefreshToken())) {
                clientSession.setCurrentRefreshToken(refreshToken.getId());
                clientSession.setCurrentRefreshTokenUseCount(0);
            }

            // 刷新token有个使用次数上限
            int currentCount = clientSession.getCurrentRefreshTokenUseCount();
            if (currentCount > realm.getRefreshTokenMaxReuse()) {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Maximum allowed refresh token reuse exceeded",
                        "Maximum allowed refresh token reuse exceeded");
            }
            clientSession.setCurrentRefreshTokenUseCount(currentCount + 1);
        }
    }

    /**
     * 验证refresh token有效性
     * @param session
     * @param realm
     * @param client
     * @param request
     * @param encodedRefreshToken
     * @param checkExpiration
     * @return
     * @throws OAuthErrorException
     */
    public RefreshToken verifyRefreshToken(KeycloakSession session, RealmModel realm, ClientModel client, HttpRequest request, String encodedRefreshToken, boolean checkExpiration) throws OAuthErrorException {
        try {
            RefreshToken refreshToken = toRefreshToken(session, encodedRefreshToken);

            // TODO offline的先不管
            if (!(TokenUtil.TOKEN_TYPE_REFRESH.equals(refreshToken.getType()) || TokenUtil.TOKEN_TYPE_OFFLINE.equals(refreshToken.getType()))) {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token");
            }

            // 校验refresh token 是否过期
            if (checkExpiration) {
                try {
                    // 要求token新 并且未过期
                    TokenVerifier.createWithoutSignature(refreshToken)
                            .withChecks(NotBeforeCheck.forModel(realm), TokenVerifier.IS_ACTIVE)
                            .verify();
                } catch (VerificationException e) {
                    throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, e.getMessage());
                }
            }

            // client id 需要匹配
            if (!client.getClientId().equals(refreshToken.getIssuedFor())) {
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token. Token client and authorized client don't match");
            }

            // KEYCLOAK-6771 Certificate Bound Token
            // TODO
            if (OIDCAdvancedConfigWrapper.fromClientModel(client).isUseMtlsHokToken()) {
                if (!MtlsHoKTokenUtil.verifyTokenBindingWithClientCertificate(refreshToken, request, session)) {
                    throw new OAuthErrorException(OAuthErrorException.UNAUTHORIZED_CLIENT, MtlsHoKTokenUtil.CERT_VERIFY_ERROR_DESC);
                }
            }

            return refreshToken;
        } catch (JWSInputException e) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token", e);
        }
    }

    /**
     * 转换成refresh token
     * @param session
     * @param encodedRefreshToken
     * @return
     * @throws JWSInputException
     * @throws OAuthErrorException
     */
    public RefreshToken toRefreshToken(KeycloakSession session, String encodedRefreshToken) throws JWSInputException, OAuthErrorException {
        RefreshToken refreshToken = session.tokens().decode(encodedRefreshToken, RefreshToken.class);
        if (refreshToken == null) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token");
        }
        return refreshToken;
    }

    public IDToken verifyIDToken(KeycloakSession session, RealmModel realm, String encodedIDToken) throws OAuthErrorException {
        IDToken idToken = session.tokens().decode(encodedIDToken, IDToken.class);
        try {
            TokenVerifier.createWithoutSignature(idToken)
                    .withChecks(NotBeforeCheck.forModel(realm), TokenVerifier.IS_ACTIVE)
                    .verify();
        } catch (VerificationException e) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, e.getMessage());
        }
        return idToken;
    }

    public IDToken verifyIDTokenSignature(KeycloakSession session, String encodedIDToken) throws OAuthErrorException {
        IDToken idToken = session.tokens().decode(encodedIDToken, IDToken.class);
        if (idToken == null) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid IDToken");
        }
        return idToken;
    }

    /**
     * 创建accessToken  通过该token 可以访问资源服务器  比如获取用户信息
     * @param session
     * @param realm
     * @param client
     * @param user
     * @param userSession
     * @param clientSessionCtx
     * @return
     */
    public AccessToken createClientAccessToken(KeycloakSession session, RealmModel realm, ClientModel client, UserModel user, UserSessionModel userSession,
                                               ClientSessionContext clientSessionCtx) {
        // 初始化token
        AccessToken token = initToken(realm, client, user, userSession, clientSessionCtx, session.getContext().getUri());
        // 做一层转换  简单的理解就是填充字段
        token = transformAccessToken(session, token, userSession, clientSessionCtx);
        return token;
    }

    /**
     * 将用户会话 和 认证会话 关联
     * @param session
     * @param userSession
     * @param authSession
     * @return
     */
    public static ClientSessionContext attachAuthenticationSession(KeycloakSession session, UserSessionModel userSession, AuthenticationSessionModel authSession) {
        ClientModel client = authSession.getClient();

        AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
        if (clientSession == null) {
            clientSession = session.sessions().createClientSession(userSession.getRealm(), client, userSession);
        }

        clientSession.setRedirectUri(authSession.getRedirectUri());
        clientSession.setProtocol(authSession.getProtocol());

        Set<String> clientScopeIds = authSession.getClientScopes();

        Map<String, String> transferredNotes = authSession.getClientNotes();
        for (Map.Entry<String, String> entry : transferredNotes.entrySet()) {
            clientSession.setNote(entry.getKey(), entry.getValue());
        }

        Map<String, String> transferredUserSessionNotes = authSession.getUserSessionNotes();
        for (Map.Entry<String, String> entry : transferredUserSessionNotes.entrySet()) {
            userSession.setNote(entry.getKey(), entry.getValue());
        }

        clientSession.setTimestamp(Time.currentTime());

        // Remove authentication session now
        new AuthenticationSessionManager(session).removeAuthenticationSession(userSession.getRealm(), authSession, true);

        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndClientScopeIds(clientSession, clientScopeIds, session);
        return clientSessionCtx;
    }


    /**
     * 将client会话从用户会话剥离
     * @param clientSession
     */
    public static void dettachClientSession(AuthenticatedClientSessionModel clientSession) {
        UserSessionModel userSession = clientSession.getUserSession();
        if (userSession == null) {
            return;
        }

        clientSession.detachFromUserSession();
    }


    /**
     * 查询client_scope/user 关联的所有role
     * @param user
     * @param client
     * @param clientScopes
     * @return
     */
    public static Set<RoleModel> getAccess(UserModel user, ClientModel client, Stream<ClientScopeModel> clientScopes) {
        // 获取用户的所有角色
        Set<RoleModel> roleMappings = RoleUtils.getDeepUserRoleMappings(user);

        // 这种情况返回user的所有角色   这样的范围会更大  因为该user可能会有一些client上并不存在的role
        if (client.isFullScopeAllowed()) {
            if (logger.isTraceEnabled()) {
                logger.tracef("Using full scope for client %s", client.getClientId());
            }
            return roleMappings;
        } else {
            // 下面的操作得到的role 都必然属于该client

            // 1 - Client roles of this client itself
            // 得到client支持的所有角色
            Stream<RoleModel> scopeMappings = client.getRolesStream();

            // 2 - Role mappings of client itself + default client scopes + optional client scopes requested by scope parameter (if applyScopeParam is true)
            // 将client_scope的所有角色取出来 (去重)
            Stream<RoleModel> clientScopesMappings;
            if (!logger.isTraceEnabled()) {
                clientScopesMappings = clientScopes.flatMap(clientScope -> clientScope.getScopeMappingsStream());
            } else {
                clientScopesMappings = clientScopes.flatMap(clientScope -> {
                    logger.tracef("Adding client scope role mappings of client scope '%s' to client '%s'",
                            clientScope.getName(), client.getClientId());
                    return clientScope.getScopeMappingsStream();
                });
            }
            scopeMappings = Stream.concat(scopeMappings, clientScopesMappings);

            // 3 - Expand scope mappings  将组合角色展开
            scopeMappings = RoleUtils.expandCompositeRolesStream(scopeMappings);

            // Intersection of expanded user roles and expanded scopeMappings  仅保留交集
            roleMappings.retainAll(scopeMappings.collect(Collectors.toSet()));

            return roleMappings;
        }
    }


    /**
     * Return client itself + all default client scopes of client + optional client scopes requested by scope parameter
     * 返回client的 scope
     */
    public static Stream<ClientScopeModel> getRequestedClientScopes(String scopeParam, ClientModel client) {
        // Add all default client scopes automatically and client itself
        // client在实体层面会关联scope对象  这里获取的是default scope
        Stream<ClientScopeModel> clientScopes = Stream.concat(
                client.getClientScopes(true, true).values().stream(),
                // 把client自身也加进去
                Stream.of(client)).distinct();

        // 代表没法提供其他信息  这样只会返回default_scope
        if (scopeParam == null) {
            return clientScopes;
        }

        // 读取所有非default scope
        Map<String, ClientScopeModel> allOptionalScopes = client.getClientScopes(false, true);
        // Add optional client scopes requested by scope parameter
        return Stream.concat(parseScopeParameter(scopeParam).map(allOptionalScopes::get).filter(Objects::nonNull),
                clientScopes).distinct();
    }

    /**
     * 检测scope对于client是否有效
     * @param scopes
     * @param client
     * @return
     */
    public static boolean isValidScope(String scopes, ClientModel client) {
        if (scopes == null) {
            return true;
        }

        // 返回client拥有的所有scope
        Set<String> clientScopes = getRequestedClientScopes(scopes, client)
                .filter(((Predicate<ClientScopeModel>) ClientModel.class::isInstance).negate())
                .map(ClientScopeModel::getName)
                .collect(Collectors.toSet());
        Collection<String> requestedScopes = TokenManager.parseScopeParameter(scopes).collect(Collectors.toSet());

        if (TokenUtil.isOIDCRequest(scopes)) {
            requestedScopes.remove(OAuth2Constants.SCOPE_OPENID);
        }

        // 代表client不支持这些scope
        if (!requestedScopes.isEmpty() && clientScopes.isEmpty()) {
            return false;
        }

        for (String requestedScope : requestedScopes) {
            // we also check dynamic scopes in case the client is from a provider that dynamically provides scopes to their clients
            // 代表请求的scope是client所不具有的 并且无法动态生成
            if (!clientScopes.contains(requestedScope) && client.getDynamicClientScope(requestedScope) == null) {
                return false;
            }
        }
        
        return true;
    }

    public static Stream<String> parseScopeParameter(String scopeParam) {
        return Arrays.stream(scopeParam.split(" ")).distinct();
    }

    /**
     * Check if user still has granted consents to all requested client scopes
     * 检查用户是否已经满足了client的所有需求
     * @param session
     * @param user
     * @param client
     * @param requestedClientScopes
     * @return
     */
    public static boolean verifyConsentStillAvailable(KeycloakSession session, UserModel user, ClientModel client,
                                                      Stream<ClientScopeModel> requestedClientScopes) {

        // 应该是代表client不需要过问用户
        if (!client.isConsentRequired()) {
            return true;
        }

        // 获取用户有关该client的授权信息
        UserConsentModel grantedConsent = session.users().getConsentByClient(client.getRealm(), user.getId(), client.getId());

        return requestedClientScopes
                .filter(ClientScopeModel::isDisplayOnConsentScreen)
                // 代表都不匹配
                .noneMatch(requestedScope -> {

                    // 请求的scope用户还没有授权
                    if (grantedConsent == null || !grantedConsent.getGrantedClientScopes().contains(requestedScope)) {
                        logger.debugf("Client '%s' no longer has requested consent from user '%s' for client scope '%s'",
                                client.getClientId(), user.getUsername(), requestedScope.getName());
                        return true;
                    }
                    return false;
                });
    }

    /**
     * 通过协议映射器 处理token   协议映射器主要是修改一些字段名
     * @param session
     * @param token
     * @param userSession
     * @param clientSessionCtx
     * @return
     */
    public AccessToken transformAccessToken(KeycloakSession session, AccessToken token,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        AtomicReference<AccessToken> finalToken = new AtomicReference<>(token);
        ProtocolMapperUtils.getSortedProtocolMappers(session, clientSessionCtx)
                .filter(mapper -> mapper.getValue() instanceof OIDCAccessTokenMapper)
                // 转换token
                .forEach(mapper -> finalToken.set(((OIDCAccessTokenMapper) mapper.getValue())
                        .transformAccessToken(finalToken.get(), mapper.getKey(), session, userSession, clientSessionCtx)));
        return finalToken.get();
    }

    /**
     * 在返回response之前 做一些数据填充
     * @param session
     * @param accessTokenResponse
     * @param userSession
     * @param clientSessionCtx
     * @return
     */
    public AccessTokenResponse transformAccessTokenResponse(KeycloakSession session, AccessTokenResponse accessTokenResponse,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        AtomicReference<AccessTokenResponse> finalResponseToken = new AtomicReference<>(accessTokenResponse);
        ProtocolMapperUtils.getSortedProtocolMappers(session, clientSessionCtx)
                .filter(mapper -> mapper.getValue() instanceof OIDCAccessTokenResponseMapper)
                .forEach(mapper -> finalResponseToken.set(((OIDCAccessTokenResponseMapper) mapper.getValue())
                        .transformAccessTokenResponse(finalResponseToken.get(), mapper.getKey(), session, userSession, clientSessionCtx)));

        return finalResponseToken.get();
    }

    public AccessToken transformUserInfoAccessToken(KeycloakSession session, AccessToken token,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        AtomicReference<AccessToken> finalToken = new AtomicReference<>(token);
        ProtocolMapperUtils.getSortedProtocolMappers(session, clientSessionCtx)
                .filter(mapper -> mapper.getValue() instanceof UserInfoTokenMapper)
                .forEach(mapper -> finalToken.set(((UserInfoTokenMapper) mapper.getValue())
                        .transformUserInfoToken(finalToken.get(), mapper.getKey(), session, userSession, clientSessionCtx)));
        return finalToken.get();
    }

    /**
     * ID token 也要经过 ProtocolMapper对象的处理
     * @param session
     * @param token
     * @param userSession
     * @param clientSessionCtx
     */
    public void transformIDToken(KeycloakSession session, IDToken token,
                                      UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        AtomicReference<IDToken> finalToken = new AtomicReference<>(token);
        ProtocolMapperUtils.getSortedProtocolMappers(session, clientSessionCtx)
                .filter(mapper -> mapper.getValue() instanceof OIDCIDTokenMapper)
                .forEach(mapper -> finalToken.set(((OIDCIDTokenMapper) mapper.getValue())
                        .transformIDToken(finalToken.get(), mapper.getKey(), session, userSession, clientSessionCtx)));
    }

    /**
     * 生成 accessToken
     * @param realm
     * @param client
     * @param user
     * @param session
     * @param clientSessionCtx
     * @param uriInfo
     * @return
     */
    protected AccessToken initToken(RealmModel realm, ClientModel client, UserModel user, UserSessionModel session,
                                    ClientSessionContext clientSessionCtx, UriInfo uriInfo) {
        AccessToken token = new AccessToken();

        // uuid 作为token的id
        token.id(KeycloakModelUtils.generateId());
        // 类型是 Bearer
        token.type(TokenUtil.TOKEN_TYPE_BEARER);
        token.subject(user.getId());
        // 设置token的生成时间
        token.issuedNow();
        // 该token是针对哪个client的
        token.issuedFor(client.getClientId());

        AuthenticatedClientSessionModel clientSession = clientSessionCtx.getClientSession();
        // 简单理解就是 baseUrl + realm
        token.issuer(clientSession.getNote(OIDCLoginProtocol.ISSUER));
        token.setNonce(clientSessionCtx.getAttribute(OIDCLoginProtocol.NONCE_PARAM, String.class));
        // 将client scope 通过 “ ” 进行拼接
        token.setScope(clientSessionCtx.getScopeString());

        // Best effort for "acr" value. Use 0 if clientSession was authenticated through cookie ( SSO )
        // TODO: Add better acr support. See KEYCLOAK-3314
        String acr = (AuthenticationManager.isSSOAuthentication(clientSession)) ? "0" : "1";
        token.setAcr(acr);

        String authTime = session.getNote(AuthenticationManager.AUTH_TIME);
        if (authTime != null) {
            token.setAuthTime(Integer.parseInt(authTime));
        }


        token.setSessionState(session.getId());

        // 是否授权了离线访问
        ClientScopeModel offlineAccessScope = KeycloakModelUtils.getClientScopeByName(realm, OAuth2Constants.OFFLINE_ACCESS);
        // 授权的基础上还要本次请求scope中包含 才支持离线访问
        boolean offlineTokenRequested = offlineAccessScope == null ? false
            : clientSessionCtx.getClientScopeIds().contains(offlineAccessScope.getId());
        // 设置token的过期时间
        token.expiration(getTokenExpiration(realm, client, session, clientSession, offlineTokenRequested));

        return token;
    }

    /**
     * 计算token的过期时间
     * @param realm
     * @param client
     * @param userSession
     * @param clientSession
     * @param offlineTokenRequested  是否需要离线token  (需要client_scope包含才行)
     * @return
     */
    private int getTokenExpiration(RealmModel realm, ClientModel client, UserSessionModel userSession,
        AuthenticatedClientSessionModel clientSession, boolean offlineTokenRequested) {
        boolean implicitFlow = false;
        String responseType = clientSession.getNote(OIDCLoginProtocol.RESPONSE_TYPE_PARAM);
        if (responseType != null) {
            implicitFlow = OIDCResponseType.parse(responseType).isImplicitFlow();
        }

        int tokenLifespan;

        // TODO 先不考虑隐性
        if (implicitFlow) {
            tokenLifespan = realm.getAccessTokenLifespanForImplicitFlow();
        } else {
            // 获取配置
            String clientLifespan = client.getAttribute(OIDCConfigAttributes.ACCESS_TOKEN_LIFESPAN);
            if (clientLifespan != null && !clientLifespan.trim().isEmpty()) {
                tokenLifespan = Integer.parseInt(clientLifespan);
            } else {
                tokenLifespan = realm.getAccessTokenLifespan();
            }
        }

        // 过期时间 默认就是当前时间+寿命
        int expiration;
        if (tokenLifespan == -1) {
            expiration = userSession.getStarted() + (userSession.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0 ?
                    realm.getSsoSessionMaxLifespanRememberMe() : realm.getSsoSessionMaxLifespan());
        } else {
            expiration = Time.currentTime() + tokenLifespan;
        }

        // TODO 此时是一个离线会话 或者需要离线token
        if (userSession.isOffline() || offlineTokenRequested) {
            if (realm.isOfflineSessionMaxLifespanEnabled()) {
                int sessionExpires = userSession.getStarted() + realm.getOfflineSessionMaxLifespan();
                expiration = expiration <= sessionExpires ? expiration : sessionExpires;

                int clientOfflineSessionMaxLifespan;
                String clientOfflineSessionMaxLifespanPerClient = client
                    .getAttribute(OIDCConfigAttributes.CLIENT_OFFLINE_SESSION_MAX_LIFESPAN);
                if (clientOfflineSessionMaxLifespanPerClient != null
                    && !clientOfflineSessionMaxLifespanPerClient.trim().isEmpty()) {
                    clientOfflineSessionMaxLifespan = Integer.parseInt(clientOfflineSessionMaxLifespanPerClient);
                } else {
                    clientOfflineSessionMaxLifespan = realm.getClientOfflineSessionMaxLifespan();
                }

                if (clientOfflineSessionMaxLifespan > 0) {
                    int clientOfflineSessionExpiration = userSession.getStarted() + clientOfflineSessionMaxLifespan;
                    return expiration < clientOfflineSessionExpiration ? expiration : clientOfflineSessionExpiration;
                }
            }
        } else {

            // 根据是否rememberme得到不同的过期时间
            int sessionExpires = userSession.getStarted()
                + (userSession.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0
                    ? realm.getSsoSessionMaxLifespanRememberMe()
                    : realm.getSsoSessionMaxLifespan());
            expiration = expiration <= sessionExpires ? expiration : sessionExpires;

            // 计算client级别的会话寿命
            int clientSessionMaxLifespan;
            String clientSessionMaxLifespanPerClient = client.getAttribute(OIDCConfigAttributes.CLIENT_SESSION_MAX_LIFESPAN);
            if (clientSessionMaxLifespanPerClient != null && !clientSessionMaxLifespanPerClient.trim().isEmpty()) {
                clientSessionMaxLifespan = Integer.parseInt(clientSessionMaxLifespanPerClient);
            } else {
                clientSessionMaxLifespan = realm.getClientSessionMaxLifespan();
            }

            // 选择短的
            if (clientSessionMaxLifespan > 0) {
                int clientSessionExpiration = userSession.getStarted() + clientSessionMaxLifespan;
                return expiration < clientSessionExpiration ? expiration : clientSessionExpiration;
            }
        }

        return expiration;
    }


    /**
     * 准备响应结果
     * @param realm
     * @param client
     * @param event
     * @param session
     * @param userSession
     * @param clientSessionCtx
     * @return
     */
    public AccessTokenResponseBuilder responseBuilder(RealmModel realm, ClientModel client, EventBuilder event, KeycloakSession session,
                                                      UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        return new AccessTokenResponseBuilder(realm, client, event, session, userSession, clientSessionCtx);
    }

    public class AccessTokenResponseBuilder {
        RealmModel realm;
        ClientModel client;
        EventBuilder event;
        KeycloakSession session;
        UserSessionModel userSession;
        ClientSessionContext clientSessionCtx;

        /**
         * 设置 accessToken
         */
        AccessToken accessToken;
        RefreshToken refreshToken;
        IDToken idToken;

        boolean generateAccessTokenHash = false;
        String codeHash;

        String stateHash;

        public AccessTokenResponseBuilder(RealmModel realm, ClientModel client, EventBuilder event, KeycloakSession session,
                                          UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
            this.realm = realm;
            this.client = client;
            this.event = event;
            this.session = session;
            this.userSession = userSession;
            this.clientSessionCtx = clientSessionCtx;
        }

        public AccessToken getAccessToken() {
            return accessToken;
        }

        public RefreshToken getRefreshToken() {
            return refreshToken;
        }

        public IDToken getIdToken() {
            return idToken;
        }

        public AccessTokenResponseBuilder accessToken(AccessToken accessToken) {
            this.accessToken = accessToken;
            return this;
        }
        public AccessTokenResponseBuilder refreshToken(RefreshToken refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public AccessTokenResponseBuilder generateAccessToken() {
            UserModel user = userSession.getUser();
            accessToken = createClientAccessToken(session, realm, client, user, userSession, clientSessionCtx);
            return this;
        }

        /**
         * 产生用于刷新token的token  称为refreshToken
         * @return
         */
        public AccessTokenResponseBuilder generateRefreshToken() {
            // 要求已经设置了token
            if (accessToken == null) {
                throw new IllegalStateException("accessToken not set");
            }

            ClientScopeModel offlineAccessScope = KeycloakModelUtils.getClientScopeByName(realm, OAuth2Constants.OFFLINE_ACCESS);
            boolean offlineTokenRequested = offlineAccessScope==null ? false : clientSessionCtx.getClientScopeIds().contains(offlineAccessScope.getId());
            // TODO 先忽略离线访问
            if (offlineTokenRequested) {
                UserSessionManager sessionManager = new UserSessionManager(session);
                if (!sessionManager.isOfflineTokenAllowed(clientSessionCtx)) {
                    event.error(Errors.NOT_ALLOWED);
                    throw new ErrorResponseException("not_allowed", "Offline tokens not allowed for the user or client", Response.Status.BAD_REQUEST);
                }

                refreshToken = new RefreshToken(accessToken);
                refreshToken.type(TokenUtil.TOKEN_TYPE_OFFLINE);
                if (realm.isOfflineSessionMaxLifespanEnabled())
                    refreshToken.expiration(getOfflineExpiration());
                sessionManager.createOrUpdateOfflineSession(clientSessionCtx.getClientSession(), userSession);
            } else {
                // 通过accessToken 赋予部分属性   (但是accessToken 是通过 ProtocolMapper 补充过属性的  所以他们还是不同)
                refreshToken = new RefreshToken(accessToken);
                refreshToken.expiration(getRefreshExpiration());
            }
            refreshToken.id(KeycloakModelUtils.generateId());
            refreshToken.issuedNow();
            return this;
        }

        /**
         * 获取refreshToken的过期时间
         * @return
         */
        private int getRefreshExpiration() {
            int sessionExpires = userSession.getStarted()
                + (userSession.isRememberMe() && realm.getSsoSessionMaxLifespanRememberMe() > 0
                    ? realm.getSsoSessionMaxLifespanRememberMe()
                    : realm.getSsoSessionMaxLifespan());

            int clientSessionMaxLifespan;
            String clientSessionMaxLifespanPerClient = client.getAttribute(OIDCConfigAttributes.CLIENT_SESSION_MAX_LIFESPAN);
            if (clientSessionMaxLifespanPerClient != null && !clientSessionMaxLifespanPerClient.trim().isEmpty()) {
                clientSessionMaxLifespan = Integer.parseInt(clientSessionMaxLifespanPerClient);
            } else {
                clientSessionMaxLifespan = realm.getClientSessionMaxLifespan();
            }

            if (clientSessionMaxLifespan > 0) {
                int clientSessionMaxExpiration = userSession.getStarted() + clientSessionMaxLifespan;
                sessionExpires = sessionExpires < clientSessionMaxExpiration ? sessionExpires : clientSessionMaxExpiration;
            }

            int expiration = Time.currentTime() + (userSession.isRememberMe() && realm.getSsoSessionIdleTimeoutRememberMe() > 0
                ? realm.getSsoSessionIdleTimeoutRememberMe()
                : realm.getSsoSessionIdleTimeout());

            int clientSessionIdleTimeout;
            String clientSessionIdleTimeoutPerClient = client.getAttribute(OIDCConfigAttributes.CLIENT_SESSION_IDLE_TIMEOUT);
            if (clientSessionIdleTimeoutPerClient != null && !clientSessionIdleTimeoutPerClient.trim().isEmpty()) {
                clientSessionIdleTimeout = Integer.parseInt(clientSessionIdleTimeoutPerClient);
            } else {
                clientSessionIdleTimeout = realm.getClientSessionIdleTimeout();
            }

            if (clientSessionIdleTimeout > 0) {
                int clientSessionIdleExpiration = Time.currentTime() + clientSessionIdleTimeout;
                expiration = expiration < clientSessionIdleExpiration ? expiration : clientSessionIdleExpiration;
            }

            return expiration <= sessionExpires ? expiration : sessionExpires;
        }

        private int getOfflineExpiration() {
            int sessionExpires = userSession.getStarted() + realm.getOfflineSessionMaxLifespan();

            int clientOfflineSessionMaxLifespan;
            String clientOfflineSessionMaxLifespanPerClient = client
                .getAttribute(OIDCConfigAttributes.CLIENT_OFFLINE_SESSION_MAX_LIFESPAN);
            if (clientOfflineSessionMaxLifespanPerClient != null
                && !clientOfflineSessionMaxLifespanPerClient.trim().isEmpty()) {
                clientOfflineSessionMaxLifespan = Integer.parseInt(clientOfflineSessionMaxLifespanPerClient);
            } else {
                clientOfflineSessionMaxLifespan = realm.getClientOfflineSessionMaxLifespan();
            }

            if (clientOfflineSessionMaxLifespan > 0) {
                int clientOfflineSessionMaxExpiration = userSession.getStarted() + clientOfflineSessionMaxLifespan;
                sessionExpires = sessionExpires < clientOfflineSessionMaxExpiration ? sessionExpires
                    : clientOfflineSessionMaxExpiration;
            }

            int expiration = Time.currentTime() + realm.getOfflineSessionIdleTimeout();

            int clientOfflineSessionIdleTimeout;
            String clientOfflineSessionIdleTimeoutPerClient = client
                .getAttribute(OIDCConfigAttributes.CLIENT_OFFLINE_SESSION_IDLE_TIMEOUT);
            if (clientOfflineSessionIdleTimeoutPerClient != null
                && !clientOfflineSessionIdleTimeoutPerClient.trim().isEmpty()) {
                clientOfflineSessionIdleTimeout = Integer.parseInt(clientOfflineSessionIdleTimeoutPerClient);
            } else {
                clientOfflineSessionIdleTimeout = realm.getClientOfflineSessionIdleTimeout();
            }

            if (clientOfflineSessionIdleTimeout > 0) {
                int clientOfflineSessionIdleExpiration = Time.currentTime() + clientOfflineSessionIdleTimeout;
                expiration = expiration < clientOfflineSessionIdleExpiration ? expiration : clientOfflineSessionIdleExpiration;
            }

            return expiration <= sessionExpires ? expiration : sessionExpires;
        }

        /**
         * 生成id token
         * @return
         */
        public AccessTokenResponseBuilder generateIDToken() {
            if (accessToken == null) {
                throw new IllegalStateException("accessToken not set");
            }
            idToken = new IDToken();
            idToken.id(KeycloakModelUtils.generateId());
            idToken.type(TokenUtil.TOKEN_TYPE_ID);
            idToken.subject(accessToken.getSubject());
            idToken.audience(client.getClientId());
            idToken.issuedNow();
            idToken.issuedFor(accessToken.getIssuedFor());
            idToken.issuer(accessToken.getIssuer());
            idToken.setNonce(accessToken.getNonce());
            idToken.setAuthTime(accessToken.getAuthTime());
            idToken.setSessionState(accessToken.getSessionState());
            idToken.expiration(accessToken.getExpiration());
            idToken.setAcr(accessToken.getAcr());
            transformIDToken(session, idToken, userSession, clientSessionCtx);
            return this;
        }

        public AccessTokenResponseBuilder generateAccessTokenHash() {
            generateAccessTokenHash = true;
            return this;
        }

        public AccessTokenResponseBuilder generateCodeHash(String code) {
            codeHash = generateOIDCHash(code);
            return this;
        }

        // Financial API - Part 2: Read and Write API Security Profile
        // http://openid.net/specs/openid-financial-api-part-2.html#authorization-server
        public AccessTokenResponseBuilder generateStateHash(String state) {
            stateHash = generateOIDCHash(state);
            return this;
        }

        /**
         * 生成响应结果
         * @return
         */
        public AccessTokenResponse build() {
            if (accessToken != null) {
                event.detail(Details.TOKEN_ID, accessToken.getId());
            }

            if (refreshToken != null) {
                if (event.getEvent().getDetails().containsKey(Details.REFRESH_TOKEN_ID)) {
                    event.detail(Details.UPDATED_REFRESH_TOKEN_ID, refreshToken.getId());
                } else {
                    event.detail(Details.REFRESH_TOKEN_ID, refreshToken.getId());
                }
                event.detail(Details.REFRESH_TOKEN_TYPE, refreshToken.getType());
            }

            AccessTokenResponse res = new AccessTokenResponse();

            if (accessToken != null) {
                // 对accessToken 进行加密 并返回
                String encodedToken = session.tokens().encode(accessToken);
                res.setToken(encodedToken);
                // 代表期望设置为 Bearer
                res.setTokenType(TokenUtil.TOKEN_TYPE_BEARER);
                // 就是session id
                res.setSessionState(accessToken.getSessionState());
                if (accessToken.getExpiration() != 0) {
                    res.setExpiresIn(accessToken.getExpiration() - Time.currentTime());
                }
            }

            if (generateAccessTokenHash) {
                String atHash = generateOIDCHash(res.getToken());
                idToken.setAccessTokenHash(atHash);
            }
            if (codeHash != null) {
                idToken.setCodeHash(codeHash);
            }
            // Financial API - Part 2: Read and Write API Security Profile
            // http://openid.net/specs/openid-financial-api-part-2.html#authorization-server
            if (stateHash != null) {
                idToken.setStateHash(stateHash);
            }
            // 对 id token 编码 并设置到res中
            if (idToken != null) {
                String encodedToken = session.tokens().encodeAndEncrypt(idToken);
                res.setIdToken(encodedToken);
            }

            if (refreshToken != null) {
                String encodedToken = session.tokens().encode(refreshToken);
                res.setRefreshToken(encodedToken);
                if (refreshToken.getExpiration() != 0) {
                    res.setRefreshExpiresIn(refreshToken.getExpiration() - Time.currentTime());
                }
            }

            // notBefore 越大 代表越新
            int notBefore = realm.getNotBefore();
            if (client.getNotBefore() > notBefore) notBefore = client.getNotBefore();
            int userNotBefore = session.users().getNotBeforeOfUser(realm, userSession.getUser());
            if (userNotBefore > notBefore) notBefore = userNotBefore;

            // 可以证明 在该时间之前的更新都已经被观测到了  但是如果用户更新发生在该值之后 就无法观测到这些更新
            res.setNotBeforePolicy(notBefore);

            transformAccessTokenResponse(session, res, userSession, clientSessionCtx);

            // OIDC Financial API Read Only Profile : scope MUST be returned in the response from Token Endpoint
            String responseScope = clientSessionCtx.getScopeString();
            res.setScope(responseScope);
            event.detail(Details.SCOPE, responseScope);

            return res;
        }


        private String generateOIDCHash(String input) {
            String signatureAlgorithm = session.tokens().signatureAlgorithm(TokenCategory.ID);
            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signatureAlgorithm);
            String hashAlgorithm = signatureProvider.signer().getHashAlgorithm();

            HashProvider hashProvider = session.getProvider(HashProvider.class, hashAlgorithm);
            byte[] hash = hashProvider.hash(input);

            return HashUtils.encodeHashToOIDC(hash);
        }

    }

    public static class RefreshResult {

        private final AccessTokenResponse response;
        private final boolean offlineToken;

        private RefreshResult(AccessTokenResponse response, boolean offlineToken) {
            this.response = response;
            this.offlineToken = offlineToken;
        }

        public AccessTokenResponse getResponse() {
            return response;
        }

        public boolean isOfflineToken() {
            return offlineToken;
        }
    }

    // 校验器 要求token的生成时间在notBefore之上
    public static class NotBeforeCheck implements TokenVerifier.Predicate<JsonWebToken> {

        private final int notBefore;

        public NotBeforeCheck(int notBefore) {
            this.notBefore = notBefore;
        }

        @Override
        public boolean test(JsonWebToken t) throws VerificationException {
            if (t.getIssuedAt() < notBefore) {
                throw new VerificationException("Stale token");
            }

            return true;
        }

        public static NotBeforeCheck forModel(ClientModel clientModel) {
            if (clientModel != null) {

                int notBeforeClient = clientModel.getNotBefore();
                int notBeforeRealm = clientModel.getRealm().getNotBefore();

                int notBefore = (notBeforeClient == 0 ? notBeforeRealm : (notBeforeRealm == 0 ? notBeforeClient :
                        Math.min(notBeforeClient, notBeforeRealm)));

                return new NotBeforeCheck(notBefore);
            }

            return new NotBeforeCheck(0);
        }

        public static NotBeforeCheck forModel(RealmModel realmModel) {
            return new NotBeforeCheck(realmModel == null ? 0 : realmModel.getNotBefore());
        }

        public static NotBeforeCheck forModel(KeycloakSession session, RealmModel realmModel, UserModel userModel) {
            return new NotBeforeCheck(session.users().getNotBeforeOfUser(realmModel, userModel));
        }
    }

    public LogoutTokenValidationCode verifyLogoutToken(KeycloakSession session, RealmModel realm, String encodedLogoutToken) {
        Optional<LogoutToken> logoutTokenOptional = toLogoutToken(encodedLogoutToken);
        if (!logoutTokenOptional.isPresent()) {
            return LogoutTokenValidationCode.DECODE_TOKEN_FAILED;
        }

        LogoutToken logoutToken = logoutTokenOptional.get();
        List<OIDCIdentityProvider> identityProviders = getOIDCIdentityProviders(realm, session).collect(Collectors.toList());
        if (identityProviders.isEmpty()) {
            return LogoutTokenValidationCode.COULD_NOT_FIND_IDP;
        }

        Stream<OIDCIdentityProvider> validOidcIdentityProviders =
                validateLogoutTokenAgainstIdpProvider(identityProviders.stream(), encodedLogoutToken, logoutToken);
        if (validOidcIdentityProviders.count() == 0) {
            return LogoutTokenValidationCode.TOKEN_VERIFICATION_WITH_IDP_FAILED;
        }

        if (logoutToken.getSubject() == null && logoutToken.getSid() == null) {
            return LogoutTokenValidationCode.MISSING_SID_OR_SUBJECT;
        }

        if (!checkLogoutTokenForEvents(logoutToken)) {
            return LogoutTokenValidationCode.BACKCHANNEL_LOGOUT_EVENT_MISSING;
        }

        if (logoutToken.getOtherClaims().get(NONCE) != null) {
            return LogoutTokenValidationCode.NONCE_CLAIM_IN_TOKEN;
        }

        if (logoutToken.getId() == null) {
            return LogoutTokenValidationCode.LOGOUT_TOKEN_ID_MISSING;
        }

        if (logoutToken.getIat() == null) {
            return LogoutTokenValidationCode.MISSING_IAT_CLAIM;
        }

        return LogoutTokenValidationCode.VALIDATION_SUCCESS;
    }

    public Optional<LogoutToken> toLogoutToken(String encodedLogoutToken) {
        try {
            JWSInput jws = new JWSInput(encodedLogoutToken);
            return Optional.of(jws.readJsonContent(LogoutToken.class));
        } catch (JWSInputException e) {
            return Optional.empty();
        }
    }


    public Stream<OIDCIdentityProvider> getValidOIDCIdentityProvidersForBackchannelLogout(RealmModel realm, KeycloakSession session, String encodedLogoutToken, LogoutToken logoutToken) {
        return validateLogoutTokenAgainstIdpProvider(getOIDCIdentityProviders(realm, session), encodedLogoutToken, logoutToken);
    }


    public Stream<OIDCIdentityProvider> validateLogoutTokenAgainstIdpProvider(Stream<OIDCIdentityProvider> oidcIdps, String encodedLogoutToken, LogoutToken logoutToken) {
            return oidcIdps
                    .filter(oidcIdp -> oidcIdp.getConfig().getIssuer() != null)
                    .filter(oidcIdp -> oidcIdp.isIssuer(logoutToken.getIssuer(), null))
                    .filter(oidcIdp -> {
                        try {
                            oidcIdp.validateToken(encodedLogoutToken);
                            return true;
                        } catch (IdentityBrokerException e) {
                            logger.debugf("LogoutToken verification with identity provider failed", e.getMessage());
                            return false;
                        }
                    });
    }

    /**
     *
     * @param realm
     * @param session
     * @return
     */
    private Stream<OIDCIdentityProvider> getOIDCIdentityProviders(RealmModel realm, KeycloakSession session) {
        try {
            return realm.getIdentityProvidersStream()
                    .map(idpModel ->
                        IdentityBrokerService.getIdentityProviderFactory(session, idpModel).create(session, idpModel))
                    .filter(OIDCIdentityProvider.class::isInstance)
                    .map(OIDCIdentityProvider.class::cast);
        } catch (IdentityBrokerException e) {
            logger.warnf("LogoutToken verification with identity provider failed", e.getMessage());
        }
        return Stream.empty();
    }

    /**
     * 检测此时登出token中 是否有一个eventName为 http://schemas.openid.net/event/backchannel-logout
     * @param logoutToken
     * @return
     */
    private boolean checkLogoutTokenForEvents(LogoutToken logoutToken) {
        for (String eventKey : logoutToken.getEvents().keySet()) {
            if (TokenUtil.TOKEN_BACKCHANNEL_LOGOUT_EVENT.equals(eventKey)) {
                return true;
            }
        }
        return false;
    }

}
