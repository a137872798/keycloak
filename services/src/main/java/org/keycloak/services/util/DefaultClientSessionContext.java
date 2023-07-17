/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.services.util;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.util.TokenUtil;

/**
 * Not thread safe. It's per-request object
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 客户端会话 上下文
 */
public class DefaultClientSessionContext implements ClientSessionContext {

    private static Logger logger = Logger.getLogger(DefaultClientSessionContext.class);

    private final AuthenticatedClientSessionModel clientSession;

    /**
     * 存储scope的id
     */
    private final Set<String> clientScopeIds;
    private final KeycloakSession session;

    /**
     * 一个client对应多个scope
     */
    private Set<ClientScopeModel> clientScopes;

    /**
     * 每个client有多个角色
     */
    private Set<RoleModel> roles;
    private Set<ProtocolMapperModel> protocolMappers;

    // All roles of user expanded. It doesn't yet take into account permitted clientScopes
    private Set<RoleModel> userRoles;

    private Map<String, Object> attributes = new HashMap<>();

    private DefaultClientSessionContext(AuthenticatedClientSessionModel clientSession, Set<String> clientScopeIds, KeycloakSession session) {
        this.clientSession = clientSession;
        this.clientScopeIds = clientScopeIds;
        this.session = session;
    }


    /**
     * Useful if we want to "re-compute" client scopes based on the scope parameter
     */
    public static DefaultClientSessionContext fromClientSessionScopeParameter(AuthenticatedClientSessionModel clientSession, KeycloakSession session) {
        // 从client会话上获取scope属性
        return fromClientSessionAndScopeParameter(clientSession, clientSession.getNote(OAuth2Constants.SCOPE), session);
    }


    public static DefaultClientSessionContext fromClientSessionAndScopeParameter(AuthenticatedClientSessionModel clientSession, String scopeParam, KeycloakSession session) {
        // 当存在scope属性时 除了获取client的default_scope外 还会获取scope关联的client_scope
        Stream<ClientScopeModel> requestedClientScopes = TokenManager.getRequestedClientScopes(scopeParam, clientSession.getClient());
        return fromClientSessionAndClientScopes(clientSession, requestedClientScopes, session);
    }


    public static DefaultClientSessionContext fromClientSessionAndClientScopeIds(AuthenticatedClientSessionModel clientSession, Set<String> clientScopeIds, KeycloakSession session) {
        return new DefaultClientSessionContext(clientSession, clientScopeIds, session);
    }


    /**
     * @param clientSession
     * @param clientScopes
     * @param session
     * @return
     */
    public static DefaultClientSessionContext fromClientSessionAndClientScopes(AuthenticatedClientSessionModel clientSession,
                                                                               Stream<ClientScopeModel> clientScopes,
                                                                               KeycloakSession session) {
        Set<String> clientScopeIds = clientScopes.map(ClientScopeModel::getId).collect(Collectors.toSet());
        return new DefaultClientSessionContext(clientSession, clientScopeIds, session);
    }


    @Override
    public AuthenticatedClientSessionModel getClientSession() {
        return clientSession;
    }


    @Override
    public Set<String> getClientScopeIds() {
        return clientScopeIds;
    }


    /**
     * 通过scopeIds属性 加载client_scope
     * @return
     */
    @Override
    public Stream<ClientScopeModel> getClientScopesStream() {
        // Load client scopes if not yet present
        if (clientScopes == null) {
            clientScopes = loadClientScopes();
        }
        return clientScopes.stream();
    }


    @Override
    public Stream<RoleModel> getRolesStream() {
        // Load roles if not yet present
        if (roles == null) {
            roles = loadRoles();
        }
        return roles.stream();
    }


    /**
     *
     * @return
     */
    @Override
    public Stream<ProtocolMapperModel> getProtocolMappersStream() {
        // Load protocolMappers if not yet present
        if (protocolMappers == null) {
            protocolMappers = loadProtocolMappers();
        }
        return protocolMappers.stream();
    }


    private Set<RoleModel> getUserRoles() {
        // Load userRoles if not yet present
        if (userRoles == null) {
            userRoles = loadUserRoles();
        }
        return userRoles;
    }


    @Override
    public String getScopeString() {
        // Add both default and optional scopes to scope parameter. Don't add client itself
        String scopeParam = getClientScopesStream()
                // 排除ClientModel
                .filter(((Predicate<ClientScopeModel>) ClientModel.class::isInstance).negate())
                // 要求scope.attr中 include.in.token.scope 为true
                .filter(ClientScopeModel::isIncludeInTokenScope)
                .map(ClientScopeModel::getName)
                .collect(Collectors.joining(" "));

        // See if "openid" scope is requested
        String scopeSent = clientSession.getNote(OAuth2Constants.SCOPE);

        // 追加一个openid的scope
        if (TokenUtil.isOIDCRequest(scopeSent)) {
            scopeParam = TokenUtil.attachOIDCScope(scopeParam);
        }

        return scopeParam;
    }


    @Override
    public void setAttribute(String name, Object value) {
        attributes.put(name, value);
    }


    @Override
    public <T> T getAttribute(String name, Class<T> clazz) {
        Object value = attributes.get(name);
        return clazz.cast(value);
    }


    // Loading data    通过scopeId查询scope对象
    private Set<ClientScopeModel> loadClientScopes() {
        Set<ClientScopeModel> clientScopes = new HashSet<>();
        for (String scopeId : clientScopeIds) {
            ClientScopeModel clientScope = KeycloakModelUtils.findClientScopeById(clientSession.getClient().getRealm(), getClientSession().getClient(), scopeId);
            if (clientScope != null) {
                // 要求scope能作用到user上 也就是scope展开的role 与user的role有交集
                if (isClientScopePermittedForUser(clientScope)) {
                    clientScopes.add(clientScope);
                } else {
                    if (logger.isTraceEnabled()) {
                        logger.tracef("User '%s' not permitted to have client scope '%s'",
                                clientSession.getUserSession().getUser().getUsername(), clientScope.getName());
                    }
                }
            }
        }
        return clientScopes;
    }


    // Return true if clientScope can be used by the user.
    private boolean isClientScopePermittedForUser(ClientScopeModel clientScope) {
        // Client 默认通过
        if (clientScope instanceof ClientModel) {
            return true;
        }

        // 将scope转换成role
        Set<RoleModel> clientScopeRoles = clientScope.getScopeMappingsStream().collect(Collectors.toSet());

        // Client scope is automatically permitted if it doesn't have any role scope mappings  没有角色 自动通过
        if (clientScopeRoles.isEmpty()) {
            return true;
        }

        // Expand (resolve composite roles)
        // 某些角色可能是组合角色  将角色展开
        clientScopeRoles = RoleUtils.expandCompositeRoles(clientScopeRoles);

        // Check if expanded roles of clientScope has any intersection with expanded roles of user. If not, it is not permitted
        // 与当前用户角色有交集 才认为可以得到该scope
        clientScopeRoles.retainAll(getUserRoles());
        return !clientScopeRoles.isEmpty();
    }


    /**
     * 加载所有角色
     * @return
     */
    private Set<RoleModel> loadRoles() {
        UserModel user = clientSession.getUserSession().getUser();
        ClientModel client = clientSession.getClient();
        return TokenManager.getAccess(user, client, getClientScopesStream());
    }


    /**
     * 加载协议映射对象
     * @return
     */
    private Set<ProtocolMapperModel> loadProtocolMappers() {
        // 该client认证所采用的协议  (oidc,saml)
        String protocol = clientSession.getClient().getProtocol();

        // Being rather defensive. But protocol should normally always be there
        if (protocol == null) {
            logger.warnf("Client '%s' doesn't have protocol set. Fallback to openid-connect. Please fix client configuration",
                    clientSession.getClient().getClientId());
            protocol = OIDCLoginProtocol.LOGIN_PROTOCOL;
        }

        String finalProtocol = protocol;
        return getClientScopesStream()
                .flatMap(clientScope -> clientScope.getProtocolMappersStream()
                        // 拿到协议映射对象   协议要匹配  并且存在对应ProtocolMapperProvider
                        .filter(mapper -> Objects.equals(finalProtocol, mapper.getProtocol()) &&
                                ProtocolMapperUtils.isEnabled(session, mapper)))
                .collect(Collectors.toSet());
    }


    private Set<RoleModel> loadUserRoles() {
        UserModel user = clientSession.getUserSession().getUser();
        return RoleUtils.getDeepUserRoleMappings(user);
    }

}
