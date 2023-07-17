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

package org.keycloak.models;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Request-scoped context object
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 客户端上下文对象 包含各种信息
 */
public interface ClientSessionContext {

    /**
     * 获取client级别的会话
     * @return
     */
    AuthenticatedClientSessionModel getClientSession();

    /**
     * 一个client 会关联多个client_scope
     * @return
     */
    Set<String> getClientScopeIds();

    /**
     * @deprecated Use {@link #getClientScopesStream() getClientScopesStream} instead.
     * @return Set of protocol mappers
     */
    @Deprecated
    default Set<ClientScopeModel> getClientScopes() {
        return getClientScopesStream().collect(Collectors.toSet());
    }

    /**
     * Returns client scopes as a stream.
     * @return Stream of client scopes. Never returns {@code null}.
     * 将关联的scope以stream的形式返回
     */
    Stream<ClientScopeModel> getClientScopesStream();

    /**
     * @deprecated Use {@link #getRolesStream() getRolesStream} instead.
     * @return expanded roles (composite roles already applied)
     */
    @Deprecated
    default Set<RoleModel> getRoles() {
        return getRolesStream().collect(Collectors.toSet());
    }

    /**
     * Returns all roles including composite ones as a stream.
     * @return Stream of {@link RoleModel}. Never returns {@code null}.
     * 每个client代表一个应用 返回该应用关联的所有角色
     */
    Stream<RoleModel> getRolesStream();

    /**
     * @deprecated Use {@link #getProtocolMappersStream() getProtocolMappersStream} instead.
     * @return Set of protocol mappers
     */
    @Deprecated
    default Set<ProtocolMapperModel> getProtocolMappers() {
        return getProtocolMappersStream().collect(Collectors.toSet());
    }

    /**
     * 到协议的映射
     * Returns protocol mappers as a stream.
     * @return Stream of protocol mappers. Never returns {@code null}.
     */
    Stream<ProtocolMapperModel> getProtocolMappersStream();

    String getScopeString();

    void setAttribute(String name, Object value);

    <T> T getAttribute(String attribute, Class<T> clazz);

}
