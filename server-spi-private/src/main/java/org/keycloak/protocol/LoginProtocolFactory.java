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

import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.idm.ClientRepresentation;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 登录协议工厂 不同的协议对应不同的对象
 */
public interface LoginProtocolFactory extends ProviderFactory<LoginProtocol> {
    /**
     * List of builtin protocol mappers that can be used to apply to clients.
     *
     * @return
     * 内建的协议映射
     */
    Map<String, ProtocolMapperModel> getBuiltinMappers();


    /**
     * 每个协议要暴露一些端点  用于提供能力
     * @param realm
     * @param event
     * @return
     */
    Object createProtocolEndpoint(RealmModel realm, EventBuilder event);


    /**
     * Called when new realm is created
     * 当新的realm被创建时  为其添加client_scope
     *
     * @param newRealm
     * @param addScopesToExistingClients If true, then existing realm clients will be updated (created realm default scopes will be added to them)
     */
    void createDefaultClientScopes(RealmModel newRealm, boolean addScopesToExistingClients);


    /**
     * Setup default values for new clients. This expects that the representation has already set up the client
     *                  当新的client被创建时 设置一些默认值
     * @param rep
     * @param newClient
     */
    void setupClientDefaults(ClientRepresentation rep, ClientModel newClient);

}
