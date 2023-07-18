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

import org.keycloak.Config;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.provider.ProviderEventListener;

import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 登录协议工厂基类
 */
public abstract class AbstractLoginProtocolFactory implements LoginProtocolFactory {

    @Override
    public void init(Config.Scope config) {
    }

    /**
     * 添加一个新的事件监听器
     * @param factory
     */
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(new ProviderEventListener() {
            @Override
            public void onEvent(ProviderEvent event) {
                // 一旦监听到某个client被创建  添加一些默认属性
                if (event instanceof ClientModel.ClientCreationEvent) {
                    ClientModel client = ((ClientModel.ClientCreationEvent)event).getCreatedClient();
                    addDefaultClientScopes(client.getRealm(), client);
                    addDefaults(client);
                }
            }
        });
    }


    @Override
    public void createDefaultClientScopes(RealmModel newRealm, boolean addScopesToExistingClients) {
        createDefaultClientScopesImpl(newRealm);

        // Create default client scopes for realm built-in clients too
        if (addScopesToExistingClients) {
            // 连同该realm关联的一组client 为他们设置client_scope
            addDefaultClientScopes(newRealm, newRealm.getClientsStream());
        }
    }

    /**
     * Impl should create default client scopes. This is called usually when new realm is created
     * 当realm被创建时 协助创建默认的client_scope  具体逻辑由子类实现
     */
    protected abstract void createDefaultClientScopesImpl(RealmModel newRealm);


    /**
     * 在该realm下 为client创建默认的client_scope
     * @param realm
     * @param newClient
     */
    protected void addDefaultClientScopes(RealmModel realm, ClientModel newClient) {
        addDefaultClientScopes(realm, Stream.of(newClient));
    }

    /**
     * 为一组client 创建默认的client_scope
     * @param realm
     * @param newClients
     */
    protected void addDefaultClientScopes(RealmModel realm, Stream<ClientModel> newClients) {

        // 注意scope是有protocol概念的  protocol需要匹配

        // realm的信息中有这些scope
        Set<ClientScopeModel> defaultClientScopes = realm.getDefaultClientScopesStream(true)
                .filter(clientScope -> Objects.equals(getId(), clientScope.getProtocol()))
                .collect(Collectors.toSet());

        // 非default的也可以查的到
        Set<ClientScopeModel> nonDefaultClientScopes = realm.getDefaultClientScopesStream(false)
                .filter(clientScope -> Objects.equals(getId(), clientScope.getProtocol()))
                .collect(Collectors.toSet());

        // 将关联数据落入持久层
        Consumer<ClientModel> addDefault = c -> c.addClientScopes(defaultClientScopes, true);
        Consumer<ClientModel> addNonDefault = c -> c.addClientScopes(nonDefaultClientScopes, false);

        if (!defaultClientScopes.isEmpty() && !nonDefaultClientScopes.isEmpty())
            newClients.forEach(addDefault.andThen(addNonDefault));
        else if (!defaultClientScopes.isEmpty())
            newClients.forEach(addDefault);
        else if (!nonDefaultClientScopes.isEmpty())
            newClients.forEach(addNonDefault);
    }

    /**
     * 添加一些默认数据 由子类拓展
     * @param realm
     */
    protected abstract void addDefaults(ClientModel realm);

    @Override
    public void close() {

    }
}
