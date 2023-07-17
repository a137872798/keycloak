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

package org.keycloak.models.sessions.infinispan;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.infinispan.Cache;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.sessions.infinispan.entities.AuthenticationSessionEntity;
import org.keycloak.models.sessions.infinispan.entities.RootAuthenticationSessionEntity;
import org.keycloak.models.utils.RealmInfoUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * root认证会话对象  可以基于不同的client产生子会话
 */
public class RootAuthenticationSessionAdapter implements RootAuthenticationSessionModel {

    /**
     * 通过该对象可以获取其他对象   类似与一个大的上下文
     */
    private KeycloakSession session;
    private InfinispanAuthenticationSessionProvider provider;
    /**
     * 可以通过它检索其他用户的认证会话信息
     */
    private Cache<String, RootAuthenticationSessionEntity> cache;
    private RealmModel realm;
    private RootAuthenticationSessionEntity entity;

    public RootAuthenticationSessionAdapter(KeycloakSession session, InfinispanAuthenticationSessionProvider provider,
                                            Cache<String, RootAuthenticationSessionEntity> cache, RealmModel realm,
                                            RootAuthenticationSessionEntity entity) {
        this.session = session;
        this.provider = provider;
        this.cache = cache;
        this.realm = realm;
        this.entity = entity;
    }

    /**
     * 更新本root认证会话的有效时间
     */
    void update() {
        int expirationSeconds = RealmInfoUtil.getDettachedClientSessionLifespan(realm);
        provider.tx.replace(cache, entity.getId(), entity, expirationSeconds, TimeUnit.SECONDS);
    }


    @Override
    public String getId() {
        return entity.getId();
    }

    @Override
    public RealmModel getRealm() {
        return realm;
    }

    @Override
    public int getTimestamp() {
        return entity.getTimestamp();
    }

    @Override
    public void setTimestamp(int timestamp) {
        entity.setTimestamp(timestamp);
        update();
    }

    /**
     * 返回该root 关联的所有子认证会话
     * @return
     */
    @Override
    public Map<String, AuthenticationSessionModel> getAuthenticationSessions() {
        Map<String, AuthenticationSessionModel> result = new HashMap<>();

        for (Map.Entry<String, AuthenticationSessionEntity> entry : entity.getAuthenticationSessions().entrySet()) {
            String tabId = entry.getKey();
            result.put(tabId , new AuthenticationSessionAdapter(session, this, tabId, entry.getValue()));
        }

        return result;
    }

    /**
     * root认证会话对应某个用户  每个用户会话可以关联到多个client上      相对的 每个root认证会话 可以关联多个子认证会话  一个子认证会话对应一个client
     * @param client {@code ClientModel} If {@code null} is provided the method will return {@code null}.
     * @param tabId {@code String} If {@code null} is provided the method will return {@code null}.
     * @return
     */
    @Override
    public AuthenticationSessionModel getAuthenticationSession(ClientModel client, String tabId) {
        if (client == null || tabId == null) {
            return null;
        }

        AuthenticationSessionModel authSession = getAuthenticationSessions().get(tabId);

        // 要求client匹配
        if (authSession != null && client.equals(authSession.getClient())) {
            session.getContext().setAuthenticationSession(authSession);
            return authSession;
        } else {
            return null;
        }
    }

    /**
     * 在root认证会话下  产生一个关于某client的子会话
     * @param client {@code ClientModel} Can't be {@code null}.
     * @return
     */
    @Override
    public AuthenticationSessionModel createAuthenticationSession(ClientModel client) {
        AuthenticationSessionEntity authSessionEntity = new AuthenticationSessionEntity();
        authSessionEntity.setClientUUID(client.getId());

        String tabId = provider.generateTabId();
        entity.getAuthenticationSessions().put(tabId, authSessionEntity);

        // Update our timestamp when adding new authenticationSession
        entity.setTimestamp(Time.currentTime());

        // 因为该root下增加了一个新的子认证 需要更新到缓存服务器上
        update();

        AuthenticationSessionAdapter authSession = new AuthenticationSessionAdapter(session, this, tabId, authSessionEntity);
        session.getContext().setAuthenticationSession(authSession);
        return authSession;
    }

    @Override
    public void removeAuthenticationSessionByTabId(String tabId) {
        if (entity.getAuthenticationSessions().remove(tabId) != null) {
            // 当root会话下没有子认证会话时  该root也就没有存在必要了   也就是需要创建root会话时 一般至少会关联一个子认证会话  和user session/client session的关系一样
            if (entity.getAuthenticationSessions().isEmpty()) {
                provider.tx.remove(cache, entity.getId());
            } else {
                entity.setTimestamp(Time.currentTime());
                update();
            }
        }
    }

    /**
     * 清除root下所有子认证会话
     * @param realm {@code RealmModel} Associated realm to the root authentication session.
     */
    @Override
    public void restartSession(RealmModel realm) {
        entity.getAuthenticationSessions().clear();
        entity.setTimestamp(Time.currentTime());
        update();
    }
}
