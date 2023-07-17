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

package org.keycloak.models.sessions.infinispan;

import org.keycloak.cluster.ClusterProvider;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.infinispan.Cache;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.cache.infinispan.events.AuthenticationSessionAuthNoteUpdateEvent;
import org.keycloak.models.sessions.infinispan.entities.RootAuthenticationSessionEntity;
import org.keycloak.models.sessions.infinispan.events.RealmRemovedSessionEvent;
import org.keycloak.models.sessions.infinispan.events.SessionEventsSenderTransaction;
import org.keycloak.models.sessions.infinispan.stream.RootAuthenticationSessionPredicate;
import org.keycloak.models.sessions.infinispan.util.InfinispanKeyGenerator;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RealmInfoUtil;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 通过缓存对象提供认证会话数据
 */
public class InfinispanAuthenticationSessionProvider implements AuthenticationSessionProvider {

    private static final Logger log = Logger.getLogger(InfinispanAuthenticationSessionProvider.class);

    /**
     * 通过该对象可以拿到各种信息
     */
    private final KeycloakSession session;

    /**
     * 该provider 会维护root对象 每个root 又可以向下延展出很多子认证会话
     */
    private final Cache<String, RootAuthenticationSessionEntity> cache;

    /**
     * 为会话产生为唯一id
     */
    private final InfinispanKeyGenerator keyGenerator;

    /**
     * 可以批量执行一组任务  都是与缓存服务器的交互
     */
    protected final InfinispanKeycloakTransaction tx;

    /**
     * TODO DC相关 先忽略
     */
    protected final SessionEventsSenderTransaction clusterEventsSenderTx;

    public InfinispanAuthenticationSessionProvider(KeycloakSession session, InfinispanKeyGenerator keyGenerator, Cache<String, RootAuthenticationSessionEntity> cache) {
        this.session = session;
        this.cache = cache;
        this.keyGenerator = keyGenerator;

        this.tx = new InfinispanKeycloakTransaction();
        this.clusterEventsSenderTx = new SessionEventsSenderTransaction(session);

        // 把他们放入一个大的会话管理器中
        session.getTransactionManager().enlistAfterCompletion(tx);
        session.getTransactionManager().enlistAfterCompletion(clusterEventsSenderTx);
    }

    /**
     * 产生属于某个realm下的root认证会话  实际上应该是对应一个用户   但是该怎么反向检索某个用户的root认证会话呢 ？？？
     * @param realm {@code RealmModel} Can't be {@code null}.
     * @return
     */
    @Override
    public RootAuthenticationSessionModel createRootAuthenticationSession(RealmModel realm) {
        String id = keyGenerator.generateKeyString(session, cache);
        return createRootAuthenticationSession(realm, id);
    }


    /**
     * 创建 root 认证会话对象   与用户会话 一一对应
     * @param realm {@code RealmModel} Can't be {@code null}.
     * @param id {@code String} Id of newly created root authentication session. If {@code null} a random id will be generated.
     * @return
     */
    @Override
    public RootAuthenticationSessionModel createRootAuthenticationSession(RealmModel realm, String id) {
        RootAuthenticationSessionEntity entity = new RootAuthenticationSessionEntity();
        entity.setId(id);
        entity.setRealmId(realm.getId());
        entity.setTimestamp(Time.currentTime());

        // 获取会话存活时长
        int expirationSeconds = RealmInfoUtil.getDettachedClientSessionLifespan(realm);
        // 存储到缓存服务器  同时指定存活时长
        tx.put(cache, id, entity, expirationSeconds, TimeUnit.SECONDS);

        return wrap(realm, entity);
    }


    /**
     * 包装root 认证会话
     * @param realm
     * @param entity
     * @return
     */
    private RootAuthenticationSessionAdapter wrap(RealmModel realm, RootAuthenticationSessionEntity entity) {
        return entity==null ? null : new RootAuthenticationSessionAdapter(session, this, cache, realm, entity);
    }


    /**
     * 通过会话id 检索某个认证会话
     * @param authSessionId
     * @return
     */
    private RootAuthenticationSessionEntity getRootAuthenticationSessionEntity(String authSessionId) {
        // Chance created in this transaction
        RootAuthenticationSessionEntity entity = tx.get(cache, authSessionId);
        return entity;
    }

    @Override
    public void removeAllExpired() {
        // Rely on expiration of cache entries provided by infinispan. Nothing needed here
    }

    @Override
    public void removeExpired(RealmModel realm) {
        // Rely on expiration of cache entries provided by infinispan. Nothing needed here
    }

    /**
     * TODO
     * @param realm {@code RealmModel} Can't be {@code null}.
     */
    @Override
    public void onRealmRemoved(RealmModel realm) {
        // Send message to all DCs. The remoteCache will notify client listeners on all DCs for remove authentication sessions
        clusterEventsSenderTx.addEvent(
                RealmRemovedSessionEvent.createEvent(RealmRemovedSessionEvent.class, InfinispanAuthenticationSessionProviderFactory.REALM_REMOVED_AUTHSESSION_EVENT, session, realm.getId(), false),
                ClusterProvider.DCNotify.ALL_DCS);
    }

    /**
     * 从缓存服务器上移除某个realm 相关的所有会话
     * @param realmId
     */
    protected void onRealmRemovedEvent(String realmId) {
        Iterator<Map.Entry<String, RootAuthenticationSessionEntity>> itr = CacheDecorators.localCache(cache)
                .entrySet()
                .stream()
                .filter(RootAuthenticationSessionPredicate.create(realmId))
                .iterator();

        while (itr.hasNext()) {
            CacheDecorators.localCache(cache)
                    .remove(itr.next().getKey());
        }
    }


    @Override
    public void onClientRemoved(RealmModel realm, ClientModel client) {
        // No update anything on clientRemove for now. AuthenticationSessions of removed client will be handled at runtime if needed.

//        clusterEventsSenderTx.addEvent(
//                ClientRemovedSessionEvent.create(session, InfinispanAuthenticationSessionProviderFactory.CLIENT_REMOVED_AUTHSESSION_EVENT, realm.getId(), false, client.getId()),
//                ClusterProvider.DCNotify.ALL_DCS);
    }

    protected void onClientRemovedEvent(String realmId, String clientUuid) {

    }

    /**
     * TODO
     * @param compoundId {@code AuthenticationSessionCompoundId} The method has no effect if {@code null}.
     * @param authNotesFragment {@code Map<String, String>} Map with authNote values.
     */
    @Override
    public void updateNonlocalSessionAuthNotes(AuthenticationSessionCompoundId compoundId, Map<String, String> authNotesFragment) {
        if (compoundId == null) {
            return;
        }

        ClusterProvider cluster = session.getProvider(ClusterProvider.class);
        cluster.notify(
          InfinispanAuthenticationSessionProviderFactory.AUTHENTICATION_SESSION_EVENTS,
          AuthenticationSessionAuthNoteUpdateEvent.create(compoundId.getRootSessionId(), compoundId.getTabId(), compoundId.getClientUUID(), authNotesFragment),
          true,
          ClusterProvider.DCNotify.ALL_BUT_LOCAL_DC
        );
    }


    /**
     * 通过id 检索认证会话   并进行包装
     * @param realm {@code RealmModel} Can't be {@code null}.
     * @param authenticationSessionId {@code RootAuthenticationSessionModel} If {@code null} then {@code null} will be returned.
     * @return
     */
    @Override
    public RootAuthenticationSessionModel getRootAuthenticationSession(RealmModel realm, String authenticationSessionId) {
        RootAuthenticationSessionEntity entity = getRootAuthenticationSessionEntity(authenticationSessionId);
        return wrap(realm, entity);
    }


    @Override
    public void removeRootAuthenticationSession(RealmModel realm, RootAuthenticationSessionModel authenticationSession) {
        tx.remove(cache, authenticationSession.getId());
    }

    @Override
    public void close() {

    }

    public Cache<String, RootAuthenticationSessionEntity> getCache() {
        return cache;
    }


    protected String generateTabId() {
        return Base64Url.encode(KeycloakModelUtils.generateSecret(8));
    }
}
