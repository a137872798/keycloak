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

import org.infinispan.Cache;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.client.hotrod.exceptions.HotRodClientException;
import org.infinispan.context.Flag;
import org.infinispan.stream.CacheCollectors;
import org.jboss.logging.Logger;
import org.keycloak.cluster.ClusterProvider;
import org.keycloak.common.util.Retry;
import org.keycloak.common.util.Time;
import org.keycloak.device.DeviceActivityManager;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OfflineUserSessionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.session.UserSessionPersisterProvider;
import org.keycloak.models.sessions.infinispan.changes.Tasks;
import org.keycloak.models.sessions.infinispan.changes.sessions.CrossDCLastSessionRefreshStore;
import org.keycloak.models.sessions.infinispan.changes.sessions.PersisterLastSessionRefreshStore;
import org.keycloak.models.sessions.infinispan.remotestore.RemoteCacheInvoker;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.changes.InfinispanChangelogBasedTransaction;
import org.keycloak.models.sessions.infinispan.changes.SessionUpdateTask;
import org.keycloak.models.sessions.infinispan.entities.AuthenticatedClientSessionEntity;
import org.keycloak.models.sessions.infinispan.entities.AuthenticatedClientSessionStore;
import org.keycloak.models.sessions.infinispan.entities.LoginFailureEntity;
import org.keycloak.models.sessions.infinispan.entities.LoginFailureKey;
import org.keycloak.models.sessions.infinispan.entities.UserSessionEntity;
import org.keycloak.models.sessions.infinispan.events.RealmRemovedSessionEvent;
import org.keycloak.models.sessions.infinispan.events.RemoveAllUserLoginFailuresEvent;
import org.keycloak.models.sessions.infinispan.events.RemoveUserSessionsEvent;
import org.keycloak.models.sessions.infinispan.events.SessionEventsSenderTransaction;
import org.keycloak.models.sessions.infinispan.stream.Comparators;
import org.keycloak.models.sessions.infinispan.stream.Mappers;
import org.keycloak.models.sessions.infinispan.stream.SessionPredicate;
import org.keycloak.models.sessions.infinispan.stream.UserLoginFailurePredicate;
import org.keycloak.models.sessions.infinispan.stream.UserSessionPredicate;
import org.keycloak.models.sessions.infinispan.util.FuturesHelper;
import org.keycloak.models.sessions.infinispan.util.InfinispanKeyGenerator;
import org.keycloak.models.sessions.infinispan.util.InfinispanUtil;
import org.keycloak.models.sessions.infinispan.util.SessionTimeouts;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.keycloak.utils.StreamsUtil.paginatedStream;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * 通过缓存维护用户会话
 */
public class InfinispanUserSessionProvider implements UserSessionProvider {

    private static final Logger log = Logger.getLogger(InfinispanUserSessionProvider.class);

    protected final KeycloakSession session;

    // 访问缓存的句柄
    protected final Cache<String, SessionEntityWrapper<UserSessionEntity>> sessionCache;
    protected final Cache<String, SessionEntityWrapper<UserSessionEntity>> offlineSessionCache;
    // 存储的是client级别的会话
    protected final Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> clientSessionCache;
    protected final Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> offlineClientSessionCache;
    protected final Cache<LoginFailureKey, SessionEntityWrapper<LoginFailureEntity>> loginFailureCache;

    // 为针对每种缓存数据的操作增加了事务概念
    protected final InfinispanChangelogBasedTransaction<String, UserSessionEntity> sessionTx;
    protected final InfinispanChangelogBasedTransaction<String, UserSessionEntity> offlineSessionTx;
    protected final InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> clientSessionTx;
    protected final InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> offlineClientSessionTx;
    protected final InfinispanChangelogBasedTransaction<LoginFailureKey, LoginFailureEntity> loginFailuresTx;

    protected final SessionEventsSenderTransaction clusterEventsSenderTx;

    // 代表发起跨数据中心(DC)的同步
    protected final CrossDCLastSessionRefreshStore lastSessionRefreshStore;
    protected final CrossDCLastSessionRefreshStore offlineLastSessionRefreshStore;
    // 每隔一定时间将会话最后的访问时间更新到DB
    protected final PersisterLastSessionRefreshStore persisterLastSessionRefreshStore;

    // 该对象可以将会话数据写入远端缓存
    protected final RemoteCacheInvoker remoteCacheInvoker;
    protected final InfinispanKeyGenerator keyGenerator;

    public InfinispanUserSessionProvider(KeycloakSession session,
                                         RemoteCacheInvoker remoteCacheInvoker,
                                         CrossDCLastSessionRefreshStore lastSessionRefreshStore,
                                         CrossDCLastSessionRefreshStore offlineLastSessionRefreshStore,
                                         PersisterLastSessionRefreshStore persisterLastSessionRefreshStore,
                                         InfinispanKeyGenerator keyGenerator,
                                         Cache<String, SessionEntityWrapper<UserSessionEntity>> sessionCache,
                                         Cache<String, SessionEntityWrapper<UserSessionEntity>> offlineSessionCache,
                                         Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> clientSessionCache,
                                         Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> offlineClientSessionCache,
                                         Cache<LoginFailureKey, SessionEntityWrapper<LoginFailureEntity>> loginFailureCache) {
        this.session = session;

        this.sessionCache = sessionCache;
        this.clientSessionCache = clientSessionCache;
        this.offlineSessionCache = offlineSessionCache;
        this.offlineClientSessionCache = offlineClientSessionCache;
        this.loginFailureCache = loginFailureCache;

        this.sessionTx = new InfinispanChangelogBasedTransaction<>(session, sessionCache, remoteCacheInvoker, SessionTimeouts::getUserSessionLifespanMs, SessionTimeouts::getUserSessionMaxIdleMs);
        this.offlineSessionTx = new InfinispanChangelogBasedTransaction<>(session, offlineSessionCache, remoteCacheInvoker, SessionTimeouts::getOfflineSessionLifespanMs, SessionTimeouts::getOfflineSessionMaxIdleMs);
        this.clientSessionTx = new InfinispanChangelogBasedTransaction<>(session, clientSessionCache, remoteCacheInvoker, SessionTimeouts::getClientSessionLifespanMs, SessionTimeouts::getClientSessionMaxIdleMs);
        this.offlineClientSessionTx = new InfinispanChangelogBasedTransaction<>(session, offlineClientSessionCache, remoteCacheInvoker, SessionTimeouts::getOfflineClientSessionLifespanMs, SessionTimeouts::getOfflineClientSessionMaxIdleMs);

        this.loginFailuresTx = new InfinispanChangelogBasedTransaction<>(session, loginFailureCache, remoteCacheInvoker, SessionTimeouts::getLoginFailuresLifespanMs, SessionTimeouts::getLoginFailuresMaxIdleMs);

        this.clusterEventsSenderTx = new SessionEventsSenderTransaction(session);

        this.lastSessionRefreshStore = lastSessionRefreshStore;
        this.offlineLastSessionRefreshStore = offlineLastSessionRefreshStore;
        this.persisterLastSessionRefreshStore = persisterLastSessionRefreshStore;
        this.remoteCacheInvoker = remoteCacheInvoker;
        this.keyGenerator = keyGenerator;

        // 这些操作都会纳入到外层的事务中
        session.getTransactionManager().enlistAfterCompletion(clusterEventsSenderTx);
        session.getTransactionManager().enlistAfterCompletion(sessionTx);
        session.getTransactionManager().enlistAfterCompletion(offlineSessionTx);
        session.getTransactionManager().enlistAfterCompletion(clientSessionTx);
        session.getTransactionManager().enlistAfterCompletion(offlineClientSessionTx);
        session.getTransactionManager().enlistAfterCompletion(loginFailuresTx);
    }

    /**
     * 根据是否离线 获取的缓存是不一样的
     * @param offline
     * @return
     */
    protected Cache<String, SessionEntityWrapper<UserSessionEntity>> getCache(boolean offline) {
        return offline ? offlineSessionCache : sessionCache;
    }

    protected InfinispanChangelogBasedTransaction<String, UserSessionEntity> getTransaction(boolean offline) {
        return offline ? offlineSessionTx : sessionTx;
    }

    protected Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> getClientSessionCache(boolean offline) {
        return offline ? offlineClientSessionCache : clientSessionCache;
    }

    protected InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> getClientSessionTransaction(boolean offline) {
        return offline ? offlineClientSessionTx : clientSessionTx;
    }

    protected CrossDCLastSessionRefreshStore getLastSessionRefreshStore() {
        return lastSessionRefreshStore;
    }

    protected CrossDCLastSessionRefreshStore getOfflineLastSessionRefreshStore() {
        return offlineLastSessionRefreshStore;
    }

    protected PersisterLastSessionRefreshStore getPersisterLastSessionRefreshStore() {
        return persisterLastSessionRefreshStore;
    }

    /**
     * 创建客户端级别的会话对象  client会话跟user会话强关联
     * @param realm
     * @param client
     * @param userSession
     * @return
     */
    @Override
    public AuthenticatedClientSessionModel createClientSession(RealmModel realm, ClientModel client, UserSessionModel userSession) {
        final UUID clientSessionId = keyGenerator.generateKeyUUID(session, clientSessionCache);

        // 产生一个会话id 并包装成client会话实体
        AuthenticatedClientSessionEntity entity = new AuthenticatedClientSessionEntity(clientSessionId);
        // 设置会话相关的领域id 和时间戳
        entity.setRealmId(realm.getId());
        entity.setTimestamp(Time.currentTime());

        // 根据是否是离线会话 返回不同的事务对象
        InfinispanChangelogBasedTransaction<String, UserSessionEntity> userSessionUpdateTx = getTransaction(false);
        // 返回client会话
        InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> clientSessionUpdateTx = getClientSessionTransaction(false);

        // 通过该对象可以修改 client session
        AuthenticatedClientSessionAdapter adapter = new AuthenticatedClientSessionAdapter(session, this, entity, client, userSession, clientSessionUpdateTx, false);

        // For now, the clientSession is considered transient in case that userSession was transient
        UserSessionModel.SessionPersistenceState persistenceState = (userSession instanceof UserSessionAdapter && ((UserSessionAdapter) userSession).getPersistenceState() != null) ?
                ((UserSessionAdapter) userSession).getPersistenceState() : UserSessionModel.SessionPersistenceState.PERSISTENT;

        // 代表要将client session 存储到缓存服务器
        SessionUpdateTask<AuthenticatedClientSessionEntity> createClientSessionTask = Tasks.addIfAbsentSync();
        clientSessionUpdateTx.addTask(clientSessionId, createClientSessionTask, entity, persistenceState);

        // 需要将client 会话关联到用户会话上
        SessionUpdateTask registerClientSessionTask = new RegisterClientSessionTask(client.getId(), clientSessionId);
        userSessionUpdateTx.addTask(userSession.getId(), registerClientSessionTask);

        return adapter;
    }

    /**
     * 先创建用户会话 之后才是client会话
     * @param realm
     * @param user
     * @param loginUsername
     * @param ipAddress
     * @param authMethod
     * @param rememberMe
     * @param brokerSessionId
     * @param brokerUserId
     * @return
     */
    @Override
    public UserSessionModel createUserSession(RealmModel realm, UserModel user, String loginUsername, String ipAddress, String authMethod, boolean rememberMe, String brokerSessionId, String brokerUserId) {
        // 产生一个会话id
        final String userSessionId = keyGenerator.generateKeyString(session, sessionCache);
        // 使用该方法产生的会话需要做持久化
        return createUserSession(userSessionId, realm, user, loginUsername, ipAddress, authMethod, rememberMe, brokerSessionId, brokerUserId, UserSessionModel.SessionPersistenceState.PERSISTENT);
    }

    /**
     * 创建用户会话  也就是用户通过验证 产生token并生成与之关联的会话的过程
     * @param id
     * @param realm
     * @param user
     * @param loginUsername
     * @param ipAddress
     * @param authMethod
     * @param rememberMe
     * @param brokerSessionId
     * @param brokerUserId
     * @param persistenceState
     * @return
     */
    @Override
    public UserSessionModel createUserSession(String id, RealmModel realm, UserModel user, String loginUsername, String ipAddress,
                                              String authMethod, boolean rememberMe, String brokerSessionId, String brokerUserId, UserSessionModel.SessionPersistenceState persistenceState) {
        UserSessionEntity entity = new UserSessionEntity();
        entity.setId(id);
        // 将用户的各种信息填充到会话中
        updateSessionEntity(entity, realm, user, loginUsername, ipAddress, authMethod, rememberMe, brokerSessionId, brokerUserId);

        // 生成一个标号task 无逻辑 代表标识了期望的Operation
        SessionUpdateTask<UserSessionEntity> createSessionTask = Tasks.addIfAbsentSync();
        // 记录任务
        sessionTx.addTask(id, createSessionTask, entity, persistenceState);

        // 包装会话对象  默认创建的是在线会话
        UserSessionAdapter adapter = wrap(realm, entity, false);
        adapter.setPersistenceState(persistenceState);

        // TODO 先忽略设备类型
        if (adapter != null) {
            DeviceActivityManager.attachDevice(adapter, session);
        }

        return adapter;
    }

    /**
     * 更新会话实体
     * @param entity
     * @param realm
     * @param user
     * @param loginUsername
     * @param ipAddress
     * @param authMethod
     * @param rememberMe
     * @param brokerSessionId
     * @param brokerUserId
     */
    void updateSessionEntity(UserSessionEntity entity, RealmModel realm, UserModel user, String loginUsername, String ipAddress, String authMethod, boolean rememberMe, String brokerSessionId, String brokerUserId) {
        entity.setRealmId(realm.getId());
        entity.setUser(user.getId());
        entity.setLoginUsername(loginUsername);
        entity.setIpAddress(ipAddress);
        entity.setAuthMethod(authMethod);
        entity.setRememberMe(rememberMe);
        entity.setBrokerSessionId(brokerSessionId);
        entity.setBrokerUserId(brokerUserId);

        int currentTime = Time.currentTime();

        entity.setStarted(currentTime);
        entity.setLastSessionRefresh(currentTime);


    }


    /**
     * 获取用户会话
     * @param realm
     * @param id
     * @return
     */
    @Override
    public UserSessionModel getUserSession(RealmModel realm, String id) {
        return getUserSession(realm, id, false);
    }

    protected UserSessionAdapter getUserSession(RealmModel realm, String id, boolean offline) {
        UserSessionEntity entity = getUserSessionEntity(realm, id, offline);
        return wrap(realm, entity, offline);
    }

    /**
     * 从本地缓存中查询会话
     * @param realm
     * @param id
     * @param offline
     * @return
     */
    private UserSessionEntity getUserSessionEntity(RealmModel realm, String id, boolean offline) {
        InfinispanChangelogBasedTransaction<String, UserSessionEntity> tx = getTransaction(offline);
        // 每个session 有自己的id
        SessionEntityWrapper<UserSessionEntity> entityWrapper = tx.get(id);
        if (entityWrapper==null) return null;
        UserSessionEntity entity = entityWrapper.getEntity();

        // 要求会话的realm id 匹配
        if (!entity.getRealmId().equals(realm.getId())) return null;
        return entity;
    }


    /**
     * 通过过滤器得到一组满足条件的用户会话
     * @param realm
     * @param predicate
     * @param offline
     * @return
     */
    protected Stream<UserSessionModel> getUserSessionsStream(RealmModel realm, Predicate<Map.Entry<String, SessionEntityWrapper<UserSessionEntity>>> predicate, boolean offline) {
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache = getCache(offline);
        // 对cache做一层包装  TODO 先不考虑
        cache = CacheDecorators.skipCacheLoaders(cache);

        // return a stream that 'wraps' the infinispan cache stream so that the cache stream's elements are read one by one
        // and then filtered/mapped locally to avoid serialization issues when trying to manipulate the cache stream directly.
        return StreamSupport.stream(cache.entrySet().stream().spliterator(), true)
                .filter(predicate)
                .map(Mappers.userSessionEntity())
                .map(entity -> this.wrap(realm, entity, offline));
    }

    /**
     * 创建客户端会话
     * @param userSession
     * @param client
     * @param clientSessionId
     * @param offline
     * @return
     */
    @Override
    public AuthenticatedClientSessionAdapter getClientSession(UserSessionModel userSession, ClientModel client, UUID clientSessionId, boolean offline) {
        AuthenticatedClientSessionEntity entity = getClientSessionEntity(clientSessionId, offline);
        return wrap(userSession, client, entity, offline);
    }

    /**
     * 通过id 精准定位到一个client session
     * @param id
     * @param offline
     * @return
     */
    private AuthenticatedClientSessionEntity getClientSessionEntity(UUID id, boolean offline) {
        InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> tx = getClientSessionTransaction(offline);
        SessionEntityWrapper<AuthenticatedClientSessionEntity> entityWrapper = tx.get(id);
        return entityWrapper == null ? null : entityWrapper.getEntity();
    }


    @Override
    public Stream<UserSessionModel> getUserSessionsStream(final RealmModel realm, UserModel user) {
        return getUserSessionsStream(realm, UserSessionPredicate.create(realm.getId()).user(user.getId()), false);
    }

    @Override
    public Stream<UserSessionModel> getUserSessionByBrokerUserIdStream(RealmModel realm, String brokerUserId) {
        return getUserSessionsStream(realm, UserSessionPredicate.create(realm.getId()).brokerUserId(brokerUserId), false);
    }

    @Override
    public UserSessionModel getUserSessionByBrokerSessionId(RealmModel realm, String brokerSessionId) {
        return this.getUserSessionsStream(realm, UserSessionPredicate.create(realm.getId()).brokerSessionId(brokerSessionId), false)
                .findFirst().orElse(null);
    }

    /**
     * 返回所有
     * @param realm a reference to the realm.
     * @param client the client whose user sessions are being searched.
     * @return
     */
    @Override
    public Stream<UserSessionModel> getUserSessionsStream(RealmModel realm, ClientModel client) {
        return getUserSessionsStream(realm, client, -1, -1);
    }

    /**
     * 限制返回条数
     * @param realm a reference tot he realm.
     * @param client the client whose user sessions are being searched.
     * @param firstResult first result to return. Ignored if negative or {@code null}.
     * @param maxResults maximum number of results to return. Ignored if negative or {@code null}.
     * @return
     */
    @Override
    public Stream<UserSessionModel> getUserSessionsStream(RealmModel realm, ClientModel client, Integer firstResult, Integer maxResults) {
        return getUserSessionsStream(realm, client, firstResult, maxResults, false);
    }

    /**
     * 返回包含该client id的所有用户会话
     * @param realm
     * @param client
     * @param firstResult
     * @param maxResults
     * @param offline
     * @return
     */
    protected Stream<UserSessionModel> getUserSessionsStream(final RealmModel realm, ClientModel client, Integer firstResult, Integer maxResults, final boolean offline) {
        final String clientUuid = client.getId();
        UserSessionPredicate predicate = UserSessionPredicate.create(realm.getId()).client(clientUuid);

        return getUserSessionModels(realm, firstResult, maxResults, offline, predicate);
    }

    /**
     * 追加 offset, limit
     * @param realm
     * @param firstResult
     * @param maxResults
     * @param offline
     * @param predicate
     * @return
     */
    protected Stream<UserSessionModel> getUserSessionModels(RealmModel realm, Integer firstResult, Integer maxResults, boolean offline, UserSessionPredicate predicate) {
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache = getCache(offline);
        cache = CacheDecorators.skipCacheLoaders(cache);

        // return a stream that 'wraps' the infinispan cache stream so that the cache stream's elements are read one by one
        // and then filtered/mapped locally to avoid serialization issues when trying to manipulate the cache stream directly.
        Stream<UserSessionEntity> stream = StreamSupport.stream(cache.entrySet().stream().spliterator(), true)
                .filter(predicate)
                .map(Mappers.userSessionEntity())
                .sorted(Comparators.userSessionLastSessionRefresh());

        return paginatedStream(stream, firstResult, maxResults).map(entity -> this.wrap(realm, entity, offline));
    }

    /**
     * 通过predicate 过滤一组用户会话
     * @param realm
     * @param id
     * @param offline
     * @param predicate
     * @return
     */
    @Override
    public UserSessionModel getUserSessionWithPredicate(RealmModel realm, String id, boolean offline, Predicate<UserSessionModel> predicate) {

        // 通过id 精准定位 user session
        UserSessionModel userSession = getUserSession(realm, id, offline);
        if (userSession == null) {
            return null;
        }

        // We have userSession, which passes predicate. No need for remote lookup. 要求会话通过验证
        if (predicate.test(userSession)) {
            log.debugf("getUserSessionWithPredicate(%s): found in local cache", id);
            return userSession;
        }

        // Try lookup userSession from remoteCache    未通过验证的情况下 会尝试从缓存服务器拉取最新数据
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache = getCache(offline);

        // TODO 好像是那DC的缓存?   先忽略有关DC的逻辑
        RemoteCache remoteCache = InfinispanUtil.getRemoteCache(cache);

        if (remoteCache != null) {
            SessionEntityWrapper<UserSessionEntity> remoteSessionEntityWrapper = (SessionEntityWrapper<UserSessionEntity>) remoteCache.get(id);
            if (remoteSessionEntityWrapper != null) {
                UserSessionEntity remoteSessionEntity = remoteSessionEntityWrapper.getEntity();
                log.debugf("getUserSessionWithPredicate(%s): remote cache contains session entity %s", id, remoteSessionEntity);

                UserSessionModel remoteSessionAdapter = wrap(realm, remoteSessionEntity, offline);
                if (predicate.test(remoteSessionAdapter)) {

                    InfinispanChangelogBasedTransaction<String, UserSessionEntity> tx = getTransaction(offline);

                    // Remote entity contains our predicate. Update local cache with the remote entity
                    SessionEntityWrapper<UserSessionEntity> sessionWrapper = remoteSessionEntity.mergeRemoteEntityWithLocalEntity(tx.get(id));

                    // Replace entity just in ispn cache. Skip remoteStore
                    cache.getAdvancedCache().withFlags(Flag.SKIP_CACHE_STORE, Flag.SKIP_CACHE_LOAD, Flag.IGNORE_RETURN_VALUES)
                            .replace(id, sessionWrapper);

                    tx.reloadEntityInCurrentTransaction(realm, id, sessionWrapper);

                    // Recursion. We should have it locally now
                    return getUserSessionWithPredicate(realm, id, offline, predicate);
                } else {
                    log.debugf("getUserSessionWithPredicate(%s): found, but predicate doesn't pass", id);

                    return null;
                }
            } else {
                log.debugf("getUserSessionWithPredicate(%s): not found", id);

                // Session not available on remoteCache. Was already removed there. So removing locally too.
                // TODO: Can be optimized to skip calling remoteCache.remove
                removeUserSession(realm, userSession);

                return null;
            }
        } else {

            log.debugf("getUserSessionWithPredicate(%s): remote cache not available", id);

            return null;
        }
    }


    /**
     * 获取该client相关的所有用户存活 会话
     * @param realm
     * @param client
     * @return
     */
    @Override
    public long getActiveUserSessions(RealmModel realm, ClientModel client) {
        return getUserSessionsCount(realm, client, false);
    }

    /**
     * key 对应client id value 对应该client上出现的用户会话数量
     * @param realm
     * @param offline
     * @return
     */
    @Override
    public Map<String, Long> getActiveClientSessionStats(RealmModel realm, boolean offline) {
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache = getCache(offline);
        cache = CacheDecorators.skipCacheLoaders(cache);
        return cache.entrySet().stream()
                .filter(UserSessionPredicate.create(realm.getId()))

                // 将每个用户关联的client id 取出来
                .map(Mappers.authClientSessionSetMapper())
                .flatMap((Serializable & Function<Set<String>, Stream<? extends String>>)Mappers::toStream)
                .collect(
                        CacheCollectors.serializableCollector(
                                () -> Collectors.groupingBy(Function.identity(), Collectors.counting())
                        )
                );
    }

    /**
     * 返回 用户会话总数
     * @param realm
     * @param client
     * @param offline
     * @return
     */
     protected long getUserSessionsCount(RealmModel realm, ClientModel client, boolean offline) {
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache = getCache(offline);
        cache = CacheDecorators.skipCacheLoaders(cache);

        final String clientUuid = client.getId();

        return cache.entrySet().stream()
                .filter(UserSessionPredicate.create(realm.getId()).client(clientUuid))
                .count();
    }

    /**
     * 从本地 移除某个用户的会话信息  还会将连带的 client session 一并移除
     * @param realm
     * @param session
     */
    @Override
    public void removeUserSession(RealmModel realm, UserSessionModel session) {
        UserSessionEntity entity = getUserSessionEntity(realm, session, false);
        if (entity != null) {
            removeUserSession(entity, false);
        }
    }

    /**
     * 删除用户会话  这里通过user名 进行移除  也就是同一个用户允许同时存在多个会话   而精准定位一个用户会话就是通过id
     * 什么情况下一个用户可以产生多个会话呢
     * @param realm
     * @param user
     */
    @Override
    public void removeUserSessions(RealmModel realm, UserModel user) {
        removeUserSessions(realm, user, false);
    }

    protected void removeUserSessions(RealmModel realm, UserModel user, boolean offline) {
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache = getCache(offline);

        cache = CacheDecorators.skipCacheLoaders(cache);

        Iterator<UserSessionEntity> itr = cache.entrySet().stream().filter(UserSessionPredicate.create(realm.getId()).user(user.getId())).map(Mappers.userSessionEntity()).iterator();

        // 这样会连带删除 user 关联的client 会话
        while (itr.hasNext()) {
            UserSessionEntity userSessionEntity = itr.next();
            removeUserSession(userSessionEntity, offline);
        }
    }

    /**
     * 移除所有过期的 会话  这里针对范围是全realm
     */
    public void removeAllExpired() {
        // Rely on expiration of cache entries provided by infinispan. Just expire entries from persister is needed
        // TODO: Avoid iteration over all realms here (Details in the KEYCLOAK-16802)
        session.realms().getRealmsStream().forEach(this::removeExpired);

    }

    /**
     * 有基于 Infinispan的用户会话了  为什么又要与基于DB存储会话的对象产生联动呢
     * @param realm {@link RealmModel} Realm where all the expired user sessions to be removed from.
     */
    @Override
    public void removeExpired(RealmModel realm) {
        // Rely on expiration of cache entries provided by infinispan. Nothing needed here besides calling persister
        session.getProvider(UserSessionPersisterProvider.class).removeExpired(realm);
    }

    /**
     * 清除某个realm 下所有用户会话  TODO DC相关先忽略
     * @param realm
     */
    @Override
    public void removeUserSessions(RealmModel realm) {
        // Don't send message to all DCs, just to all cluster nodes in current DC. The remoteCache will notify client listeners for removed userSessions.
        clusterEventsSenderTx.addEvent(
                RemoveUserSessionsEvent.createEvent(RemoveUserSessionsEvent.class, InfinispanUserSessionProviderFactory.REMOVE_USER_SESSIONS_EVENT, session, realm.getId(), true),
                ClusterProvider.DCNotify.LOCAL_DC_ONLY);
    }

    /**
     * 在本地移除某个realm的会话
     * @param realmId
     */
    protected void onRemoveUserSessionsEvent(String realmId) {
        removeLocalUserSessions(realmId, false);
    }

    // public for usage in the testsuite     这个是清理缓存服务器  按时没有清理本地数据
    public void removeLocalUserSessions(String realmId, boolean offline) {
        FuturesHelper futures = new FuturesHelper();

        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache = getCache(offline);
        Cache<String, SessionEntityWrapper<UserSessionEntity>> localCache = CacheDecorators.localCache(cache);
        Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> clientSessionCache = getClientSessionCache(offline);
        Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> localClientSessionCache = CacheDecorators.localCache(clientSessionCache);

        Cache<String, SessionEntityWrapper<UserSessionEntity>> localCacheStoreIgnore = CacheDecorators.skipCacheLoaders(localCache);

        // 代表处理了多少用户session
        final AtomicInteger userSessionsSize = new AtomicInteger();

        // 找到该realm下的所有
        localCacheStoreIgnore
                .entrySet()
                .stream()
                .filter(SessionPredicate.create(realmId))
                .map(Mappers.userSessionEntity())
                .forEach(new Consumer<UserSessionEntity>() {

                    @Override
                    public void accept(UserSessionEntity userSessionEntity) {
                        userSessionsSize.incrementAndGet();

                        // Remove session from remoteCache too. Use removeAsync for better perf
                        Future future = localCache.removeAsync(userSessionEntity.getId());
                        futures.addTask(future);
                        userSessionEntity.getAuthenticatedClientSessions().forEach((clientUUID, clientSessionId) -> {
                            Future f = localClientSessionCache.removeAsync(clientSessionId);
                            futures.addTask(f);
                        });
                    }

                });


        futures.waitForAllToFinish();

        log.debugf("Removed %d sessions in realm %s. Offline: %b", (Object) userSessionsSize.get(), realmId, offline);
    }

    /**
     * 查找某个用户登录失败的信息
     * @param realm
     * @param userId
     * @return
     */
    @Override
    public UserLoginFailureModel getUserLoginFailure(RealmModel realm, String userId) {
        LoginFailureKey key = new LoginFailureKey(realm.getId(), userId);
        LoginFailureEntity entity = getLoginFailureEntity(key);
        // 将信息进一步包装
        return wrap(key, entity);
    }

    /**
     * 通过key 检索entity
     * @param key
     * @return
     */
    private LoginFailureEntity getLoginFailureEntity(LoginFailureKey key) {
        InfinispanChangelogBasedTransaction<LoginFailureKey, LoginFailureEntity> tx = getLoginFailuresTx();
        SessionEntityWrapper<LoginFailureEntity> entityWrapper = tx.get(key);
        return entityWrapper==null ? null : entityWrapper.getEntity();
    }

    /**
     * 由于一个用户登录失败事件 产生一个记录对象
     * @param realm
     * @param userId
     * @return
     */
    @Override
    public UserLoginFailureModel addUserLoginFailure(RealmModel realm, String userId) {
        LoginFailureKey key = new LoginFailureKey(realm.getId(), userId);
        LoginFailureEntity entity = new LoginFailureEntity();
        entity.setRealmId(realm.getId());
        entity.setUserId(userId);

        // 生成一个添加到缓存服务器的记录
        SessionUpdateTask<LoginFailureEntity> createLoginFailureTask = Tasks.addIfAbsentSync();
        loginFailuresTx.addTask(key, createLoginFailureTask, entity, UserSessionModel.SessionPersistenceState.PERSISTENT);

        return wrap(key, entity);
    }

    /**
     * 移除某个realm 下某个用户的登录失败记录
     * @param realm
     * @param userId
     */
    @Override
    public void removeUserLoginFailure(RealmModel realm, String userId) {
        SessionUpdateTask<LoginFailureEntity> removeTask = Tasks.removeSync();
        loginFailuresTx.addTask(new LoginFailureKey(realm.getId(), userId), removeTask);
    }

    /**
     * 移除该realm下所有用户的登录失败记录
     * TODO DC 先忽略
     * @param realm
     */
    @Override
    public void removeAllUserLoginFailures(RealmModel realm) {
        clusterEventsSenderTx.addEvent(
                RemoveAllUserLoginFailuresEvent.createEvent(RemoveAllUserLoginFailuresEvent.class, InfinispanUserSessionProviderFactory.REMOVE_ALL_LOGIN_FAILURES_EVENT, session, realm.getId(), true),
                ClusterProvider.DCNotify.LOCAL_DC_ONLY);
    }

    // TODO
    protected void onRemoveAllUserLoginFailuresEvent(String realmId) {
        removeAllLocalUserLoginFailuresEvent(realmId);
    }

    /**
     * 移除该realm下所有用户
     * @param realmId
     */
    private void removeAllLocalUserLoginFailuresEvent(String realmId) {
        FuturesHelper futures = new FuturesHelper();

        Cache<LoginFailureKey, SessionEntityWrapper<LoginFailureEntity>> localCache = CacheDecorators.localCache(loginFailureCache);

        Cache<LoginFailureKey, SessionEntityWrapper<LoginFailureEntity>> localCacheStoreIgnore = CacheDecorators.skipCacheLoaders(localCache);

        localCacheStoreIgnore
                .entrySet()
                .stream()
                .filter(UserLoginFailurePredicate.create(realmId))
                .map(Mappers.loginFailureId())
                .forEach(loginFailureKey -> {
                    // Remove loginFailure from remoteCache too. Use removeAsync for better perf
                    Future future = localCache.removeAsync(loginFailureKey);
                    futures.addTask(future);
                });

        futures.waitForAllToFinish();

        log.debugf("Removed %d login failures in realm %s", futures.size(), realmId);
    }

    @Override
    public void onRealmRemoved(RealmModel realm) {
        // Don't send message to all DCs, just to all cluster nodes in current DC. The remoteCache will notify client listeners for removed userSessions.
        clusterEventsSenderTx.addEvent(
                RealmRemovedSessionEvent.createEvent(RealmRemovedSessionEvent.class, InfinispanUserSessionProviderFactory.REALM_REMOVED_SESSION_EVENT, session, realm.getId(), true),
                ClusterProvider.DCNotify.LOCAL_DC_ONLY);

        // 看来本对象还要跟 persister对象做联动
        UserSessionPersisterProvider sessionsPersister = session.getProvider(UserSessionPersisterProvider.class);
        if (sessionsPersister != null) {
            sessionsPersister.onRealmRemoved(realm);
        }
    }

    /**
     * 清除该realm下所有数据  但是不涉及DB
     * @param realmId
     */
    protected void onRealmRemovedEvent(String realmId) {
        removeLocalUserSessions(realmId, true);
        removeLocalUserSessions(realmId, false);
        removeAllLocalUserLoginFailuresEvent(realmId);
    }

    /**
     * 移除某个client的数据
     * @param realm
     * @param client
     */
    @Override
    public void onClientRemoved(RealmModel realm, ClientModel client) {
//        clusterEventsSenderTx.addEvent(
//                ClientRemovedSessionEvent.createEvent(ClientRemovedSessionEvent.class, InfinispanUserSessionProviderFactory.CLIENT_REMOVED_SESSION_EVENT, session, realm.getId(), true),
//                ClusterProvider.DCNotify.LOCAL_DC_ONLY);
        UserSessionPersisterProvider sessionsPersister = session.getProvider(UserSessionPersisterProvider.class);
        if (sessionsPersister != null) {
            sessionsPersister.onClientRemoved(realm, client);
        }
    }

    protected void onClientRemovedEvent(String realmId, String clientUuid) {
        // Nothing for now. userSession.getAuthenticatedClientSessions() will check lazily if particular client exists and update userSession on-the-fly.
    }


    /**
     * 监听用户删除事件  并移除缓存和DB 会话数据
     * @param realm
     * @param user
     */
    protected void onUserRemoved(RealmModel realm, UserModel user) {
        removeUserSessions(realm, user, true);
        removeUserSessions(realm, user, false);

        removeUserLoginFailure(realm, user.getId());

        UserSessionPersisterProvider persisterProvider = session.getProvider(UserSessionPersisterProvider.class);
        if (persisterProvider != null) {
            persisterProvider.onUserRemoved(realm, user);
        }
    }

    @Override
    public void close() {
    }

    /**
     * 移除某个用户会话
     * @param sessionEntity
     * @param offline
     */
    protected void removeUserSession(UserSessionEntity sessionEntity, boolean offline) {
        InfinispanChangelogBasedTransaction<String, UserSessionEntity> userSessionUpdateTx = getTransaction(offline);
        InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> clientSessionUpdateTx = getClientSessionTransaction(offline);

        // 移除用户会话时 连关联的client session 一并移除
        sessionEntity.getAuthenticatedClientSessions().forEach((clientUUID, clientSessionId) -> clientSessionUpdateTx.addTask(clientSessionId, Tasks.removeSync()));

        // 添加移除user session 的任务
        SessionUpdateTask<UserSessionEntity> removeTask = Tasks.removeSync();
        userSessionUpdateTx.addTask(sessionEntity.getId(), removeTask);
    }

    InfinispanChangelogBasedTransaction<LoginFailureKey, LoginFailureEntity> getLoginFailuresTx() {
        return loginFailuresTx;
    }

    /**
     * 包装基础的用户会话   用户会话是个Pojo对象   adapter也一样
     * @param realm
     * @param entity
     * @param offline
     * @return
     */
    UserSessionAdapter wrap(RealmModel realm, UserSessionEntity entity, boolean offline) {
        // 这2个对象用于将会话数据同步到缓存服务器
        InfinispanChangelogBasedTransaction<String, UserSessionEntity> userSessionUpdateTx = getTransaction(offline);
        InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> clientSessionUpdateTx = getClientSessionTransaction(offline);
        return entity != null ? new UserSessionAdapter(session, this, userSessionUpdateTx, clientSessionUpdateTx, realm, entity, offline) : null;
    }

    AuthenticatedClientSessionAdapter wrap(UserSessionModel userSession, ClientModel client, AuthenticatedClientSessionEntity entity, boolean offline) {
        InfinispanChangelogBasedTransaction<String, UserSessionEntity> userSessionUpdateTx = getTransaction(offline);
        InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> clientSessionUpdateTx = getClientSessionTransaction(offline);
        return entity != null ? new AuthenticatedClientSessionAdapter(session,this, entity, client, userSession, clientSessionUpdateTx, offline) : null;
    }

    UserLoginFailureModel wrap(LoginFailureKey key, LoginFailureEntity entity) {
        return entity != null ? new UserLoginFailureAdapter(this, key, entity) : null;
    }

    UserSessionEntity getUserSessionEntity(RealmModel realm, UserSessionModel userSession, boolean offline) {
        if (userSession instanceof UserSessionAdapter) {
            if (!userSession.getRealm().equals(realm)) return null;
            return ((UserSessionAdapter) userSession).getEntity();
        } else {
            return getUserSessionEntity(realm, userSession.getId(), offline);
        }
    }


    /**
     * 创建离线会话
     * @param userSession
     * @return
     */
    @Override
    public UserSessionModel createOfflineUserSession(UserSessionModel userSession) {
        // 产生一个新的会话对象
        UserSessionAdapter offlineUserSession = importUserSession(userSession, true);

        // started and lastSessionRefresh set to current time
        int currentTime = Time.currentTime();
        offlineUserSession.getEntity().setStarted(currentTime);
        offlineUserSession.setLastSessionRefresh(currentTime);

        // 离线会话通过持久化对象创建
        session.getProvider(UserSessionPersisterProvider.class).createUserSession(userSession, true);

        return offlineUserSession;
    }

    @Override
    public UserSessionAdapter getOfflineUserSession(RealmModel realm, String userSessionId) {
        return getUserSession(realm, userSessionId, true);
    }

    /**
     * 通过broker锁定会话
     * @param realm
     * @param brokerSessionId
     * @return
     */
    @Override
    public UserSessionModel getOfflineUserSessionByBrokerSessionId(RealmModel realm, String brokerSessionId) {
        return this.getUserSessionsStream(realm, UserSessionPredicate.create(realm.getId()).brokerSessionId(brokerSessionId), true)
                .findFirst().orElse(null);
    }

    @Override
    public Stream<UserSessionModel> getOfflineUserSessionByBrokerUserIdStream(RealmModel realm, String brokerUserId) {
        return getUserSessionsStream(realm, UserSessionPredicate.create(realm.getId()).brokerUserId(brokerUserId), true);
    }

    @Override
    public void removeOfflineUserSession(RealmModel realm, UserSessionModel userSession) {
        // 同时移除缓存和DB的用户会话
        UserSessionEntity userSessionEntity = getUserSessionEntity(realm, userSession, true);
        if (userSessionEntity != null) {
            removeUserSession(userSessionEntity, true);
        }
        session.getProvider(UserSessionPersisterProvider.class).removeUserSession(userSession.getId(), true);
    }

    /**
     * 创建离线的 client会话
     * @param clientSession
     * @param offlineUserSession
     * @return
     */
    @Override
    public AuthenticatedClientSessionModel createOfflineClientSession(AuthenticatedClientSessionModel clientSession, UserSessionModel offlineUserSession) {
        UserSessionAdapter userSessionAdapter = (offlineUserSession instanceof UserSessionAdapter) ? (UserSessionAdapter) offlineUserSession :
                getOfflineUserSession(offlineUserSession.getRealm(), offlineUserSession.getId());

        InfinispanChangelogBasedTransaction<String, UserSessionEntity> userSessionUpdateTx = getTransaction(true);
        InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> clientSessionUpdateTx = getClientSessionTransaction(true);

        // 根据已有的client会话产生一个离线的版本
        AuthenticatedClientSessionAdapter offlineClientSession = importClientSession(userSessionAdapter, clientSession, userSessionUpdateTx, clientSessionUpdateTx, true);

        // update timestamp to current time
        offlineClientSession.setTimestamp(Time.currentTime());

        session.getProvider(UserSessionPersisterProvider.class).createClientSession(clientSession, true);

        return offlineClientSession;
    }

    @Override
    public Stream<UserSessionModel> getOfflineUserSessionsStream(RealmModel realm, UserModel user) {
        return this.getUserSessionsStream(realm, UserSessionPredicate.create(realm.getId()).user(user.getId()), true);
    }

    @Override
    public long getOfflineSessionsCount(RealmModel realm, ClientModel client) {
        return getUserSessionsCount(realm, client, true);
    }

    @Override
    public Stream<UserSessionModel> getOfflineUserSessionsStream(RealmModel realm, ClientModel client, Integer first, Integer max) {
        return getUserSessionsStream(realm, client, first, max, true);
    }


    /**
     * 将一组从持久层读取到的用户会话 放入缓存中
     * @param persistentUserSessions
     * @param offline
     */
    @Override
    public void importUserSessions(Collection<UserSessionModel> persistentUserSessions, boolean offline) {
        if (persistentUserSessions == null || persistentUserSessions.isEmpty()) {
            return;
        }

        Map<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> clientSessionsById = new HashMap<>();

        Map<String, SessionEntityWrapper<UserSessionEntity>> sessionsById = persistentUserSessions.stream()
                .map((UserSessionModel persistentUserSession) -> {

                    // 转换成一个新的用户会话
                    UserSessionEntity userSessionEntityToImport = createUserSessionEntityInstance(persistentUserSession);

                    // 遍历该用户关联的client 会话
                    for (Map.Entry<String, AuthenticatedClientSessionModel> entry : persistentUserSession.getAuthenticatedClientSessions().entrySet()) {
                        String clientUUID = entry.getKey();
                        AuthenticatedClientSessionModel clientSession = entry.getValue();

                        // 产生client 会话
                        AuthenticatedClientSessionEntity clientSessionToImport = createAuthenticatedClientSessionInstance(clientSession, userSessionEntityToImport.getRealmId(), offline);

                        // Update timestamp to same value as userSession. LastSessionRefresh of userSession from DB will have correct value
                        clientSessionToImport.setTimestamp(userSessionEntityToImport.getLastSessionRefresh());

                        clientSessionsById.put(clientSessionToImport.getId(), new SessionEntityWrapper<>(clientSessionToImport));

                        // Update userSession entity with the clientSession
                        AuthenticatedClientSessionStore clientSessions = userSessionEntityToImport.getAuthenticatedClientSessions();
                        clientSessions.put(clientUUID, clientSessionToImport.getId());
                    }

                    return userSessionEntityToImport;
                })
                .map(SessionEntityWrapper::new)
                .collect(Collectors.toMap(sessionEntityWrapper -> sessionEntityWrapper.getEntity().getId(), Function.identity()));

        // Directly put all entities to the infinispan cache  加入缓存
        Cache<String, SessionEntityWrapper<UserSessionEntity>> cache = CacheDecorators.skipCacheLoaders(getCache(offline));
        cache.putAll(sessionsById);

        // put all entities to the remoteCache (if exists)  TODO DC先不看
        RemoteCache remoteCache = InfinispanUtil.getRemoteCache(cache);
        if (remoteCache != null) {
            Map<String, SessionEntityWrapper<UserSessionEntity>> sessionsByIdForTransport = sessionsById.values().stream()
                    .map(SessionEntityWrapper::forTransport)
                    .collect(Collectors.toMap(sessionEntityWrapper -> sessionEntityWrapper.getEntity().getId(), Function.identity()));

            Retry.executeWithBackoff((int iteration) -> {

                try {
                    remoteCache.putAll(sessionsByIdForTransport);
                } catch (HotRodClientException re) {
                    if (log.isDebugEnabled()) {
                        log.debugf(re, "Failed to put import %d sessions to remoteCache. Iteration '%s'. Will try to retry the task",
                                sessionsByIdForTransport.size(), iteration);
                    }

                    // Rethrow the exception. Retry will take care of handle the exception and eventually retry the operation.
                    throw re;
                }

            }, 10, 10);
        }

        // Import client sessions
        Cache<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> clientSessCache = offline ? offlineClientSessionCache : clientSessionCache;
        clientSessCache = CacheDecorators.skipCacheLoaders(clientSessCache);

        // 加入client缓存
        clientSessCache.putAll(clientSessionsById);

        // put all entities to the remoteCache (if exists)  TODO
        RemoteCache remoteCacheClientSessions = InfinispanUtil.getRemoteCache(clientSessCache);
        if (remoteCacheClientSessions != null) {
            Map<UUID, SessionEntityWrapper<AuthenticatedClientSessionEntity>> sessionsByIdForTransport = clientSessionsById.values().stream()
                    .map(SessionEntityWrapper::forTransport)
                    .collect(Collectors.toMap(sessionEntityWrapper -> sessionEntityWrapper.getEntity().getId(), Function.identity()));

            Retry.executeWithBackoff((int iteration) -> {

                try {
                    remoteCacheClientSessions.putAll(sessionsByIdForTransport);
                } catch (HotRodClientException re) {
                    if (log.isDebugEnabled()) {
                        log.debugf(re, "Failed to put import %d client sessions to remoteCache. Iteration '%s'. Will try to retry the task",
                                sessionsByIdForTransport.size(), iteration);
                    }

                    // Rethrow the exception. Retry will take care of handle the exception and eventually retry the operation.
                    throw re;
                }

            }, 10, 10);
        }
    }


    // Imports just userSession without it's clientSessions     导入用户会话数据
    protected UserSessionAdapter importUserSession(UserSessionModel userSession, boolean offline) {

        // 通过完整用户会话 反向构建会话对象
        UserSessionEntity entity = createUserSessionEntityInstance(userSession);

        InfinispanChangelogBasedTransaction<String, UserSessionEntity> userSessionUpdateTx = getTransaction(offline);
        InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> clientSessionUpdateTx = getClientSessionTransaction(offline);

        SessionUpdateTask<UserSessionEntity> importTask = Tasks.addIfAbsentSync();
        userSessionUpdateTx.addTask(userSession.getId(), importTask, entity, UserSessionModel.SessionPersistenceState.PERSISTENT);

        UserSessionAdapter importedSession = wrap(userSession.getRealm(), entity, offline);

        return importedSession;
    }


    /**
     * 通过完善的用户会话信息 反向构建 session entity
     * @param userSession
     * @return
     */
    private UserSessionEntity createUserSessionEntityInstance(UserSessionModel userSession) {
        UserSessionEntity entity = new UserSessionEntity();
        entity.setId(userSession.getId());
        entity.setRealmId(userSession.getRealm().getId());

        entity.setAuthMethod(userSession.getAuthMethod());
        entity.setBrokerSessionId(userSession.getBrokerSessionId());
        entity.setBrokerUserId(userSession.getBrokerUserId());
        entity.setIpAddress(userSession.getIpAddress());
        entity.setNotes(userSession.getNotes() == null ? new ConcurrentHashMap<>() : userSession.getNotes());
        entity.setAuthenticatedClientSessions(new AuthenticatedClientSessionStore());
        entity.setRememberMe(userSession.isRememberMe());
        entity.setState(userSession.getState());
        if (userSession instanceof OfflineUserSessionModel) {
            // this is a hack so that UserModel doesn't have to be available when offline token is imported.
            // see related JIRA - KEYCLOAK-5350 and corresponding test
            OfflineUserSessionModel oline = (OfflineUserSessionModel)userSession;
            entity.setUser(oline.getUserId());
            // NOTE: Hack
            // We skip calling entity.setLoginUsername(userSession.getLoginUsername())

        } else {
            entity.setLoginUsername(userSession.getLoginUsername());
            entity.setUser(userSession.getUser().getId());
        }

        entity.setStarted(userSession.getStarted());
        entity.setLastSessionRefresh(userSession.getLastSessionRefresh());

        return entity;
    }

    /**
     * 在已经存在的用户会话中 增加一个client会话
     * @param sessionToImportInto
     * @param clientSession
     * @param userSessionUpdateTx
     * @param clientSessionUpdateTx
     * @param offline
     * @return
     */
    private AuthenticatedClientSessionAdapter importClientSession(UserSessionAdapter sessionToImportInto, AuthenticatedClientSessionModel clientSession,
                                                                  InfinispanChangelogBasedTransaction<String, UserSessionEntity> userSessionUpdateTx,
                                                                  InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> clientSessionUpdateTx,
                                                                  boolean offline) {

        // 基于已有的client 会话信息 生成entity
        AuthenticatedClientSessionEntity entity = createAuthenticatedClientSessionInstance(clientSession, sessionToImportInto.getRealm().getId(), offline);
        final UUID clientSessionId = entity.getId();

        SessionUpdateTask<AuthenticatedClientSessionEntity> createClientSessionTask = Tasks.addIfAbsentSync();
        clientSessionUpdateTx.addTask(entity.getId(), createClientSessionTask, entity, UserSessionModel.SessionPersistenceState.PERSISTENT);

        // 新生成的client 要加入到用户会话中
        AuthenticatedClientSessionStore clientSessions = sessionToImportInto.getEntity().getAuthenticatedClientSessions();
        clientSessions.put(clientSession.getClient().getId(), clientSessionId);

        SessionUpdateTask registerClientSessionTask = new RegisterClientSessionTask(clientSession.getClient().getId(), clientSessionId);
        userSessionUpdateTx.addTask(sessionToImportInto.getId(), registerClientSessionTask);

        return new AuthenticatedClientSessionAdapter(session,this, entity, clientSession.getClient(), sessionToImportInto, clientSessionUpdateTx, offline);
    }


    private AuthenticatedClientSessionEntity createAuthenticatedClientSessionInstance(AuthenticatedClientSessionModel clientSession, String realmId, boolean offline) {
        final UUID clientSessionId = keyGenerator.generateKeyUUID(session, getClientSessionCache(offline));
        AuthenticatedClientSessionEntity entity = new AuthenticatedClientSessionEntity(clientSessionId);
        entity.setRealmId(realmId);

        entity.setAction(clientSession.getAction());
        entity.setAuthMethod(clientSession.getProtocol());

        entity.setNotes(clientSession.getNotes() == null ? new ConcurrentHashMap<>() : clientSession.getNotes());
        entity.setRedirectUri(clientSession.getRedirectUri());
        entity.setTimestamp(clientSession.getTimestamp());

        return entity;
    }

    /**
     * 该任务会将client会话id 追加到用户会话中
     */
    private static class RegisterClientSessionTask implements SessionUpdateTask<UserSessionEntity> {

        private final String clientUuid;
        private final UUID clientSessionId;

        public RegisterClientSessionTask(String clientUuid, UUID clientSessionId) {
            this.clientUuid = clientUuid;
            this.clientSessionId = clientSessionId;
        }

        @Override
        public void runUpdate(UserSessionEntity session) {
            AuthenticatedClientSessionStore clientSessions = session.getAuthenticatedClientSessions();
            clientSessions.put(clientUuid, clientSessionId);
        }

        @Override
        public CacheOperation getOperation(UserSessionEntity session) {
            return CacheOperation.REPLACE;
        }

        @Override
        public CrossDCMessageStatus getCrossDCMessageStatus(SessionEntityWrapper<UserSessionEntity> sessionWrapper) {
            return CrossDCMessageStatus.SYNC;
        }
    }

}
