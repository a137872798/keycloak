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

package org.keycloak.models.jpa.session;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.session.PersistentAuthenticatedClientSessionAdapter;
import org.keycloak.models.session.PersistentClientSessionModel;
import org.keycloak.models.session.PersistentUserSessionAdapter;
import org.keycloak.models.session.PersistentUserSessionModel;
import org.keycloak.models.session.UserSessionPersisterProvider;
import org.keycloak.models.utils.SessionTimeoutHelper;
import org.keycloak.storage.StorageId;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.persistence.LockModeType;

import static org.keycloak.models.jpa.PaginationUtils.paginateQuery;
import static org.keycloak.utils.StreamsUtil.closing;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * keycloak的用户会话信息  通过DB进行持久化
 */
public class JpaUserSessionPersisterProvider implements UserSessionPersisterProvider {
    private static final Logger logger = Logger.getLogger(JpaUserSessionPersisterProvider.class);

    private final KeycloakSession session;
    // 关联到DB
    private final EntityManager em;

    public JpaUserSessionPersisterProvider(KeycloakSession session, EntityManager em) {
        this.session = session;
        this.em = em;
    }

    /**
     * 创建用户会话
     * @param userSession
     * @param offline
     */
    @Override
    public void createUserSession(UserSessionModel userSession, boolean offline) {
        // UserSessionAdapter会被包装成可持久化的userSession对象
        PersistentUserSessionAdapter adapter = new PersistentUserSessionAdapter(userSession);
        PersistentUserSessionModel model = adapter.getUpdatedModel();

        PersistentUserSessionEntity entity = new PersistentUserSessionEntity();
        entity.setUserSessionId(model.getUserSessionId());
        entity.setCreatedOn(model.getStarted());
        entity.setRealmId(adapter.getRealm().getId());
        entity.setUserId(adapter.getUser().getId());
        String offlineStr = offlineToString(offline);
        entity.setOffline(offlineStr);
        entity.setLastSessionRefresh(model.getLastSessionRefresh());
        entity.setData(model.getData());
        em.persist(entity);
        em.flush();
    }

    @Override
    public void createClientSession(AuthenticatedClientSessionModel clientSession, boolean offline) {

        // 使用clientSession 更新model数据
        PersistentAuthenticatedClientSessionAdapter adapter = new PersistentAuthenticatedClientSessionAdapter(session, clientSession);
        PersistentClientSessionModel model = adapter.getUpdatedModel();

        PersistentClientSessionEntity entity = new PersistentClientSessionEntity();
        StorageId clientStorageId = new StorageId(clientSession.getClient().getId());

        // 代表存储在本地
        if (clientStorageId.isLocal()) {
            entity.setClientId(clientStorageId.getId());
            entity.setClientStorageProvider(PersistentClientSessionEntity.LOCAL);
            entity.setExternalClientId(PersistentClientSessionEntity.LOCAL);

        } else {
            entity.setClientId(PersistentClientSessionEntity.EXTERNAL);
            entity.setClientStorageProvider(clientStorageId.getProviderId());
            entity.setExternalClientId(clientStorageId.getExternalId());
        }
        entity.setTimestamp(clientSession.getTimestamp());
        String offlineStr = offlineToString(offline);
        entity.setOffline(offlineStr);
        // 意味着某个用户在某个client完成认证
        entity.setUserSessionId(clientSession.getUserSession().getId());
        entity.setData(model.getData());
        em.persist(entity);
        em.flush();
    }

    @Override
    public void removeUserSession(String userSessionId, boolean offline) {
        String offlineStr = offlineToString(offline);

        em.createNamedQuery("deleteClientSessionsByUserSession")
                .setParameter("userSessionId", userSessionId)
                .setParameter("offline", offlineStr)
                .executeUpdate();

        PersistentUserSessionEntity sessionEntity = em.find(PersistentUserSessionEntity.class, new PersistentUserSessionEntity.Key(userSessionId, offlineStr), LockModeType.PESSIMISTIC_WRITE);
        if (sessionEntity != null) {
            em.remove(sessionEntity);
            em.flush();
        }
    }

    /**
     * 删除某个client 会话
     * @param userSessionId
     * @param clientUUID
     * @param offline
     */
    @Override
    public void removeClientSession(String userSessionId, String clientUUID, boolean offline) {
        String offlineStr = offlineToString(offline);
        StorageId clientStorageId = new StorageId(clientUUID);
        String clientId = PersistentClientSessionEntity.EXTERNAL;
        String clientStorageProvider = PersistentClientSessionEntity.LOCAL;
        String externalId = PersistentClientSessionEntity.LOCAL;

        // 观察id 可以知道是本地还是远端
        if (clientStorageId.isLocal()) {
            clientId = clientUUID;
        } else {
            clientStorageProvider = clientStorageId.getProviderId();
            externalId = clientStorageId.getExternalId();

        }
        PersistentClientSessionEntity sessionEntity = em.find(PersistentClientSessionEntity.class, new PersistentClientSessionEntity.Key(userSessionId, clientId, clientStorageProvider, externalId, offlineStr), LockModeType.PESSIMISTIC_WRITE);
        if (sessionEntity != null) {
            // 删除client会话
            em.remove(sessionEntity);

            // Remove userSession if it was last clientSession 删除关联数据
            List<PersistentClientSessionEntity> clientSessions = getClientSessionsByUserSession(sessionEntity.getUserSessionId(), offline);
            if (clientSessions.size() == 0) {
                offlineStr = offlineToString(offline);
                // 如果该用户没有任何的client 会话 那么这个会话实际上就是无效的 可以将用户会话删除  也就是说用户认证至少会关联一个client
                PersistentUserSessionEntity userSessionEntity = em.find(PersistentUserSessionEntity.class, new PersistentUserSessionEntity.Key(sessionEntity.getUserSessionId(), offlineStr), LockModeType.PESSIMISTIC_WRITE);
                if (userSessionEntity != null) {
                    em.remove(userSessionEntity);
                }
            }

            em.flush();
        }
    }

    private List<PersistentClientSessionEntity> getClientSessionsByUserSession(String userSessionId, boolean offline) {
        String offlineStr = offlineToString(offline);

        TypedQuery<PersistentClientSessionEntity> query = em.createNamedQuery("findClientSessionsByUserSession", PersistentClientSessionEntity.class);
        query.setParameter("userSessionId", userSessionId);
        query.setParameter("offline", offlineStr);
        return query.getResultList();
    }



    @Override
    public void onRealmRemoved(RealmModel realm) {
        int num = em.createNamedQuery("deleteClientSessionsByRealm").setParameter("realmId", realm.getId()).executeUpdate();
        num = em.createNamedQuery("deleteUserSessionsByRealm").setParameter("realmId", realm.getId()).executeUpdate();
    }

    @Override
    public void onClientRemoved(RealmModel realm, ClientModel client) {
        onClientRemoved(client.getId());
    }

    private void onClientRemoved(String clientUUID) {
        int num = 0;
        StorageId clientStorageId = new StorageId(clientUUID);
        if (clientStorageId.isLocal()) {
            num = em.createNamedQuery("deleteClientSessionsByClient").setParameter("clientId", clientUUID).executeUpdate();
        } else {
            num = em.createNamedQuery("deleteClientSessionsByExternalClient")
                    .setParameter("clientStorageProvider", clientStorageId.getProviderId())
                    .setParameter("externalClientId", clientStorageId.getExternalId())
                    .executeUpdate();
        }
    }

    @Override
    public void onUserRemoved(RealmModel realm, UserModel user) {
        onUserRemoved(realm, user.getId());
    }

    private void onUserRemoved(RealmModel realm, String userId) {
        int num = em.createNamedQuery("deleteClientSessionsByUser").setParameter("userId", userId).executeUpdate();
        num = em.createNamedQuery("deleteUserSessionsByUser").setParameter("userId", userId).executeUpdate();
    }


    /**
     * 将session最后的访问时间写入到DB中
     * @param realm
     * @param lastSessionRefresh
     * @param userSessionIds
     * @param offline  是否是离线会话
     */
    @Override
    public void updateLastSessionRefreshes(RealmModel realm, int lastSessionRefresh, Collection<String> userSessionIds, boolean offline) {
        String offlineStr = offlineToString(offline);

        int us = em.createNamedQuery("updateUserSessionLastSessionRefresh")
                .setParameter("lastSessionRefresh", lastSessionRefresh)
                .setParameter("realmId", realm.getId())
                .setParameter("offline", offlineStr)
                .setParameter("userSessionIds", userSessionIds)
                .executeUpdate();

        logger.debugf("Updated lastSessionRefresh of %d user sessions in realm '%s'", us, realm.getName());
    }

    /**
     * 删除所有 超时的用户会话
     * @param realm
     */
    @Override
    public void removeExpired(RealmModel realm) {
        int expiredOffline = Time.currentTime() - realm.getOfflineSessionIdleTimeout() - SessionTimeoutHelper.PERIODIC_CLEANER_IDLE_TIMEOUT_WINDOW_SECONDS;

        String offlineStr = offlineToString(true);

        logger.tracef("Trigger removing expired user sessions for realm '%s'", realm.getName());

        int cs = em.createNamedQuery("deleteExpiredClientSessions")
                .setParameter("realmId", realm.getId())
                .setParameter("lastSessionRefresh", expiredOffline)
                .setParameter("offline", offlineStr)
                .executeUpdate();

        int us = em.createNamedQuery("deleteExpiredUserSessions")
                .setParameter("realmId", realm.getId())
                .setParameter("lastSessionRefresh", expiredOffline)
                .setParameter("offline", offlineStr)
                .executeUpdate();

        logger.debugf("Removed %d expired user sessions and %d expired client sessions in realm '%s'", us, cs, realm.getName());

    }

    /**
     * 根据条件查询会话
     * @param firstResult {@code Integer} Index of the first desired user session. Ignored if negative or {@code null}.
     * @param maxResults {@code Integer} Maximum number of returned user sessions. Ignored if negative or {@code null}.
     * @param offline {@code boolean} Flag to include offline sessions.
     * @param lastCreatedOn {@code Integer} Timestamp when the user session was created. It will return only user sessions created later.
     * @param lastUserSessionId {@code String} Id of the user session. In case of equal {@code lastCreatedOn}
     * it will compare the id in dictionary order and takes only those created later.
     * @return
     */
    @Override
    public Stream<UserSessionModel> loadUserSessionsStream(Integer firstResult, Integer maxResults, boolean offline,
                                                           Integer lastCreatedOn, String lastUserSessionId) {
        String offlineStr = offlineToString(offline);

        TypedQuery<PersistentUserSessionEntity> query = em.createNamedQuery("findUserSessions", PersistentUserSessionEntity.class);
        query.setParameter("offline", offlineStr);
        query.setParameter("lastCreatedOn", lastCreatedOn);
        query.setParameter("lastSessionId", lastUserSessionId);

        List<PersistentUserSessionAdapter> result = closing(paginateQuery(query, firstResult, maxResults).getResultStream()
                .map(this::toAdapter))
                .collect(Collectors.toList());

        Map<String, PersistentUserSessionAdapter> sessionsById = result.stream()
                .collect(Collectors.toMap(UserSessionModel::getId, Function.identity()));

        Set<String> userSessionIds = sessionsById.keySet();

        Set<String> removedClientUUIDs = new HashSet<>();

        // 查询用户关联的client
        if (!userSessionIds.isEmpty()) {
            TypedQuery<PersistentClientSessionEntity> query2 = em.createNamedQuery("findClientSessionsByUserSessions", PersistentClientSessionEntity.class);
            query2.setParameter("userSessionIds", userSessionIds);
            query2.setParameter("offline", offlineStr);
            closing(query2.getResultStream()).forEach(clientSession -> {
                PersistentUserSessionAdapter userSession = sessionsById.get(clientSession.getUserSessionId());

                PersistentAuthenticatedClientSessionAdapter clientSessAdapter = toAdapter(userSession.getRealm(), userSession, clientSession);
                Map<String, AuthenticatedClientSessionModel> currentClientSessions = userSession.getAuthenticatedClientSessions();

                // Case when client was removed in the meantime
                if (clientSessAdapter.getClient() == null) {
                    removedClientUUIDs.add(clientSession.getClientId());
                } else {
                    currentClientSessions.put(clientSession.getClientId(), clientSessAdapter);
                }
            });
        }

        for (String clientUUID : removedClientUUIDs) {
            onClientRemoved(clientUUID);
        }

        return result.stream().map(UserSessionModel.class::cast);
    }

    private PersistentUserSessionAdapter toAdapter(PersistentUserSessionEntity entity) {
        RealmModel realm = session.realms().getRealm(entity.getRealmId());
        return toAdapter(realm, entity);
    }

    private PersistentUserSessionAdapter toAdapter(RealmModel realm, PersistentUserSessionEntity entity) {
        PersistentUserSessionModel model = new PersistentUserSessionModel();
        model.setUserSessionId(entity.getUserSessionId());
        model.setStarted(entity.getCreatedOn());
        model.setLastSessionRefresh(entity.getLastSessionRefresh());
        model.setData(entity.getData());
        model.setOffline(offlineFromString(entity.getOffline()));

        Map<String, AuthenticatedClientSessionModel> clientSessions = new HashMap<>();
        return new PersistentUserSessionAdapter(session, model, realm, entity.getUserId(), clientSessions);
    }

    private PersistentAuthenticatedClientSessionAdapter toAdapter(RealmModel realm, PersistentUserSessionAdapter userSession, PersistentClientSessionEntity entity) {
        String clientId = entity.getClientId();
        if (!entity.getExternalClientId().equals("local")) {
            clientId = new StorageId(entity.getClientId(), entity.getExternalClientId()).getId();
        }
        ClientModel client = realm.getClientById(clientId);

        PersistentClientSessionModel model = new PersistentClientSessionModel();
        model.setClientId(clientId);
        model.setUserSessionId(userSession.getId());
        model.setUserId(userSession.getUserId());
        model.setTimestamp(entity.getTimestamp());
        model.setData(entity.getData());
        return new PersistentAuthenticatedClientSessionAdapter(session, model, realm, client, userSession);
    }

    @Override
    public int getUserSessionsCount(boolean offline) {
        String offlineStr = offlineToString(offline);

        Query query = em.createNamedQuery("findUserSessionsCount");
        query.setParameter("offline", offlineStr);
        Number n = (Number) query.getSingleResult();
        return n.intValue();
    }

    @Override
    public void close() {

    }

    private String offlineToString(boolean offline) {
        return offline ? "1" : "0";
    }

    private boolean offlineFromString(String offlineStr) {
        return "1".equals(offlineStr);
    }
}
