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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.session.UserSessionPersisterProvider;
import org.keycloak.models.sessions.infinispan.changes.InfinispanChangelogBasedTransaction;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.changes.ClientSessionUpdateTask;
import org.keycloak.models.sessions.infinispan.changes.SessionUpdateTask;
import org.keycloak.models.sessions.infinispan.changes.Tasks;
import org.keycloak.models.sessions.infinispan.changes.UserSessionUpdateTask;
import org.keycloak.models.sessions.infinispan.changes.sessions.CrossDCLastSessionRefreshChecker;
import org.keycloak.models.sessions.infinispan.entities.AuthenticatedClientSessionEntity;
import org.keycloak.models.sessions.infinispan.entities.UserSessionEntity;

import java.util.UUID;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 包含有关client会话的操作
 */
public class AuthenticatedClientSessionAdapter implements AuthenticatedClientSessionModel {

    // 维护了各种会话信息
    private final KeycloakSession kcSession;
    // 通过它调用一些公共方法
    private final InfinispanUserSessionProvider provider;

    // 包含client会话的基础信息
    private AuthenticatedClientSessionEntity entity;

    // 包含client数据
    private final ClientModel client;
    // 维护最新的session 以及作用在session上的任务
    private final InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> clientSessionUpdateTx;
    // 客户端会话是和用户会话强关联的
    private UserSessionModel userSession;
    private boolean offline;

    public AuthenticatedClientSessionAdapter(KeycloakSession kcSession, InfinispanUserSessionProvider provider,
                                             AuthenticatedClientSessionEntity entity, ClientModel client, UserSessionModel userSession,
                                             InfinispanChangelogBasedTransaction<UUID, AuthenticatedClientSessionEntity> clientSessionUpdateTx, boolean offline) {
        if (userSession == null) {
            throw new NullPointerException("userSession must not be null");
        }

        this.kcSession = kcSession;
        this.provider = provider;
        this.entity = entity;
        this.userSession = userSession;
        this.client = client;
        this.clientSessionUpdateTx = clientSessionUpdateTx;
        this.offline = offline;
    }

    /**
     * 将一个更新任务作用到client会话上
     * @param task
     */
    private void update(ClientSessionUpdateTask task) {
        clientSessionUpdateTx.addTask(entity.getId(), task);
    }

    /**
     * Detaches the client session from its user session.
     * <p>
     * <b>This method does not delete the client session from user session records, it only removes the client session.</b>
     * The list of client sessions within user session is updated lazily for performance reasons.
     * 用户会话 本来会绑定一组client会话  现在要将client会话从用户会话中移除
     */
    @Override
    public void detachFromUserSession() {
        // TODO 先不考虑离线的   貌似离线都是跟persister相关的
        if (this.userSession.isOffline()) {
            kcSession.getProvider(UserSessionPersisterProvider.class).removeClientSession(userSession.getId(), client.getId(), true);
        }
        // Intentionally do not remove the clientUUID from the user session, invalid session is handled
        // as nonexistent in org.keycloak.models.sessions.infinispan.UserSessionAdapter.getAuthenticatedClientSessions()
        this.userSession = null;

        // 产生一个remove任务 加入到client更新任务中
        SessionUpdateTask<AuthenticatedClientSessionEntity> removeTask = Tasks.removeSync();

        clientSessionUpdateTx.addTask(entity.getId(), removeTask);
    }

    /**
     * 获取关联的用户会话
     * @return
     */
    @Override
    public UserSessionModel getUserSession() {
        return this.userSession;
    }

    @Override
    public String getRedirectUri() {
        return entity.getRedirectUri();
    }

    @Override
    public void setRedirectUri(String uri) {
        ClientSessionUpdateTask task = new ClientSessionUpdateTask() {

            @Override
            public void runUpdate(AuthenticatedClientSessionEntity entity) {
                entity.setRedirectUri(uri);
            }

        };

        update(task);
    }

    @Override
    public String getId() {
        return null;
    }

    @Override
    public RealmModel getRealm() {
        return userSession.getRealm();
    }

    @Override
    public ClientModel getClient() {
        return client;
    }

    @Override
    public int getTimestamp() {
        return entity.getTimestamp();
    }

    @Override
    public void setTimestamp(int timestamp) {
        ClientSessionUpdateTask task = new ClientSessionUpdateTask() {

            @Override
            public void runUpdate(AuthenticatedClientSessionEntity entity) {
                entity.setTimestamp(timestamp);
            }

            @Override
            public CrossDCMessageStatus getCrossDCMessageStatus(SessionEntityWrapper<AuthenticatedClientSessionEntity> sessionWrapper) {
                return new CrossDCLastSessionRefreshChecker(provider.getLastSessionRefreshStore(), provider.getOfflineLastSessionRefreshStore())
                        .shouldSaveClientSessionToRemoteCache(kcSession, client.getRealm(), sessionWrapper, userSession, offline, timestamp);
            }

            @Override
            public String toString() {
                return "setTimestamp(" + timestamp + ')';
            }

        };

        update(task);
    }

    @Override
    public int getCurrentRefreshTokenUseCount() {
        return entity.getCurrentRefreshTokenUseCount();
    }

    @Override
    public void setCurrentRefreshTokenUseCount(int currentRefreshTokenUseCount) {
        ClientSessionUpdateTask task = new ClientSessionUpdateTask() {

            @Override
            public void runUpdate(AuthenticatedClientSessionEntity entity) {
                entity.setCurrentRefreshTokenUseCount(currentRefreshTokenUseCount);
            }
        };

        update(task);
    }

    @Override
    public String getCurrentRefreshToken() {
        return entity.getCurrentRefreshToken();
    }

    @Override
    public void setCurrentRefreshToken(String currentRefreshToken) {
        ClientSessionUpdateTask task = new ClientSessionUpdateTask() {

            @Override
            public void runUpdate(AuthenticatedClientSessionEntity entity) {
                entity.setCurrentRefreshToken(currentRefreshToken);
            }
        };

        update(task);
    }

    @Override
    public String getAction() {
        return entity.getAction();
    }

    @Override
    public void setAction(String action) {
        ClientSessionUpdateTask task = new ClientSessionUpdateTask() {

            @Override
            public void runUpdate(AuthenticatedClientSessionEntity entity) {
                entity.setAction(action);
            }

        };

        update(task);
    }

    @Override
    public String getProtocol() {
        return entity.getAuthMethod();
    }

    @Override
    public void setProtocol(String method) {
        ClientSessionUpdateTask task = new ClientSessionUpdateTask() {

            @Override
            public void runUpdate(AuthenticatedClientSessionEntity entity) {
                entity.setAuthMethod(method);
            }

        };

        update(task);
    }

    @Override
    public String getNote(String name) {
        return entity.getNotes().get(name);
    }

    @Override
    public void setNote(String name, String value) {
        ClientSessionUpdateTask task = new ClientSessionUpdateTask() {

            @Override
            public void runUpdate(AuthenticatedClientSessionEntity entity) {
                entity.getNotes().put(name, value);
            }

        };

        update(task);
    }

    @Override
    public void removeNote(String name) {
        ClientSessionUpdateTask task = new ClientSessionUpdateTask() {

            @Override
            public void runUpdate(AuthenticatedClientSessionEntity entity) {
                entity.getNotes().remove(name);
            }

        };

        update(task);
    }

    @Override
    public Map<String, String> getNotes() {
        if (entity.getNotes().isEmpty()) return Collections.emptyMap();
        Map<String, String> copy = new HashMap<>();
        copy.putAll(entity.getNotes());
        return copy;
    }

}
