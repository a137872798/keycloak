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

package org.keycloak.models.sessions.infinispan.changes.sessions;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;

/**
 * Abstract "store" for bulk sending of the updates related to lastSessionRefresh
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractLastSessionRefreshStore {

    /**
     * 2次消息间最大间隔时间
     */
    private final int maxIntervalBetweenMessagesSeconds;
    /**
     * 最大次数
     */
    private final int maxCount;

    /**
     * 维护每个会话最后一次访问时间
     */
    private volatile Map<String, SessionData> lastSessionRefreshes = new ConcurrentHashMap<>();

    private volatile int lastRun = Time.currentTime();


    protected AbstractLastSessionRefreshStore(int maxIntervalBetweenMessagesSeconds, int maxCount) {
        this.maxIntervalBetweenMessagesSeconds = maxIntervalBetweenMessagesSeconds;
        this.maxCount = maxCount;
    }


    public void putLastSessionRefresh(KeycloakSession kcSession, String sessionId, String realmId, int lastSessionRefresh) {
        lastSessionRefreshes.put(sessionId, new SessionData(realmId, lastSessionRefresh));

        // Assume that lastSessionRefresh is same or close to current time
        checkSendingMessage(kcSession, lastSessionRefresh);
    }


    /**
     * 判断是否需要将最新的session访问信息上报到缓存服务器
     * @param kcSession
     * @param currentTime
     */
    void checkSendingMessage(KeycloakSession kcSession, int currentTime) {
        // 当本地维护的缓存数过多  或者距离上次发送超过了时间间隔
        if (lastSessionRefreshes.size() >= maxCount || lastRun + maxIntervalBetweenMessagesSeconds <= currentTime) {
            Map<String, SessionData> refreshesToSend = prepareSendingMessage();

            // Sending message doesn't need to be synchronized
            if (refreshesToSend != null) {
                sendMessage(kcSession, refreshesToSend);
            }
        }
    }


    // synchronized manipulation with internal object instances. Will return map if message should be sent. Otherwise return null
    // 产生一个会话副本
    private synchronized Map<String, SessionData> prepareSendingMessage() {
        // Safer to retrieve currentTime to avoid race conditions during testsuite
        int currentTime = Time.currentTime();
        if (lastSessionRefreshes.size() >= maxCount || lastRun + maxIntervalBetweenMessagesSeconds <= currentTime) {
            // Create new map instance, so that new writers will use that one
            Map<String, SessionData> copiedRefreshesToSend = lastSessionRefreshes;
            lastSessionRefreshes = new ConcurrentHashMap<>();
            lastRun = currentTime;

            return copiedRefreshesToSend;
        } else {
            return null;
        }
    }


    public synchronized void reset() {
        lastRun = Time.currentTime();
        lastSessionRefreshes = new ConcurrentHashMap<>();
    }


    /**
     * Bulk update the underlying store with all the user sessions, which were refreshed by Keycloak since the last call of this method
     *
     * @param kcSession
     * @param refreshesToSend Key is userSession ID, SessionData are data about the session
     */
    protected abstract void sendMessage(KeycloakSession kcSession, Map<String, SessionData> refreshesToSend);
}
