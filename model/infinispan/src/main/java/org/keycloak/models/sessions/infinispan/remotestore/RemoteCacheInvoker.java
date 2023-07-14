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

package org.keycloak.models.sessions.infinispan.remotestore;

import org.infinispan.client.hotrod.exceptions.HotRodClientException;
import org.keycloak.common.util.Retry;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.infinispan.client.hotrod.Flag;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.client.hotrod.VersionedValue;
import org.jboss.logging.Logger;
import org.keycloak.connections.infinispan.TopologyInfo;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.sessions.infinispan.changes.MergedUpdate;
import org.keycloak.models.sessions.infinispan.changes.SessionEntityWrapper;
import org.keycloak.models.sessions.infinispan.changes.SessionUpdateTask;
import org.keycloak.models.sessions.infinispan.entities.SessionEntity;
import org.keycloak.models.sessions.infinispan.util.InfinispanUtil;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 缓存在Infinispan服务器上 不在本地  所以需要借助一个remote对象
 */
public class RemoteCacheInvoker {

    public static final Logger logger = Logger.getLogger(RemoteCacheInvoker.class);

    /**
     * 每个名字对应一个缓存对象
     */
    private final Map<String, RemoteCacheContext> remoteCaches =  new HashMap<>();

    /**
     * 增加一个缓存对象
     * @param cacheName  缓存名
     * @param remoteCache  拉取缓存数据的对象
     * @param maxIdleLoader  最大等待时间
     */
    public void addRemoteCache(String cacheName, RemoteCache remoteCache, MaxIdleTimeLoader maxIdleLoader) {
        RemoteCacheContext ctx = new RemoteCacheContext(remoteCache, maxIdleLoader);
        remoteCaches.put(cacheName, ctx);
    }

    public Set<String> getRemoteCacheNames() {
        return Collections.unmodifiableSet(remoteCaches.keySet());
    }

    /**
     * 执行任务
     * @param kcSession
     * @param realm
     * @param cacheName
     * @param key
     * @param task  记录了对本地会话的所有更新操作
     * @param sessionWrapper  已经作用了本地UpdateTask
     * @param <K>
     * @param <V>
     */
    public <K, V extends SessionEntity> void runTask(KeycloakSession kcSession, RealmModel realm, String cacheName, K key, MergedUpdate<V> task, SessionEntityWrapper<V> sessionWrapper) {
        // 当没有为该缓存创建 RemoteCacheContext 时 不需要处理
        RemoteCacheContext context = remoteCaches.get(cacheName);
        if (context == null) {
            return;
        }

        // 获取会话数据
        V session = sessionWrapper.getEntity();

        SessionUpdateTask.CacheOperation operation = task.getOperation(session);
        SessionUpdateTask.CrossDCMessageStatus status = task.getCrossDCMessageStatus(sessionWrapper);

        // RemoteCacheInvoker 本身就是为了DC服务的  所以Not_Needed 就不需要继续处理了
        if (status == SessionUpdateTask.CrossDCMessageStatus.NOT_NEEDED) {
            if (logger.isTraceEnabled()) {
                logger.tracef("Skip writing to remoteCache for entity '%s' of cache '%s' and operation '%s'", key, cacheName, operation);
            }
            return;
        }

        long loadedMaxIdleTimeMs = context.maxIdleTimeLoader.getMaxIdleTimeMs(realm);

        // Increase the timeout to ensure that entry won't expire on remoteCache in case that write of some entities to remoteCache is postponed (eg. userSession.lastSessionRefresh)
        final long maxIdleTimeMs = loadedMaxIdleTimeMs + 1800000;

        if (logger.isTraceEnabled()) {
            logger.tracef("Running task '%s' on remote cache '%s' . Key is '%s'", operation, cacheName, key);
        }

        // 获取网络拓扑信息
        TopologyInfo topology = InfinispanUtil.getTopologyInfo(kcSession);

        Retry.executeWithBackoff((int iteration) -> {

            try {
                // 将会话信息同步到远端服务器
                runOnRemoteCache(topology, context.remoteCache, maxIdleTimeMs, key, task, sessionWrapper);
            } catch (HotRodClientException re) {
                if (logger.isDebugEnabled()) {
                    logger.debugf(re, "Failed running task '%s' on remote cache '%s' . Key: '%s', iteration '%s'. Will try to retry the task",
                            operation, cacheName, key, iteration);
                }

                // Rethrow the exception. Retry will take care of handle the exception and eventually retry the operation.
                throw re;
            }

        }, 10, 10);
    }


    /**
     * 将会话同步到远端服务器
     * @param topology
     * @param remoteCache
     * @param maxIdleMs
     * @param key  存储到缓存时 还需要带一个key
     * @param task
     * @param sessionWrapper
     * @param <K>
     * @param <V>
     */
    private <K, V extends SessionEntity> void runOnRemoteCache(TopologyInfo topology, RemoteCache<K, SessionEntityWrapper<V>> remoteCache, long maxIdleMs, K key, MergedUpdate<V> task, SessionEntityWrapper<V> sessionWrapper) {
        final V session = sessionWrapper.getEntity();
        // 会话转换成operation
        SessionUpdateTask.CacheOperation operation = task.getOperation(session);

        switch (operation) {
            // 移除缓存
            case REMOVE:
                remoteCache.remove(key);
                break;
                // 这种情况 要是existing应该会报错
            case ADD:
                remoteCache.put(key, sessionWrapper.forTransport(),
                        InfinispanUtil.toHotrodTimeMs(remoteCache, task.getLifespanMs()), TimeUnit.MILLISECONDS,
                        InfinispanUtil.toHotrodTimeMs(remoteCache, maxIdleMs), TimeUnit.MILLISECONDS);
                break;
            case ADD_IF_ABSENT:
                SessionEntityWrapper<V> existing = remoteCache
                        .withFlags(Flag.FORCE_RETURN_VALUE)
                        .putIfAbsent(key, sessionWrapper.forTransport(), -1, TimeUnit.MILLISECONDS, InfinispanUtil.toHotrodTimeMs(remoteCache, maxIdleMs), TimeUnit.MILLISECONDS);
                if (existing != null) {
                    logger.debugf("Existing entity in remote cache for key: %s . Will update it", key);

                    // 将task作用在返回的existing 并再次推送
                    replace(topology, remoteCache, task.getLifespanMs(), maxIdleMs, key, task);
                }
                break;
                // 替换缓存的值
            case REPLACE:
                replace(topology, remoteCache, task.getLifespanMs(), maxIdleMs, key, task);
                break;
            default:
                throw new IllegalStateException("Unsupported state " +  operation);
        }
    }


    /**
     * 替换会话信息
     * @param topology
     * @param remoteCache
     * @param lifespanMs
     * @param maxIdleMs
     * @param key
     * @param task
     * @param <K>
     * @param <V>
     */
    private <K, V extends SessionEntity> void replace(TopologyInfo topology, RemoteCache<K, SessionEntityWrapper<V>> remoteCache, long lifespanMs, long maxIdleMs, K key, SessionUpdateTask<V> task) {
        // Adjust based on the hotrod protocol
        lifespanMs = InfinispanUtil.toHotrodTimeMs(remoteCache, lifespanMs);
        maxIdleMs = InfinispanUtil.toHotrodTimeMs(remoteCache, maxIdleMs);

        boolean replaced = false;
        int replaceIteration = 0;
        while (!replaced && replaceIteration < InfinispanUtil.MAXIMUM_REPLACE_RETRIES) {
            replaceIteration++;

            // 获取此时服务器上已经存在的值
            VersionedValue<SessionEntityWrapper<V>> versioned = remoteCache.getWithMetadata(key);
            if (versioned == null) {
                logger.warnf("Not found entity to replace for key '%s'", key);
                return;
            }

            SessionEntityWrapper<V> sessionWrapper = versioned.getValue();
            final V session = sessionWrapper.getEntity();

            // Run task on the remote session   将本地的更新操作作用在远端缓存数据上
            task.runUpdate(session);

            if (logger.isTraceEnabled()) {
                logger.tracef("%s: Before replaceWithVersion. Entity to write version %d: %s", logTopologyData(topology, replaceIteration),
                        versioned.getVersion(), session);
            }

            // 发起提交操作
            replaced = remoteCache.replaceWithVersion(key, SessionEntityWrapper.forTransport(session), versioned.getVersion(), lifespanMs, TimeUnit.MILLISECONDS, maxIdleMs, TimeUnit.MILLISECONDS);

            if (!replaced) {
                logger.debugf("%s: Failed to replace entity '%s' version %d. Will retry again", logTopologyData(topology, replaceIteration), key, versioned.getVersion());
            } else {
                if (logger.isTraceEnabled()) {
                    logger.tracef("%s: Replaced entity version %d in remote cache: %s", logTopologyData(topology, replaceIteration), versioned.getVersion(), session);
                }
            }
        }

        if (!replaced) {
            logger.warnf("Failed to replace entity '%s' in remote cache '%s'", key, remoteCache.getName());
        }
    }


    private String logTopologyData(TopologyInfo topology, int iteration) {
        return topology.toString() + ", replaceIteration: " + iteration;
    }


    /**
     * 包含从远端拉取缓存数据的对象
     */
    private static class RemoteCacheContext {

        private final RemoteCache remoteCache;
        private final MaxIdleTimeLoader maxIdleTimeLoader;

        public RemoteCacheContext(RemoteCache remoteCache, MaxIdleTimeLoader maxIdleLoader) {
            this.remoteCache = remoteCache;
            this.maxIdleTimeLoader = maxIdleLoader;
        }

    }


    @FunctionalInterface
    public interface MaxIdleTimeLoader {

        long getMaxIdleTimeMs(RealmModel realm);

    }


}
