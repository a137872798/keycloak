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

package org.keycloak.adapters;

import org.jboss.logging.Logger;
import org.keycloak.common.util.HostUtils;
import org.keycloak.common.util.Time;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 节点注册管理器
 * 每隔一段时间 就需要重新注册 更像是在续约
 */
public class NodesRegistrationManagement {

    private static final Logger log = Logger.getLogger(NodesRegistrationManagement.class);

    private final Map<String, NodeRegistrationContext> nodeRegistrations = new ConcurrentHashMap<String, NodeRegistrationContext>();
    // 通过线程池并发注册
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    // Sending registration event during first request to application or if re-registration is needed
    // 当需要重新注册 或者首个请求到达时 触发注册逻辑
    public void tryRegister(final KeycloakDeployment resolvedDeployment) {
        if (resolvedDeployment.isRegisterNodeAtStartup()) {
            // 获取注册的url
            final String registrationUri = resolvedDeployment.getRegisterNodeUrl();
            // 需要重新注册
            if (needRefreshRegistration(registrationUri, resolvedDeployment)) {
                Runnable runnable = new Runnable() {

                    @Override
                    public void run() {
                        // Need to check it again in case that executor triggered by other thread already finished computation in the meantime
                        if (needRefreshRegistration(registrationUri, resolvedDeployment)) {
                            // 注册就是通过该方法
                            sendRegistrationEvent(resolvedDeployment);
                        }
                    }
                };
                executor.execute(runnable);
            }
        }
    }

    private boolean needRefreshRegistration(String registrationUri, KeycloakDeployment resolvedDeployment) {
        NodeRegistrationContext currentRegistration = nodeRegistrations.get(registrationUri);
        /// We don't yet have any registration for this node
        /// 还没有上下文存在 也就是需要注册
        if (currentRegistration == null) {
            return true;
        }

        // 需要重新注册  续约？
        return currentRegistration.lastRegistrationTime + resolvedDeployment.getRegisterNodePeriod() < Time.currentTime();
    }

    /**
     * Called during undeployment or server stop. De-register from all previously registered deployments
     * 当应用服务器被关闭时 本对象也需要关闭  发送注销事件
     */
    public void stop() {
        executor.shutdownNow();

        // 对所有已经注册的节点 发送注销请求
        Collection<NodeRegistrationContext> allRegistrations = nodeRegistrations.values();
        for (NodeRegistrationContext registration : allRegistrations) {
            sendUnregistrationEvent(registration.resolvedDeployment);
        }
    }

    /**
     * 注册
     * @param deployment
     */
    protected void sendRegistrationEvent(KeycloakDeployment deployment) {
        // This method is invoked from single-thread executor, so no synchronization is needed
        // However, it could happen that the same deployment was submitted more than once to that executor
        // Hence we need to recheck that the registration is really needed
        // 本对象通过该地址将自身注册到keycloak上
        final String registrationUri = deployment.getRegisterNodeUrl();
        if (! needRefreshRegistration(registrationUri, deployment)) {
            return;
        }
        if (Thread.currentThread().isInterrupted()) {
            return;
        }

        log.debug("Sending registration event right now");

        // 解析得到本机IP
        String host = HostUtils.getHostName();
        try {
            ServerRequest.invokeRegisterNode(deployment, host);
            NodeRegistrationContext regContext = new NodeRegistrationContext(Time.currentTime(), deployment);
            nodeRegistrations.put(deployment.getRegisterNodeUrl(), regContext);
            log.debugf("Node '%s' successfully registered in Keycloak", host);
        } catch (ServerRequest.HttpFailure failure) {
            log.error("failed to register node to keycloak");
            log.error("status from server: " + failure.getStatus());
            if (failure.getError() != null) {
                log.error("   " + failure.getError());
            }
        } catch (IOException e) {
            log.error("failed to register node to keycloak", e);
        }
    }

    protected boolean sendUnregistrationEvent(KeycloakDeployment deployment) {
        log.debug("Sending Unregistration event right now");

        String host = HostUtils.getHostName();
        try {
            ServerRequest.invokeUnregisterNode(deployment, host);
            log.debugf("Node '%s' successfully unregistered from Keycloak", host);
            return true;
        } catch (ServerRequest.HttpFailure failure) {
            log.error("failed to unregister node from keycloak");
            log.error("status from server: " + failure.getStatus());
            if (failure.getError() != null) {
                log.error("   " + failure.getError());
            }
            return false;
        } catch (IOException e) {
            log.error("failed to unregister node from keycloak", e);
            return false;
        }
    }

    /**
     * 节点注册上下文
     */
    public static class NodeRegistrationContext {

        // 最近的注册时间
        private final Integer lastRegistrationTime;
        // deployment instance used for registration request  里头包括了部署keycloak的各种参数
        private final KeycloakDeployment resolvedDeployment;

        public NodeRegistrationContext(Integer lastRegTime, KeycloakDeployment deployment) {
            this.lastRegistrationTime = lastRegTime;
            this.resolvedDeployment = deployment;
        }
    }

}
