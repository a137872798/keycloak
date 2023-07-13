/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.provider.wildfly;

import org.keycloak.platform.PlatformProvider;
import org.keycloak.services.ServicesLogger;

// web应用服务器
public class WildflyPlatform implements PlatformProvider {

    Runnable shutdownHook;

    // 在平台启动前触发钩子
    @Override
    public void onStartup(Runnable startupHook) {
        startupHook.run();
    }

    // 这里只是设置shutdown钩子
    @Override
    public void onShutdown(Runnable shutdownHook) {
        this.shutdownHook = shutdownHook;
    }

    // 代表出现错误 应用在该平台上退出
    @Override
    public void exit(Throwable cause) {
        ServicesLogger.LOGGER.fatal("Error during startup", cause);
        exit(1);
    }

    private void exit(int status) {
        new Thread() {
            @Override
            public void run() {
                System.exit(status);
            }
        }.start();
    }

}
