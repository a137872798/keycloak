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

package org.keycloak.provider.quarkus;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import org.keycloak.platform.Platform;
import org.keycloak.platform.PlatformProvider;

// Quarkus 是一种运行在k8s上的开发栈
public class QuarkusPlatform implements PlatformProvider {

    // 当发现error时 先存储起来
    public static void addInitializationException(Throwable throwable) {
        QuarkusPlatform platform = (QuarkusPlatform) Platform.getPlatform();
        platform.addDeferredException(throwable);
    }

    /**
     * <p>Throws a {@link InitializationException} exception to indicate errors during the startup.
     * 
     * <p>Calling this method after the server is started has no effect but just the exception being thrown.
     * 
     * @throws InitializationException the exception holding all errors during startup.
     * 将所有error组合后 一次性返回
     */
    public static void exitOnError() throws InitializationException {
        QuarkusPlatform platform = (QuarkusPlatform) Platform.getPlatform();
        
        // Check if we had any exceptions during initialization phase
        if (!platform.getDeferredExceptions().isEmpty()) {
            InitializationException quarkusException = new InitializationException();
            for (Throwable inner : platform.getDeferredExceptions()) {
                quarkusException.addSuppressed(inner);
            }
            throw quarkusException;
        }
    }

    /**
     * Similar behavior as per {@code #exitOnError} but convenient to throw a {@link InitializationException} with a single
     * {@code cause}
     * 
     * @param cause the cause
     * @throws InitializationException the initialization exception with the given {@code cause}.
     */
    public static void exitOnError(Throwable cause) throws InitializationException{
        addInitializationException(cause);
        exitOnError();
    }

    Runnable startupHook;
    Runnable shutdownHook;

    // 代表应用已经启动
    private AtomicBoolean started = new AtomicBoolean(false);
    // 存储error
    private List<Throwable> deferredExceptions = new CopyOnWriteArrayList<>();

    // 分别在容器启动前后设置钩子
    @Override
    public void onStartup(Runnable startupHook) {
        this.startupHook = startupHook;
    }
    @Override
    public void onShutdown(Runnable shutdownHook) {
        this.shutdownHook = shutdownHook;
    }

    @Override
    public void exit(Throwable cause) {
        throw new RuntimeException(cause);
    }

    /**
     * Called when Quarkus platform is started
     */
    void started() {
        this.started.set(true);
    }

    public boolean isStarted() {
        return started.get();
    }

    /**
     * Add the exception, which  won't be thrown right-away, but should be thrown later after QuarkusPlatform is initialized (including proper logging)
     *
     * @param t
     */
    private void addDeferredException(Throwable t) {
        deferredExceptions.add(t);
    }

    List<Throwable> getDeferredExceptions() {
        return deferredExceptions;
    }

}
