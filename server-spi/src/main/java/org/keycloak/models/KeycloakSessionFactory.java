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

package org.keycloak.models;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderEventManager;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 工厂本身还支持注册事件监听器
 */
public interface KeycloakSessionFactory extends ProviderEventManager {

    // 作为会话工厂可以创建会话
    KeycloakSession create();

    // 这个会话的概念 更像是一个上下文 而不是常规意义的session
    Set<Spi> getSpis();

    // 根据provider类型 查找SPI实现类
    Spi getSpi(Class<? extends Provider> providerClass);

    // SPI实现类 肯定是由工厂来管理的
    <T extends Provider> ProviderFactory<T> getProviderFactory(Class<T> clazz);

    <T extends Provider> ProviderFactory<T> getProviderFactory(Class<T> clazz, String id);

    /**
     * Returns list of provider factories for the given provider.
     * @param clazz {@code Class<? extends Provider>}
     * @return {@code List<ProviderFactory>} List of provider factories
     * @deprecated Use {@link #getProviderFactoriesStream(Class) getProviderFactoriesStream} instead.
     */
    @Deprecated
    default List<ProviderFactory> getProviderFactories(Class<? extends Provider> clazz) {
        return getProviderFactoriesStream(clazz).collect(Collectors.toList());
    }

    /**
     * Returns stream of provider factories for the given provider.
     * @param clazz {@code Class<? extends Provider>}
     * @return {@code Stream<ProviderFactory>} Stream of provider factories. Never returns {@code null}.
     * 返回该provider相关的工厂
     */
    Stream<ProviderFactory> getProviderFactoriesStream(Class<? extends Provider> clazz);
    
    long getServerStartupTimestamp();

    void close();
}
