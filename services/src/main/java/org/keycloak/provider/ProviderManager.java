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
package org.keycloak.provider;

import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.services.DefaultKeycloakSessionFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * 通过该对象管理所有的提供者
 */
public class ProviderManager {

    private static final Logger logger = Logger.getLogger(ProviderManager.class);

    private final KeycloakDeploymentInfo info;

    // 每个Loader对象都可以加载SPI对象
    private List<ProviderLoader> loaders = new LinkedList<ProviderLoader>();

    // spi可以加载一组工厂实例 而这组工厂都是用来产生期望的provider的  注意这是一个MultivaluedHashMap对象
    // Provider 描述的是接口  ProviderFactory 描述的是实现类
    private MultivaluedHashMap<Class<? extends Provider>, ProviderFactory> cache = new MultivaluedHashMap<>();


    /**
     * @param info  存储provider的容器
     * @param baseClassLoader
     * @param resources  相关提供者名字
     */
    public ProviderManager(KeycloakDeploymentInfo info, ClassLoader baseClassLoader, String... resources) {
        this.info = info;
        List<ProviderLoaderFactory> factories = new LinkedList<ProviderLoaderFactory>();
        // ProviderLoaderFactory决定了会加载到哪些 ProviderLoader    每个ProviderLoader 又可以加载一组Spi对象
        // 每个Spi对象又可以加载一组 ProviderFactory
        for (ProviderLoaderFactory f : ServiceLoader.load(ProviderLoaderFactory.class, getClass().getClassLoader())) {
            factories.add(f);
        }

        logger.debugv("Provider loaders {0}", factories);

        // 存入2个默认的
        loaders.add(new DefaultProviderLoader(info, baseClassLoader));
        loaders.add(new DeploymentProviderLoader(info));

        // 描述需要加载哪些providerLoader
        if (resources != null) {
            for (String r : resources) {
                String type = r.substring(0, r.indexOf(':'));
                String resource = r.substring(r.indexOf(':') + 1, r.length());

                boolean found = false;
                for (ProviderLoaderFactory f : factories) {
                    if (f.supports(type)) {
                        KeycloakDeploymentInfo resourceInfo = KeycloakDeploymentInfo.create().services();
                        loaders.add(f.create(resourceInfo, baseClassLoader, resource));
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    throw new RuntimeException("Provider loader for " + r + " not found");
                }
            }
        }
    }

    // 加载所有spi对象
    public synchronized List<Spi> loadSpis() {
        // Use a map to prevent duplicates, since the loaders may have overlapping classpaths.
        Map<String, Spi> spiMap = new HashMap<>();
        for (ProviderLoader loader : loaders) {
            List<Spi> spis = loader.loadSpis();
            if (spis != null) {
                for (Spi spi : spis) {
                    spiMap.put(spi.getName(), spi);
                }
            }
        }
        return new LinkedList<>(spiMap.values());
    }

    public synchronized List<ProviderFactory> load(Spi spi) {
        if (!cache.containsKey(spi.getProviderClass())) {

            Map<String, ProviderFactory> loaded = new HashMap<>();
            for (ProviderLoader loader : loaders) {
                List<ProviderFactory> f = loader.load(spi);
                if (f != null) {
                    for (ProviderFactory pf: f) {
                        String uniqueId = spi.getName() + "-" + pf.getId();
                        if (!loaded.containsKey(uniqueId)) {
                            loaded.put(uniqueId, pf);
                        } else {
                            ProviderFactory currentFactory = loaded.get(uniqueId);
                            ProviderFactory factoryToUse = compareFactories(currentFactory, pf);
                            loaded.put(uniqueId, factoryToUse);

                            logger.debugf("Found multiple provider factories of same provider ID implementing same SPI. SPI is '%s', providerFactory ID '%s'. Factories are '%s' and '%s'. Using provider factory '%s'.",
                                    spi.getName(), pf.getId(), currentFactory.getClass().getName(), pf.getClass().getName(), factoryToUse.getClass().getName());
                        }
                    }
                }
            }

            for (ProviderFactory providerFactory : loaded.values()) {
                cache.add(spi.getProviderClass(), providerFactory);
            }
        }
        List<ProviderFactory> rtn = cache.get(spi.getProviderClass());
        return rtn == null ? Collections.EMPTY_LIST : rtn;
    }

    // Compare provider factories of same providerId. Just one of them needs to be chosen to be used in Keycloak
    public ProviderFactory compareFactories(ProviderFactory p1, ProviderFactory p2) {
        if (p1.order() != p2.order()) return (p1.order() > p2.order()) ? p1 : p2;

        // Internal factory is supposed to be overriden by custom factory
        if (DefaultKeycloakSessionFactory.isInternal(p1) ^ DefaultKeycloakSessionFactory.isInternal(p2)) {
            return DefaultKeycloakSessionFactory.isInternal(p1) ? p2 : p1;
        }

        return p1;
    }

    /**
     * returns a copy of internal factories.
     *
     * @return
     */
    public synchronized MultivaluedHashMap<Class<? extends Provider>, ProviderFactory> getLoadedFactories() {
        MultivaluedHashMap<Class<? extends Provider>, ProviderFactory> copy = new MultivaluedHashMap<>();
        copy.addAll(cache);
        return copy;
    }

    public synchronized ProviderFactory load(Spi spi, String providerId) {
        for (ProviderFactory f : load(spi)) {
            if (f.getId().equals(providerId)) {
                return f;
            }
        }
        return null;
    }

    public synchronized KeycloakDeploymentInfo getInfo() {
        return  info;
    }

}
