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

package org.keycloak;

import java.util.Set;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * 可以获取spi全名  或者是从系统变量中读取值
 */
public class Config {

    // 相当于默认情况  当SPI加载到拓展provider时 一般是读取某个配置文件 并获取配置值
    private static ConfigProvider configProvider = new SystemPropertiesConfigProvider();

    public static void init(ConfigProvider configProvider) {
        Config.configProvider = configProvider;
    }

    public static String getAdminRealm() {
        return configProvider.scope("admin").get("realm", "master");
    }

    // 生成spi对象的全名
    public static String getProvider(String spi) {
        String provider = configProvider.getProvider(spi);
        if (provider == null || provider.trim().equals("")) {
            return null;
        } else {
            return provider;
        }
    }

    public static Scope scope(String... scope) {
         return configProvider.scope(scope);
    }

    public static interface ConfigProvider {

        // 获取spi全名
        String getProvider(String spi);

        // scope会作为前缀 便于读取系统变量
        Scope scope(String... scope);

    }

    public static class SystemPropertiesConfigProvider implements ConfigProvider {

        @Override
        public String getProvider(String spi) {
            return System.getProperties().getProperty("keycloak." + spi + ".provider");
        }

        // 传入scope 确定前缀名 以便从系统变量中读取配置值
        @Override
        public Scope scope(String... scope) {
            StringBuilder sb = new StringBuilder();
            sb.append("keycloak.");
            for (String s : scope) {
                sb.append(s);
                sb.append(".");
            }
            return new SystemPropertiesScope(sb.toString());
        }

    }

    // 从环境变量中读取配置值 需要一个前缀名进行初始化
    public static class SystemPropertiesScope implements Scope {

        protected String prefix;

        public SystemPropertiesScope(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public String get(String key) {
            return get(key, null);
        }

        @Override
        public String get(String key, String defaultValue) {
            String v = System.getProperty(prefix + key, defaultValue);
            return v != null && !v.isEmpty() ? v : null;
        }

        @Override
        public String[] getArray(String key) {
            String value = get(key);
            if (value != null) {
                String[] a = value.split(",");
                for (int i = 0; i < a.length; i++) {
                    a[i] = a[i].trim();
                }
                return a;
            } else {
                return null;
            }
        }

        @Override
        public Integer getInt(String key) {
            return getInt(key, null);
        }

        @Override
        public Integer getInt(String key, Integer defaultValue) {
            String v = get(key, null);
            return v != null ? Integer.valueOf(v) : defaultValue;
        }

        @Override
        public Long getLong(String key) {
            return getLong(key, null);
        }

        @Override
        public Long getLong(String key, Long defaultValue) {
            String v = get(key, null);
            return v != null ? Long.valueOf(v) : defaultValue;
        }

        @Override
        public Boolean getBoolean(String key) {
            return getBoolean(key, null);
        }

        @Override
        public Boolean getBoolean(String key, Boolean defaultValue) {
            String v = get(key, null);
            if (v != null) {
                return Boolean.valueOf(v);
            } else {
                return defaultValue;
            }
        }

        @Override
        public Scope scope(String... scope) {
            StringBuilder sb = new StringBuilder();
            sb.append(prefix + ".");
            for (String s : scope) {
                sb.append(s);
                sb.append(".");
            }
            return new SystemPropertiesScope(sb.toString());
        }

        @Override
        public Set<String> getPropertyNames() {
            throw new UnsupportedOperationException("Not implemented");
        }

    }

    /**
     * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
     * 采用不同的方式解释读取到的值
     */
    public static interface Scope {

        String get(String key);

        String get(String key, String defaultValue);

        String[] getArray(String key);

        Integer getInt(String key);

        Integer getInt(String key, Integer defaultValue);

        Long getLong(String key);

        Long getLong(String key, Long defaultValue);

        Boolean getBoolean(String key);

        Boolean getBoolean(String key, Boolean defaultValue);

        Scope scope(String... scope);

        Set<String> getPropertyNames();
    }
}
