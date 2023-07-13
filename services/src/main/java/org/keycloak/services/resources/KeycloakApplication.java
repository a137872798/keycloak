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
package org.keycloak.services.resources;

import com.fasterxml.jackson.core.type.TypeReference;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.common.util.Resteasy;
import org.keycloak.config.ConfigProviderFactory;
import org.keycloak.exportimport.ExportImportManager;
import org.keycloak.migration.MigrationModelManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.dblock.DBLockManager;
import org.keycloak.models.dblock.DBLockProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.platform.Platform;
import org.keycloak.platform.PlatformProvider;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.error.KeycloakErrorHandler;
import org.keycloak.services.filters.KeycloakSecurityHeadersFilter;
import org.keycloak.services.managers.ApplianceBootstrap;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.managers.UserStorageSyncManager;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.scheduled.ClearExpiredClientInitialAccessTokens;
import org.keycloak.services.scheduled.ClearExpiredEvents;
import org.keycloak.services.scheduled.ClearExpiredUserSessions;
import org.keycloak.services.scheduled.ClusterAwareScheduledTaskRunner;
import org.keycloak.services.scheduled.ScheduledTaskRunner;
import org.keycloak.services.util.ObjectMapperResolver;
import org.keycloak.timer.TimerProvider;
import org.keycloak.transaction.JtaTransactionManagerLookup;
import org.keycloak.util.JsonSerialization;

import javax.transaction.SystemException;
import javax.transaction.Transaction;
import javax.ws.rs.core.Application;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 实现 javax.ws.rs规范   核心接口一个是获取内部单例对象的类型 一个是获取单例对象
 */
public class KeycloakApplication extends Application {

    public static final AtomicBoolean BOOTSTRAP_ADMIN_USER = new AtomicBoolean(false);

    private static final Logger logger = Logger.getLogger(KeycloakApplication.class);

    // 维护平台相关的钩子
    protected final PlatformProvider platform = Platform.getPlatform();

    // 作为application 存储相关class以及单例对象
    protected Set<Object> singletons = new HashSet<Object>();
    protected Set<Class<?>> classes = new HashSet<Class<?>>();

    // 该对象用于产生会话
    protected static KeycloakSessionFactory sessionFactory;

    public KeycloakApplication() {

        try {

            logger.debugv("PlatformProvider: {0}", platform.getClass().getName());
            // 获取SPI加载的easyRest框架
            logger.debugv("RestEasy provider: {0}", Resteasy.getProvider().getClass().getName());

            // 借助SPI机制 激活configProvider对象 并设置到全局Config中  这样随时可以通过Config读取配置信息
            loadConfig();

            singletons.add(new RobotsResource());

            // 暴露realm相关的接口
            singletons.add(new RealmsResource());
            // 暴露admin相关的接口
            singletons.add(new AdminRoot());
            // TODO 主题先忽略
            classes.add(ThemeResource.class);
            // TODO 忽略js
            classes.add(JsResource.class);

            classes.add(KeycloakSecurityHeadersFilter.class);
            classes.add(KeycloakErrorHandler.class);

            // json解析器
            singletons.add(new ObjectMapperResolver());
            singletons.add(new WelcomeResource());

            platform.onStartup(this::startup);
            platform.onShutdown(this::shutdown);

        } catch (Throwable t) {
            platform.exit(t);
        }

    }

    // web服务器的情况 需要直接触发函数
    protected void startup() {

        // 初始化session工厂 其中包括了SPI加载
        this.sessionFactory = createSessionFactory();

        ExportImportManager[] exportImportManager = new ExportImportManager[1];

        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

            // 在事务中执行任务 通过session可以拿到事务管理器
            @Override
            public void run(KeycloakSession lockSession) {
                DBLockManager dbLockManager = new DBLockManager(lockSession);
                // 使用前先释放锁
                dbLockManager.checkForcedUnlock();
                // 获取锁启动
                DBLockProvider dbLock = dbLockManager.getDBLock();
                dbLock.waitForLock(DBLockProvider.Namespace.KEYCLOAK_BOOT);
                try {
                    // 完成引导后 产生一个导入导出对象
                    exportImportManager[0] = migrateAndBootstrap();
                } finally {
                    dbLock.releaseLock();
                }
            }

        });

        // 在上面已经完成了初始数据的加载

        // TODO 先忽略导出
        if (exportImportManager[0].isRunExport()) {
            exportImportManager[0].runExport();
        }

        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

            @Override
            public void run(KeycloakSession session) {
                // 判断master realm内是否有用户
                boolean shouldBootstrapAdmin = new ApplianceBootstrap(session).isNoMasterUser();
                BOOTSTRAP_ADMIN_USER.set(shouldBootstrapAdmin);
            }

        });

        sessionFactory.publish(new PostMigrationEvent());

        // 在完成了realm的初始化后 需要开启一些定时任务
        setupScheduledTasks(sessionFactory);
    }

    protected void shutdown() {
        // 当应用终止时 关闭会话工厂
        if (sessionFactory != null)
            sessionFactory.close();
    }

    // Migrate model, bootstrap master realm, import realms and create admin user. This is done with acquired dbLock
    // 导入数据并完成引导
    protected ExportImportManager migrateAndBootstrap() {
        ExportImportManager exportImportManager;
        logger.debug("Calling migrateModel");
        // 先忽略迁移
        migrateModel();

        logger.debug("bootstrap");
        KeycloakSession session = sessionFactory.create();
        try {
            // 开启事务
            session.getTransactionManager().begin();
            JtaTransactionManagerLookup lookup = (JtaTransactionManagerLookup) sessionFactory.getProviderFactory(JtaTransactionManagerLookup.class);
            if (lookup != null) {
                if (lookup.getTransactionManager() != null) {
                    try {
                        Transaction transaction = lookup.getTransactionManager().getTransaction();
                        logger.debugv("bootstrap current transaction? {0}", transaction != null);
                        if (transaction != null) {
                            logger.debugv("bootstrap current transaction status? {0}", transaction.getStatus());
                        }
                    } catch (SystemException e) {
                        throw new RuntimeException(e);
                    }
                }
            }

            // 进行应用的引导工作
            ApplianceBootstrap applianceBootstrap = new ApplianceBootstrap(session);
            // 该对象内部包含导入或者导出对象
            exportImportManager = new ExportImportManager(session);

            // true 代表master realm未创建  / false代表已创建
            boolean createMasterRealm = applianceBootstrap.isNewInstall();
            // 表示exportImportManager 会负责进行数据的导入 并且导入数据包含master realm  那么就不需要创建了
            if (exportImportManager.isRunImport() && exportImportManager.isImportMasterIncluded()) {
                createMasterRealm = false;
            }

            // 创建 master realm   并且会在结束后将realm设置到session中
            if (createMasterRealm) {
                applianceBootstrap.createMasterRealm();
            }
            session.getTransactionManager().commit();
        } catch (RuntimeException re) {
            if (session.getTransactionManager().isActive()) {
                // 实际上创建过程涉及了各种DB操作 所以rollback可以做到回滚
                session.getTransactionManager().rollback();
            }
            throw re;
        } finally {
            session.close();
        }

        // 开始进行import工作
        if (exportImportManager.isRunImport()) {
            exportImportManager.runImport();
        } else {
            // 代表没法通过exportImportManager进行导入
            importRealms();
        }

        importAddUser();

        return exportImportManager;
    }


    // 在事务内开启迁移  迁移指的是不同版本之间数据迁移  可以先不考虑
    protected void migrateModel() {
        KeycloakSession session = sessionFactory.create();
        try {
            session.getTransactionManager().begin();
            MigrationModelManager.migrate(session);
            session.getTransactionManager().commit();
        } catch (Exception e) {
            session.getTransactionManager().rollback();
            throw e;
        } finally {
            session.close();
        }
    }


    protected void loadConfig() {

        // 基于SPI机制产生一个配置对象 或基于系统变量 或基于JSON文件
        ServiceLoader<ConfigProviderFactory> loader = ServiceLoader.load(ConfigProviderFactory.class, KeycloakApplication.class.getClassLoader());

        try {
            ConfigProviderFactory factory = loader.iterator().next();
            logger.debugv("ConfigProvider: {0}", factory.getClass().getName());
            Config.init(factory.create().orElseThrow(() -> new RuntimeException("Failed to load Keycloak configuration")));
        } catch (NoSuchElementException e) {
            throw new RuntimeException("No valid ConfigProvider found");
        }

    }

    // 启动应用时 创建会话工厂
    public static KeycloakSessionFactory createSessionFactory() {
        DefaultKeycloakSessionFactory factory = new DefaultKeycloakSessionFactory();
        factory.init();
        return factory;
    }

    /**
     * 开启一些定时任务
     * @param sessionFactory
     */
    public static void setupScheduledTasks(final KeycloakSessionFactory sessionFactory) {
        long interval = Config.scope("scheduled").getLong("interval", 900L) * 1000;

        KeycloakSession session = sessionFactory.create();
        try {
            // 定时任务都在事务中进行
            TimerProvider timer = session.getProvider(TimerProvider.class);
            // ClusterAwareScheduledTaskRunner 将任务从单节点变成作用在集群上
            timer.schedule(new ClusterAwareScheduledTaskRunner(sessionFactory, new ClearExpiredEvents(), interval), interval, "ClearExpiredEvents");
            // 通过定时扫描的方式清除过期token
            timer.schedule(new ClusterAwareScheduledTaskRunner(sessionFactory, new ClearExpiredClientInitialAccessTokens(), interval), interval, "ClearExpiredClientInitialAccessTokens");
            // 定期清理用户会话
            timer.schedule(new ScheduledTaskRunner(sessionFactory, new ClearExpiredUserSessions()), interval, ClearExpiredUserSessions.TASK_NAME);
            new UserStorageSyncManager().bootstrapPeriodic(sessionFactory, timer);
        } finally {
            session.close();
        }
    }

    public static KeycloakSessionFactory getSessionFactory() {
        return sessionFactory;
    }

    @Override
    public Set<Class<?>> getClasses() {
        return classes;
    }

    @Override
    public Set<Object> getSingletons() {
        return singletons;
    }

    /**
     * 降级处理就是读取指定目录下的文件 解析成json
     */
    public void importRealms() {
        String files = System.getProperty("keycloak.import");
        if (files != null) {
            StringTokenizer tokenizer = new StringTokenizer(files, ",");
            while (tokenizer.hasMoreTokens()) {
                String file = tokenizer.nextToken().trim();
                RealmRepresentation rep;
                try {
                    rep = loadJson(new FileInputStream(file), RealmRepresentation.class);
                } catch (FileNotFoundException e) {
                    throw new RuntimeException(e);
                }
                importRealm(rep, "file " + file);
            }
        }
    }

    public void importRealm(RealmRepresentation rep, String from) {
        KeycloakSession session = sessionFactory.create();
        boolean exists = false;
        try {
            session.getTransactionManager().begin();

            try {
                RealmManager manager = new RealmManager(session);

                if (rep.getId() != null && manager.getRealm(rep.getId()) != null) {
                    ServicesLogger.LOGGER.realmExists(rep.getRealm(), from);
                    exists = true;
                }

                if (manager.getRealmByName(rep.getRealm()) != null) {
                    ServicesLogger.LOGGER.realmExists(rep.getRealm(), from);
                    exists = true;
                }
                if (!exists) {
                    RealmModel realm = manager.importRealm(rep);
                    ServicesLogger.LOGGER.importedRealm(realm.getName(), from);
                }
                session.getTransactionManager().commit();
            } catch (Throwable t) {
                session.getTransactionManager().rollback();
                if (!exists) {
                    ServicesLogger.LOGGER.unableToImportRealm(t, rep.getRealm(), from);
                }
            }
        } finally {
            session.close();
        }
    }

    public void importAddUser() {
        String configDir = System.getProperty("jboss.server.config.dir");
        if (configDir != null) {
            File addUserFile = new File(configDir + File.separator + "keycloak-add-user.json");
            if (addUserFile.isFile()) {
                ServicesLogger.LOGGER.imprtingUsersFrom(addUserFile);

                List<RealmRepresentation> realms;
                try {
                    realms = JsonSerialization.readValue(new FileInputStream(addUserFile), new TypeReference<List<RealmRepresentation>>() {
                    });
                } catch (IOException e) {
                    ServicesLogger.LOGGER.failedToLoadUsers(e);
                    return;
                }

                for (RealmRepresentation realmRep : realms) {
                    for (UserRepresentation userRep : realmRep.getUsers()) {
                        KeycloakSession session = sessionFactory.create();

                        try {
                            session.getTransactionManager().begin();
                            RealmModel realm = session.realms().getRealmByName(realmRep.getRealm());

                            if (realm == null) {
                                ServicesLogger.LOGGER.addUserFailedRealmNotFound(userRep.getUsername(), realmRep.getRealm());
                            }

                            UserProvider users = session.users();

                            if (users.getUserByUsername(realm, userRep.getUsername()) != null) {
                                ServicesLogger.LOGGER.notCreatingExistingUser(userRep.getUsername());
                            } else {
                                UserModel user = users.addUser(realm, userRep.getUsername());
                                user.setEnabled(userRep.isEnabled());
                                RepresentationToModel.createCredentials(userRep, session, realm, user, false);
                                RepresentationToModel.createRoleMappings(userRep, user, realm);
                                ServicesLogger.LOGGER.addUserSuccess(userRep.getUsername(), realmRep.getRealm());
                            }

                            session.getTransactionManager().commit();
                        } catch (ModelDuplicateException e) {
                            session.getTransactionManager().rollback();
                            ServicesLogger.LOGGER.addUserFailedUserExists(userRep.getUsername(), realmRep.getRealm());
                        } catch (Throwable t) {
                            session.getTransactionManager().rollback();
                            ServicesLogger.LOGGER.addUserFailed(t, userRep.getUsername(), realmRep.getRealm());
                        } finally {
                            session.close();
                        }
                    }
                }

                if (!addUserFile.delete()) {
                    ServicesLogger.LOGGER.failedToDeleteFile(addUserFile.getAbsolutePath());
                }
            }
        }
    }

    private static <T> T loadJson(InputStream is, Class<T> type) {
        try {
            return JsonSerialization.readValue(is, type);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse json", e);
        }
    }

}
