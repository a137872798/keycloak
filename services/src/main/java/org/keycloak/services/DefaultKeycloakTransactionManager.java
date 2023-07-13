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
package org.keycloak.services;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.transaction.JtaTransactionManagerLookup;
import org.keycloak.transaction.JtaTransactionWrapper;

import javax.transaction.TransactionManager;
import java.util.LinkedList;
import java.util.List;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 * 默认事务管理器
 */
public class DefaultKeycloakTransactionManager implements KeycloakTransactionManager {

    private static final Logger logger = Logger.getLogger(DefaultKeycloakTransactionManager.class);

    // 存储不同状态的事务
    private List<KeycloakTransaction> prepare = new LinkedList<KeycloakTransaction>();
    private List<KeycloakTransaction> transactions = new LinkedList<KeycloakTransaction>();
    private List<KeycloakTransaction> afterCompletion = new LinkedList<KeycloakTransaction>();

    // manager还处于可用状态
    private boolean active;
    private boolean rollback;
    private KeycloakSession session;
    private JTAPolicy jtaPolicy = JTAPolicy.REQUIRES_NEW;
    // Used to prevent double committing/rollback if there is an uncaught exception
    protected boolean completed;

    // 每个会话借助一个事务管理器来管理事务
    public DefaultKeycloakTransactionManager(KeycloakSession session) {
        this.session = session;
    }

    // active = true 代表管理器已经开启 后加入的事务直接begin就好 否则要先搁置 等待manager启动
    @Override
    public void enlist(KeycloakTransaction transaction) {
        if (active && !transaction.isActive()) {
            transaction.begin();
        }

        transactions.add(transaction);
    }
    @Override
    public void enlistAfterCompletion(KeycloakTransaction transaction) {
        if (active && !transaction.isActive()) {
            transaction.begin();
        }

        afterCompletion.add(transaction);
    }
    @Override
    public void enlistPrepare(KeycloakTransaction transaction) {
        if (active && !transaction.isActive()) {
            transaction.begin();
        }

        prepare.add(transaction);
    }

    @Override
    public JTAPolicy getJTAPolicy() {
        return jtaPolicy;
    }

    @Override
    public void setJTAPolicy(JTAPolicy policy) {
        jtaPolicy = policy;

    }

    // 事务管理器 本身就是一个大事务
    @Override
    public void begin() {
        if (active) {
             throw new IllegalStateException("Transaction already active");
        }

        completed = false;

        if (jtaPolicy == JTAPolicy.REQUIRES_NEW) {
            JtaTransactionManagerLookup jtaLookup = session.getProvider(JtaTransactionManagerLookup.class);
            if (jtaLookup != null) {
                // 产生一个jta事务 并加入到list中
                TransactionManager tm = jtaLookup.getTransactionManager();
                if (tm != null) {
                   enlist(new JtaTransactionWrapper(session.getKeycloakSessionFactory(), tm));
                }
            }
        }

        for (KeycloakTransaction tx : transactions) {
            tx.begin();
        }

        active = true;
    }

    @Override
    public void commit() {
        if (completed) {
            return;
        } else {
            completed = true;
        }

        // 触发各个事务的commit 如果发现异常 触发rollback
        RuntimeException exception = null;
        for (KeycloakTransaction tx : prepare) {
            try {
                tx.commit();
            } catch (RuntimeException e) {
                exception = exception == null ? e : exception;
            }
        }
        if (exception != null) {
            rollback(exception);
            return;
        }
        for (KeycloakTransaction tx : transactions) {
            try {
                tx.commit();
            } catch (RuntimeException e) {
                exception = exception == null ? e : exception;
            }
        }

        // Don't commit "afterCompletion" if commit of some main transaction failed
        if (exception == null) {
            for (KeycloakTransaction tx : afterCompletion) {
                try {
                    tx.commit();
                } catch (RuntimeException e) {
                    exception = exception == null ? e : exception;
                }
            }
        } else {
            for (KeycloakTransaction tx : afterCompletion) {
                try {
                    tx.rollback();
                } catch (RuntimeException e) {
                    ServicesLogger.LOGGER.exceptionDuringRollback(e);
                }
            }
        }

        active = false;
        if (exception != null) {
            throw exception;
        }
    }

    @Override
    public void rollback() {
        if (completed) {
            return;
        } else {
            completed = true;
        }

        RuntimeException exception = null;
        rollback(exception);
    }

    protected void rollback(RuntimeException exception) {
        for (KeycloakTransaction tx : transactions) {
            try {
                tx.rollback();
            } catch (RuntimeException e) {
                exception = exception != null ? e : exception;
            }
        }
        for (KeycloakTransaction tx : afterCompletion) {
            try {
                tx.rollback();
            } catch (RuntimeException e) {
                exception = exception != null ? e : exception;
            }
        }
        active = false;
        if (exception != null) {
            throw exception;
        }
    }

    @Override
    public void setRollbackOnly() {
        rollback = true;
    }

    @Override
    public boolean getRollbackOnly() {
        if (rollback) {
            return true;
        }

        for (KeycloakTransaction tx : transactions) {
            if (tx.getRollbackOnly()) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean isActive() {
        return active;
    }

}
