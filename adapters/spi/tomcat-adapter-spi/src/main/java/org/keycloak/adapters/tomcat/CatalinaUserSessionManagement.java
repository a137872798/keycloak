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

package org.keycloak.adapters.tomcat;

import org.apache.catalina.Manager;
import org.apache.catalina.Session;
import org.apache.catalina.SessionEvent;
import org.apache.catalina.SessionListener;
import org.apache.catalina.realm.GenericPrincipal;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.List;

/**
 * Manages relationship to users and sessions so that forced admin logout can be implemented
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 监听tomcat会话相关的事件
 */
public class CatalinaUserSessionManagement implements SessionListener {
    private static final Logger log = Logger.getLogger(CatalinaUserSessionManagement.class);

    /**
     * 当产生一个新的session时  就将本对象注册成监听器
     * @param session
     */
    public void login(Session session) {
        session.addSessionListener(this);
    }

    /**
     * 所有会话完成登出
     * @param sessionManager
     */
    public void logoutAll(Manager sessionManager) {
        Session[] allSessions = sessionManager.findSessions();
        for (Session session : allSessions) {
            logoutSession(session);
        }
    }

    public void logoutHttpSessions(Manager sessionManager, List<String> sessionIds) {
        log.debug("logoutHttpSessions: " + sessionIds);

        for (String sessionId : sessionIds) {
            logoutSession(sessionManager, sessionId);
        }
    }

    /**
     * 通过id查找 并触发登出
     * @param manager
     * @param httpSessionId
     */
    protected void logoutSession(Manager manager, String httpSessionId) {
        log.debug("logoutHttpSession: " + httpSessionId);

        Session session;
        try {
            session = manager.findSession(httpSessionId);
        } catch (IOException ioe) {
            log.warn("IO exception when looking for session " + httpSessionId, ioe);
            return;
        }

        logoutSession(session);
    }

    /**
     * 将会话标记成过期
     * @param session
     */
    protected void logoutSession(Session session) {
        try {
            // 这个举动会产生session事件 并触发监听器
            if (session != null) session.expire();
        } catch (Exception e) {
            log.debug("Session not present or already invalidated.", e);
        }
    }

    /**
     * 当收到会话事件时 触发该方法
     * @param event
     */
    public void sessionEvent(SessionEvent event) {
        // We only care about session destroyed events
        // 只关注会话销毁事件
        if (!Session.SESSION_DESTROYED_EVENT.equals(event.getType()))
            return;

        // Look up the single session id associated with this session (if any)
        Session session = event.getSession();
        log.debugf("Session %s destroyed", session.getId());

        GenericPrincipal principal = (GenericPrincipal) session.getPrincipal();
        if (principal == null) return;

        // 就是将principal 从session上移除
        session.setPrincipal(null);
        session.setAuthType(null);
    }
}
