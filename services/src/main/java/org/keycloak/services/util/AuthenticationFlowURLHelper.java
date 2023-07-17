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

package org.keycloak.services.util;

import java.net.URI;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 帮助跳转回认证页
 */
public class AuthenticationFlowURLHelper {

    protected static final Logger logger = Logger.getLogger(AuthenticationFlowURLHelper.class);

    private final KeycloakSession session;
    private final RealmModel realm;
    private final UriInfo uriInfo;

    public AuthenticationFlowURLHelper(KeycloakSession session, RealmModel realm, UriInfo uriInfo) {
        this.session = session;
        this.realm = realm;
        this.uriInfo = uriInfo;
    }


    public Response showPageExpired(AuthenticationSessionModel authSession) {
        URI lastStepUrl = getLastExecutionUrl(authSession);

        logger.debugf("Redirecting to 'page expired' now. Will use last step URL: %s", lastStepUrl);

        return session.getProvider(LoginFormsProvider.class).setAuthenticationSession(authSession)
                .setActionUri(lastStepUrl)
                .setExecution(getExecutionId(authSession))
                .createLoginExpiredPage();
    }


    /**
     * 生成一个通往认证流的页面 同时设置参数
     * @param flowPath
     * @param executionId
     * @param clientId
     * @param tabId
     * @return
     */
    public URI getLastExecutionUrl(String flowPath, String executionId, String clientId, String tabId) {
        UriBuilder uriBuilder = LoginActionsService.loginActionsBaseUrl(uriInfo)
                .path(flowPath);

        if (executionId != null) {
            uriBuilder.queryParam(Constants.EXECUTION, executionId);
        }
        uriBuilder.queryParam(Constants.CLIENT_ID, clientId);
        uriBuilder.queryParam(Constants.TAB_ID, tabId);

        return uriBuilder.build(realm.getName());
    }


    /**
     * 返回最近一个执行的认证
     * @param authSession
     * @return
     */
    public URI getLastExecutionUrl(AuthenticationSessionModel authSession) {
        // 获取当前正在执行的认证器id
        String executionId = getExecutionId(authSession);
        String latestFlowPath = authSession.getAuthNote(AuthenticationProcessor.CURRENT_FLOW_PATH);

        if (latestFlowPath == null) {
            latestFlowPath = authSession.getClientNote(AuthorizationEndpointBase.APP_INITIATED_FLOW);
        }

        if (latestFlowPath == null) {
            latestFlowPath = LoginActionsService.AUTHENTICATE_PATH;
        }

        // 拼接path 填充参数
        return getLastExecutionUrl(latestFlowPath, executionId, authSession.getClient().getClientId(), authSession.getTabId());
    }

    private String getExecutionId(AuthenticationSessionModel authSession) {
        return authSession.getAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
    }

}
