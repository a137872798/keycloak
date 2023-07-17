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

package org.keycloak.sessions;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;

/**
 * Predecesor of AuthenticationSessionModel, ClientLoginSessionModel and ClientSessionModel (then action tickets). Maybe we will remove it later...
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 描述针对某个客户端的会话  实际上是 用户会话+client会话   用户会话与客户端会话强绑定
 */
public interface CommonClientSessionModel {

    /**
     * 当认证完成后需要跳转的重定向地址
     * @return
     */
    String getRedirectUri();
    void setRedirectUri(String uri);

    // 描述客户端信息 以及客户端所属的realm
    RealmModel getRealm();
    ClientModel getClient();

    String getAction();
    void setAction(String action);

    /**
     * 交互所使用的协议
     * @return
     */
    String getProtocol();
    void setProtocol(String method);

    enum Action {
        OAUTH_GRANT,
        AUTHENTICATE,
        LOGGED_OUT,
        LOGGING_OUT,
        REQUIRED_ACTIONS
    }

    enum ExecutionStatus {
        FAILED,
        SUCCESS,
        SETUP_REQUIRED,
        ATTEMPTED,
        SKIPPED,
        CHALLENGED,
        EVALUATED_TRUE,
        EVALUATED_FALSE
    }
}
