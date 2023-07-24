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

import org.apache.catalina.connector.Request;
import org.keycloak.adapters.spi.AdapterSessionStore;

import java.io.IOException;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 基于catalina
 */
public class CatalinaAdapterSessionStore implements AdapterSessionStore {

    /**
     * 本次的请求对象
     */
    protected Request request;

    /**
     * 接入keycloak认证逻辑的阀门对象
     */
    protected AbstractKeycloakAuthenticatorValve valve;

    public CatalinaAdapterSessionStore(Request request, AbstractKeycloakAuthenticatorValve valve) {
        this.request = request;
        this.valve = valve;
    }

    public void saveRequest() {
        try {
            valve.keycloakSaveRequest(request);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean restoreRequest() {
        return valve.keycloakRestoreRequest(request);
    }
}
