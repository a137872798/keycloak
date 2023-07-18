/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.services.clientpolicy.context;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;

/**
 * 认证请求对应的上下文
 */
public class AuthorizationRequestContext implements ClientPolicyContext {

    private final OIDCResponseType parsedResponseType;
    /**
     * 从本次认证请求参数中解析出来的
     */
    private final AuthorizationEndpointRequest request;
    /**
     * 认证产生结果后的重定向地址
     */
    private final String redirectUri;
    /**
     * 请求参数
     */
    private final MultivaluedMap<String, String> requestParameters;

    public AuthorizationRequestContext(OIDCResponseType parsedResponseType,
            AuthorizationEndpointRequest request,
            String redirectUri,
            MultivaluedMap<String, String> requestParameters) {
        this.parsedResponseType = parsedResponseType;
        this.request = request;
        this.redirectUri = redirectUri;
        this.requestParameters = requestParameters;
    }

    @Override
    public ClientPolicyEvent getEvent() {
        return ClientPolicyEvent.AUTHORIZATION_REQUEST;
    }

    public OIDCResponseType getparsedResponseType() {
        return parsedResponseType;
    }

    public AuthorizationEndpointRequest getAuthorizationEndpointRequest() {
        return request;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
 
    public MultivaluedMap<String, String> getRequestParameters() {
        return requestParameters;
    }
}
