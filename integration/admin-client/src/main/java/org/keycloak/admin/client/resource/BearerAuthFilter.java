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

package org.keycloak.admin.client.resource;

import org.keycloak.admin.client.token.TokenManager;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientResponseFilter;
import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;
import java.util.List;

/**
 * @author rodrigo.sasaki@icarros.com.br
 * 认证过滤器
 */
public class BearerAuthFilter implements ClientRequestFilter, ClientResponseFilter {

    public static final String AUTH_HEADER_PREFIX = "Bearer ";
    private final String tokenString;
    private final TokenManager tokenManager;

    // 要么是使用固定的token  要么是使用

    public BearerAuthFilter(String tokenString) {
        this.tokenString = tokenString;
        this.tokenManager = null;
    }

    public BearerAuthFilter(TokenManager tokenManager) {
        this.tokenManager = tokenManager;
        this.tokenString = null;
    }


    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        String authHeader = (tokenManager != null ? tokenManager.getAccessTokenString() : tokenString);
        if (!authHeader.startsWith(AUTH_HEADER_PREFIX)) {
            authHeader = AUTH_HEADER_PREFIX + authHeader;
        }
        // token 会自动加在请求头上
        requestContext.getHeaders().add(HttpHeaders.AUTHORIZATION, authHeader);
    }

    @Override
    public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) throws IOException {
        // 401 代表需要用户认证 也就是之前关联的token已经无效了
        if (responseContext.getStatus() == 401 && tokenManager != null) {
            List<Object> authHeaders = requestContext.getHeaders().get(HttpHeaders.AUTHORIZATION);
            if (authHeaders == null) {
                return;
            }
            for (Object authHeader : authHeaders) {
                if (authHeader instanceof String) {
                    String headerValue = (String) authHeader;
                    if (headerValue.startsWith(AUTH_HEADER_PREFIX)) {
                        String token = headerValue.substring( AUTH_HEADER_PREFIX.length() );
                        // 使得token无效
                        tokenManager.invalidate( token );
                    }
                }
            }
        }
    }
}
