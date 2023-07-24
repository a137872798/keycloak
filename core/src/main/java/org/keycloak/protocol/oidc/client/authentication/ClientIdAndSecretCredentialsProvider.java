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

package org.keycloak.protocol.oidc.client.authentication;

import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.util.BasicAuthHelper;

/**
 * Traditional OAuth2 authentication of clients based on client_id and client_secret
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClientIdAndSecretCredentialsProvider implements ClientCredentialsProvider {

    private static Logger logger = Logger.getLogger(ClientIdAndSecretCredentialsProvider.class);

    public static final String PROVIDER_ID = CredentialRepresentation.SECRET;

    private String clientSecret;

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(AdapterConfig deployment, Object config) {
        clientSecret = (config == null ? null : config.toString());
    }

    /**
     * 在将请求发往keycloak服务器前 需要添加一些请求头
     * @param deployment Fully resolved deployment
     * @param requestHeaders You should put any HTTP request headers you want to use for authentication of client. These headers will be attached to the HTTP request sent to Keycloak server
     * @param formParams You should put any request parameters you want to use for authentication of client. These parameters will be attached to the HTTP request sent to Keycloak server
     */
    @Override
    public void setClientCredentials(AdapterConfig deployment, Map<String, String> requestHeaders, Map<String, String> formParams) {
        String clientId = deployment.getResource();

        if (!deployment.isPublicClient()) {
            if (clientSecret != null) {
                String authorization = BasicAuthHelper.RFC6749.createHeader(clientId, clientSecret);
                requestHeaders.put("Authorization", authorization);
            } else {
                logger.warnf("Client '%s' doesn't have secret available", clientId);
            }
        } else {
            formParams.put(OAuth2Constants.CLIENT_ID, clientId);
        }
    }
}
