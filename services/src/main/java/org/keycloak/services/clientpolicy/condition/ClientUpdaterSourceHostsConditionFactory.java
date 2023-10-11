/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.services.clientpolicy.condition;

import java.util.Arrays;
import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class ClientUpdaterSourceHostsConditionFactory implements ClientPolicyConditionProviderFactory {

    public static final String PROVIDER_ID = "client-updater-source-host";

    public static final String TRUSTED_HOSTS = "trusted-hosts";

    private static final ProviderConfigProperty TRUSTED_HOSTS_PROPERTY = new ProviderConfigProperty(TRUSTED_HOSTS, "client-updater-trusted-hosts.label",
            "client-updater-trusted-hosts.tooltip", ProviderConfigProperty.MULTIVALUED_STRING_TYPE, null);

    @Override
    public ClientPolicyConditionProvider create(KeycloakSession session) {
        return new ClientUpdaterSourceHostsCondition(session);
    }

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "The condition checks the host/domain of the entity who tries to create/update the client to determine whether the policy is applied.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Arrays.asList(TRUSTED_HOSTS_PROPERTY);
    }

}
