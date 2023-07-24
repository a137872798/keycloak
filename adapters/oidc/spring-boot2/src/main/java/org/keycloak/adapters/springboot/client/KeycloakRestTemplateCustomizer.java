package org.keycloak.adapters.springboot.client;

import org.springframework.boot.web.client.RestTemplateCustomizer;
import org.springframework.web.client.RestTemplate;

public class KeycloakRestTemplateCustomizer implements RestTemplateCustomizer {

    private final KeycloakSecurityContextClientRequestInterceptor keycloakInterceptor;

    public KeycloakRestTemplateCustomizer() {
        this(new KeycloakSecurityContextClientRequestInterceptor());
    }

    protected KeycloakRestTemplateCustomizer(
            KeycloakSecurityContextClientRequestInterceptor keycloakInterceptor
    ) {
        this.keycloakInterceptor = keycloakInterceptor;
    }

    /**
     * 在spring boot 内部的http客户端上追加一个keycloak拦截器
     * @param restTemplate
     */
    @Override
    public void customize(RestTemplate restTemplate) {
        restTemplate.getInterceptors().add(keycloakInterceptor);
    }
}
