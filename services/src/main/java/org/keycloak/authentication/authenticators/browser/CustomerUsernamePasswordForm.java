package org.keycloak.authentication.authenticators.browser;

import org.keycloak.authentication.AuthenticationFlowContext;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;

/**
 * author: xuelei.guo
 * date: 2023/7/24 22:05
 */
public class CustomerUsernamePasswordForm extends UsernamePasswordForm {

    private String loginUrl = "";

    protected void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        // 根据会话信息生成一个code
        String accessCode = context.generateAccessCode();
        // 拼接生成url
        URI action = context.getActionUrl(accessCode);

        UriBuilder uriBuilder = UriBuilder.fromUri(loginUrl).queryParam("actionUrl", action);

        return Response.status(302).location(uriBuilder.build()).build();
    }
}