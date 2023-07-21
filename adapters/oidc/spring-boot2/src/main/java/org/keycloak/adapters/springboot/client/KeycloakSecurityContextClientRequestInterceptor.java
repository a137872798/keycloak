package org.keycloak.adapters.springboot.client;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.security.Principal;

/**
 * Interceptor for {@link ClientHttpRequestExecution} objects created for server to server secured
 * communication using OAuth2 bearer tokens issued by Keycloak.
 *
 * @author <a href="mailto:jmcshan1@gmail.com">James McShane</a>
 * @version $Revision: 1 $
 * 该拦截器用在专门和keycloak交互的 RestTemplate上
 */
public class KeycloakSecurityContextClientRequestInterceptor implements ClientHttpRequestInterceptor {

    private static final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * Returns the {@link KeycloakSecurityContext} from the Spring {@link ServletRequestAttributes}'s {@link Principal}.
     *
     * The principal must support retrieval of the KeycloakSecurityContext, so at this point, only {@link KeycloakPrincipal}
     * values are supported
     *
     * @return the current <code>KeycloakSecurityContext</code>
     * 获取keycloak 上下文
     */
    protected KeycloakSecurityContext getKeycloakSecurityContext() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        // 从请求头中获取凭证
        Principal principal = attributes.getRequest().getUserPrincipal();
        if (principal == null) {
            throw new IllegalStateException("Cannot set authorization header because there is no authenticated principal");
        }

        // 要求凭证必须是KeycloakPrincipal类型的  也就是KeycloakPrincipal是keycloak自己提前设置进去的
        if (!(principal instanceof KeycloakPrincipal)) {
            throw new IllegalStateException(
                    String.format(
                            "Cannot set authorization header because the principal type %s does not provide the KeycloakSecurityContext",
                            principal.getClass()));
        }
        return ((KeycloakPrincipal) principal).getKeycloakSecurityContext();
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest httpRequest, byte[] bytes, ClientHttpRequestExecution clientHttpRequestExecution) throws IOException {
        // 获取keycloak上下文  该对象中有从keycloak上获取的 id_token access_token
        KeycloakSecurityContext context = this.getKeycloakSecurityContext();
        // 在发起请求前 自动带上access token
        httpRequest.getHeaders().set(AUTHORIZATION_HEADER, "Bearer " + context.getTokenString());
        return clientHttpRequestExecution.execute(httpRequest, bytes);
    }
}
