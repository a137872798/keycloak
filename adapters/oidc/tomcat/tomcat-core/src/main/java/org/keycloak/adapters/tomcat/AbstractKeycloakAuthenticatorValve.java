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

import org.apache.catalina.*;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.jboss.logging.Logger;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.NodesRegistrationManagement;
import org.keycloak.adapters.PreAuthActionsHandler;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.enums.TokenStore;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Keycloak authentication valve
 * 
 * @author <a href="mailto:ungarida@gmail.com">Davide Ungari</a>
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * keycloak认证阀门
 */
public abstract class AbstractKeycloakAuthenticatorValve extends FormAuthenticator implements LifecycleListener {

    public static final String TOKEN_STORE_NOTE = "TOKEN_STORE_NOTE";

	private final static Logger log = Logger.getLogger(AbstractKeycloakAuthenticatorValve.class);

	// 该对象负责为session注册监听器 并在session过期时 移除session绑定的principal
	protected CatalinaUserSessionManagement userSessionManagement = new CatalinaUserSessionManagement();

	// 该对象包含了keycloak相关的各种配置 oidc相关的各endpoint
    protected AdapterDeploymentContext deploymentContext;

    /**
     * 节点注册管理器  可以注册节点和注销节点  需要定期注册 (或者理解为续约)
     */
    protected NodesRegistrationManagement nodesRegistrationManagement;

    /**
     * 收到 tomcat 相关事件
     * @param event
     */
    @Override
    public void lifecycleEvent(LifecycleEvent event) {
        if (Lifecycle.START_EVENT.equals(event.getType())) {
            // 当重启时 要关闭缓存
            cache = false;
        } else if (Lifecycle.AFTER_START_EVENT.equals(event.getType())) {
            // 启动完毕后 进行keycloak相关的初始化
        	keycloakInit();
        } else if (event.getType() == Lifecycle.BEFORE_STOP_EVENT) {
            // 进行一些关闭工作
            beforeStop();
        }
    }

    protected void logoutInternal(Request request) {
        KeycloakSecurityContext ksc = (KeycloakSecurityContext)request.getAttribute(KeycloakSecurityContext.class.getName());
        if (ksc != null) {
            CatalinaHttpFacade facade = new OIDCCatalinaHttpFacade(request, null);
            KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);
            if (ksc instanceof RefreshableKeycloakSecurityContext) {
                ((RefreshableKeycloakSecurityContext) ksc).logout(deployment);
            }

            AdapterTokenStore tokenStore = getTokenStore(request, facade, deployment);
            tokenStore.logout();
            request.removeAttribute(KeycloakSecurityContext.class.getName());
        }
        request.setUserPrincipal(null);
    }

    protected void beforeStop() {
        if (nodesRegistrationManagement != null) {
            nodesRegistrationManagement.stop();
        }
    }


    /**
     * 在tomcat启动时 做一些初始化工作
     */
    @SuppressWarnings("UseSpecificCatch")
    public void keycloakInit() {
        // Possible scenarios:
        // 1) The deployment has a keycloak.config.resolver specified and it exists:
        //    Outcome: adapter uses the resolver
        // 2) The deployment has a keycloak.config.resolver and isn't valid (doesn't exist, isn't a resolver, ...) :
        //    Outcome: adapter is left unconfigured
        // 3) The deployment doesn't have a keycloak.config.resolver , but has a keycloak.json (or equivalent)
        //    Outcome: adapter uses it
        // 4) The deployment doesn't have a keycloak.config.resolver nor keycloak.json (or equivalent)
        //    Outcome: adapter is left unconfigured

        // 在tomcat的context中 可以获取到初始化参数   当上层使用spring boot时 对应KeycloakSpringBootConfigResolverWrapper
        String configResolverClass = context.getServletContext().getInitParameter("keycloak.config.resolver");

        // 从上下文配置可以拿到一个配置解析器
        if (configResolverClass != null) {
            try {
                // 通过配置解析器 初始化deploymentContext(部署上下文对象)
                KeycloakConfigResolver configResolver = (KeycloakConfigResolver) context.getLoader().getClassLoader().loadClass(configResolverClass).newInstance();
                deploymentContext = new AdapterDeploymentContext(configResolver);
                log.debugv("Using {0} to resolve Keycloak configuration on a per-request basis.", configResolverClass);
            } catch (Exception ex) {
                log.errorv("The specified resolver {0} could NOT be loaded. Keycloak is unconfigured and will deny all requests. Reason: {1}", configResolverClass, ex.getMessage());
                deploymentContext = new AdapterDeploymentContext(new KeycloakDeployment());
            }
        } else {
            InputStream configInputStream = getConfigInputStream(context);
            KeycloakDeployment kd;
            if (configInputStream == null) {
                log.warn("No adapter configuration. Keycloak is unconfigured and will deny all requests.");
                // 没有获取到配置解析器时采用的fallback
                kd = new KeycloakDeployment();
            } else {
                kd = KeycloakDeploymentBuilder.build(configInputStream);
            }
            deploymentContext = new AdapterDeploymentContext(kd);
            log.debug("Keycloak is using a per-deployment configuration.");
        }

        // 上面就是2种不同的初始化方式 一个是通过配置解析器初始化AdapterDeploymentContext  一个是用配置好的KeycloakDeployment初始化AdapterDeploymentContext

        // 这样之后随时可以拿到 AdapterDeploymentContext对象
        context.getServletContext().setAttribute(AdapterDeploymentContext.class.getName(), deploymentContext);
        // 基于该上下文创建一个认证器阀门 并设置在下一环
        AbstractAuthenticatedActionsValve actions = createAuthenticatedActionsValve(deploymentContext, getNext(), getContainer());
        setNext(actions);

        // 初始化一个node注册管理器
        nodesRegistrationManagement = new NodesRegistrationManagement();
    }


    /**
     * 读取context配置 得到一个json字符串
     * @param servletContext
     * @return
     */
    private static InputStream getJSONFromServletContext(ServletContext servletContext) {
        String json = servletContext.getInitParameter(AdapterConstants.AUTH_DATA_PARAM_NAME);
        if (json == null) {
            return null;
        }
        log.trace("**** using " + AdapterConstants.AUTH_DATA_PARAM_NAME);
        return new ByteArrayInputStream(json.getBytes());
    }

    /**
     * 读取一个json文件
     * @param context
     * @return
     */
    private static InputStream getConfigInputStream(Context context) {
        // 反正就是挨个尝试读取
        InputStream is = getJSONFromServletContext(context.getServletContext());
        if (is == null) {
            String path = context.getServletContext().getInitParameter("keycloak.config.file");
            if (path == null) {
                log.trace("**** using /WEB-INF/keycloak.json");
                is = context.getServletContext().getResourceAsStream("/WEB-INF/keycloak.json");
            } else {
                try {
                    is = new FileInputStream(path);
                } catch (FileNotFoundException e) {
                    log.errorv("NOT FOUND {0}", path);
                    throw new RuntimeException(e);
                }
            }
        }
        return is;
    }

    /**
     * 处理请求
     * @param request
     * @param response
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        try {
            // 将req/res包装成门面对象
            CatalinaHttpFacade facade = new OIDCCatalinaHttpFacade(request, response);
            // session通过该对象维护
            Manager sessionManager = request.getContext().getManager();
            CatalinaUserSessionManagementWrapper sessionManagementWrapper = new CatalinaUserSessionManagementWrapper(userSessionManagement, sessionManager);
            // 在认证前起作用的handler  能够被该对象处理的请求 都是一些特殊命令 JWT也是直接以请求体的方式传递
            PreAuthActionsHandler handler = new PreAuthActionsHandler(sessionManagementWrapper, deploymentContext, facade);
            // 代表请求已经被处理完毕了
            if (handler.handleRequest()) {
                return;
            }

            // 先找到TokenStore 然后检查会话 如果过期自动进行续约 如果无法续约删除会话
            checkKeycloakSession(request, facade);
            // super.invoke 会检查本次请求是否需要认证  如果需要会触发doAuthenticate
            super.invoke(request, response);
        } finally {
        }
    }

    protected abstract PrincipalFactory createPrincipalFactory();
    protected abstract boolean forwardToErrorPageInternal(Request request, HttpServletResponse response, Object loginConfig) throws IOException;

    /**
     * 创建一个包含认证逻辑的阀门对象
     * @param deploymentContext
     * @param next
     * @param container
     * @return
     */
    protected abstract AbstractAuthenticatedActionsValve createAuthenticatedActionsValve(AdapterDeploymentContext deploymentContext, Valve next, Container container);


    /**
     * 认证逻辑
     * @param request
     * @param response
     * @param loginConfig
     * @return
     * @throws IOException
     */
    protected boolean authenticateInternal(Request request, HttpServletResponse response, Object loginConfig) throws IOException {

        CatalinaHttpFacade facade = new OIDCCatalinaHttpFacade(request, response);
        KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);

        // keycloak的配置有问题 无法使用 也就无法认证
        if (deployment == null || !deployment.isConfigured()) {
            //needed for the EAP6/AS7 adapter relying on the tomcat core adapter
            facade.getResponse().sendError(401);
            return false;
        }

        // 获取之前创建的store
        AdapterTokenStore tokenStore = getTokenStore(request, facade, deployment);

        // 每个应用在配置中需要声明clientId 现在在借助keycloak的认证能力前 需要先注册  就是在keycloak服务器的表中增加一个client-node的关联关系 包括node的注册时间
        nodesRegistrationManagement.tryRegister(deployment);

        // 创建请求认证器
        CatalinaRequestAuthenticator authenticator = createRequestAuthenticator(request, facade, deployment, tokenStore);
        // 需要的参数都已经设置进去了 直接触发认证逻辑即可
        AuthOutcome outcome = authenticator.authenticate();

        // 已通过认证
        if (outcome == AuthOutcome.AUTHENTICATED) {
            if (facade.isEnded()) {
                return false;
            }
            return true;
        }
        AuthChallenge challenge = authenticator.getChallenge();
        if (challenge != null) {
            challenge.challenge(facade);
        }
        // 返回false 会导致流程提前结束
        return false;
    }

    protected CatalinaRequestAuthenticator createRequestAuthenticator(Request request, CatalinaHttpFacade facade, KeycloakDeployment deployment, AdapterTokenStore tokenStore) {
        return new CatalinaRequestAuthenticator(deployment, tokenStore, facade, request, createPrincipalFactory());
    }

    /**
     * Checks that access token is still valid.  Will attempt refresh of token if it is not.
     *
     * @param request
     */
    protected void checkKeycloakSession(Request request, HttpFacade facade) {
        KeycloakDeployment deployment = deploymentContext.resolveDeployment(facade);
        // 找到存储token的仓库  如果没有则新建 并且会绑定在req上
        AdapterTokenStore tokenStore = getTokenStore(request, facade, deployment);
        tokenStore.checkCurrentToken();
    }

    /**
     * 在tokenStore中会触发该方法
     * @param request
     * @throws IOException
     */
    public void keycloakSaveRequest(Request request) throws IOException {
        saveRequest(request, request.getSessionInternal(true));
    }

    /**
     *
     * @param request
     * @return
     */
    public boolean keycloakRestoreRequest(Request request) {
        try {
            return restoreRequest(request, request.getSessionInternal());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 获取存储token的仓库
     * @param request
     * @param facade
     * @param resolvedDeployment
     * @return
     */
    protected AdapterTokenStore getTokenStore(Request request, HttpFacade facade, KeycloakDeployment resolvedDeployment) {

        // 代表req中已经记录了store 直接使用
        AdapterTokenStore store = (AdapterTokenStore)request.getNote(TOKEN_STORE_NOTE);
        if (store != null) {
            return store;
        }

        // token 默认存储在session中
        if (resolvedDeployment.getTokenStore() == TokenStore.SESSION) {
            store = createSessionTokenStore(request, resolvedDeployment);
        } else {
            // TODO
            store = new CatalinaCookieTokenStore(request, facade, resolvedDeployment, createPrincipalFactory());
        }

        request.setNote(TOKEN_STORE_NOTE, store);
        return store;
    }

    /**
     * 为每个请求创建一个tokenStore
     * @param request
     * @param resolvedDeployment
     * @return
     */
    private AdapterTokenStore createSessionTokenStore(Request request, KeycloakDeployment resolvedDeployment) {
        AdapterTokenStore store;
        store = new CatalinaSessionTokenStore(request, resolvedDeployment, userSessionManagement, createPrincipalFactory(), this);
        return store;
    }

}
