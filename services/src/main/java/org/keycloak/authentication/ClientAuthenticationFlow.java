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

package org.keycloak.authentication;

import org.jboss.logging.Logger;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 客户端认证流   每个execution关联一个ClientAuthenticator
 */
public class ClientAuthenticationFlow implements AuthenticationFlow {

    private static final Logger logger = Logger.getLogger(ClientAuthenticationFlow.class);

    Response alternativeChallenge = null;
    AuthenticationProcessor processor;
    AuthenticationFlowModel flow;

    private boolean success;

    public ClientAuthenticationFlow(AuthenticationProcessor processor, AuthenticationFlowModel flow) {
        this.processor = processor;
        this.flow = flow;
    }

    /**
     * 不支持指定某个execution执行
     * @param actionExecution
     * @return
     */
    @Override
    public Response processAction(String actionExecution) {
        throw new IllegalStateException("Not supposed to be invoked");
    }

    /**
     * 这里看起来也是一个个执行的  需要认证类型匹配 应该是要配合nextExecution使用
     */
    @Override
    public Response processFlow() {

        // 返回第一个必选或者所有可选
        List<AuthenticationExecutionModel> executions = findExecutionsToRun();

        for (AuthenticationExecutionModel model : executions) {
            ClientAuthenticatorFactory factory = (ClientAuthenticatorFactory) processor.getSession().getKeycloakSessionFactory().getProviderFactory(ClientAuthenticator.class, model.getAuthenticator());
            if (factory == null) {
                throw new AuthenticationFlowException("Could not find ClientAuthenticatorFactory for: " + model.getAuthenticator(), AuthenticationFlowError.INTERNAL_ERROR);
            }
            ClientAuthenticator authenticator = factory.create();
            logger.debugv("client authenticator: {0}", factory.getId());

            // 为每个认证器生成一个result对象 描述该认证器的处理结果
            AuthenticationProcessor.Result context = processor.createClientAuthenticatorContext(model, authenticator, executions);
            authenticator.authenticateClient(context);

            ClientModel client = processor.getClient();
            if (client != null) {
                // 如果认证器有期望的类型
                String expectedClientAuthType = client.getClientAuthenticatorType();

                // Fallback to secret just in case (for backwards compatibility) 使用默认类型
                // 默认类型为client-secret
                if (expectedClientAuthType == null) {
                    expectedClientAuthType = KeycloakModelUtils.getDefaultClientAuthenticatorType();
                    ServicesLogger.LOGGER.authMethodFallback(client.getClientId(), expectedClientAuthType);
                }

                // Check if client authentication matches
                // 类型不匹配的情况下 转而尝试下个
                if (factory.getId().equals(expectedClientAuthType)) {
                    // 匹配的情况下进行验证
                    Response response = processResult(context);
                    if (response != null) return response;

                    if (!context.getStatus().equals(FlowStatus.SUCCESS)) {
                        throw new AuthenticationFlowException("Expected success, but for an unknown reason the status was " + context.getStatus(), AuthenticationFlowError.INTERNAL_ERROR);
                    } else {
                        success = true;
                    }

                    logger.debugv("Client {0} authenticated by {1}", client.getClientId(), factory.getId());
                    processor.getEvent().detail(Details.CLIENT_AUTH_METHOD, factory.getId());
                    // 返回null 代表不需要提前结束认证流程 一切正常
                    return null;
                }
            }
        }

        // 都不匹配的情况下进入这里

        // Check if any alternative challenge was identified
        if (alternativeChallenge != null) {
            processor.getEvent().error(Errors.INVALID_CLIENT);
            return alternativeChallenge;
        }
        throw new AuthenticationFlowException("Invalid client credentials", AuthenticationFlowError.INVALID_CREDENTIALS);
    }

    /**
     * 返回马上要执行的认证器
     * @return
     */
    protected List<AuthenticationExecutionModel> findExecutionsToRun() {
        List<AuthenticationExecutionModel> executionsToRun = new LinkedList<>();
        List<AuthenticationExecutionModel> finalExecutionsToRun = executionsToRun;
        Optional<AuthenticationExecutionModel> first = processor.getRealm().getAuthenticationExecutionsStream(flow.getId())
                .filter(e -> {
                    if (e.isRequired()) {
                        return true;
                    } else if (e.isAlternative()){
                        finalExecutionsToRun.add(e);
                        return false;
                    }
                    return false;
                }).findFirst();

        // 返回第一个必选execution
        // 如果都不是必选,则返回所有可选的execution
        if (first.isPresent())
            executionsToRun = Arrays.asList(first.get());
        else
            executionsToRun.addAll(finalExecutionsToRun);

        if (logger.isTraceEnabled()) {
            List<String> exIds = new ArrayList<>();
            for (AuthenticationExecutionModel execution : executionsToRun) {
                exIds.add(execution.getId());
            }
            logger.tracef("Using executions for client authentication: %s", exIds.toString());
        }

        return executionsToRun;
    }

    /**
     * 执行验证逻辑
     * @param result
     * @return
     */
    protected Response processResult(AuthenticationProcessor.Result result) {
        AuthenticationExecutionModel execution = result.getExecution();
        FlowStatus status = result.getStatus();

        logger.debugv("client authenticator {0}: {1}", status.toString(), execution.getAuthenticator());

        // 直接成功了不需要处理
        if (status == FlowStatus.SUCCESS) {
            return null;
        }

        if (status == FlowStatus.FAILED) {
            // 代表使用KECP模式  在请求中会额外携带 challenge challenge_code
            if (result.getChallenge() != null) {
                // 设置错误信息 返回result.challenge
                return sendChallenge(result, execution);
            } else {
                // 非KECP失败
                throw new AuthenticationFlowException(result.getError());
            }
        } else if (status == FlowStatus.FORCE_CHALLENGE) {
            return sendChallenge(result, execution);
        } else if (status == FlowStatus.CHALLENGE) {

            // Make sure the first priority alternative challenge is used
            if (alternativeChallenge == null) {
                alternativeChallenge = result.getChallenge();
            }
            return sendChallenge(result, execution);
        } else if (status == FlowStatus.FAILURE_CHALLENGE) {
            return sendChallenge(result, execution);
        } else {
            ServicesLogger.LOGGER.unknownResultStatus();
            throw new AuthenticationFlowException(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    /**
     * KCEP失败
     * @param result
     * @param execution
     * @return
     */
    public Response sendChallenge(AuthenticationProcessor.Result result, AuthenticationExecutionModel execution) {
        logger.debugv("client authenticator: sending challenge for authentication execution {0}", execution.getAuthenticator());

        if (result.getError() != null) {
            String errorAsString = result.getError().toString().toLowerCase();
            result.getEvent().error(errorAsString);
        } else {
            if (result.getClient() == null) {
                result.getEvent().error(Errors.INVALID_CLIENT);
            } else {
                result.getEvent().error(Errors.INVALID_CLIENT_CREDENTIALS);
            }
        }

        return result.getChallenge();
    }

    @Override
    public boolean isSuccessful() {
        return success;
    }
}
