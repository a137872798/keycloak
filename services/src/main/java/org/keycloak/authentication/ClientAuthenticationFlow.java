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
 * 客户端认证流
 */
public class ClientAuthenticationFlow implements AuthenticationFlow {

    private static final Logger logger = Logger.getLogger(ClientAuthenticationFlow.class);

    Response alternativeChallenge = null;
    AuthenticationProcessor processor;
    AuthenticationFlowModel flow;

    /**
     * 代表处理结果
     */
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
     * 处理整个flow
     */
    @Override
    public Response processFlow() {
        // 找到接下来要执行的execution 如果发现了一个必选项  则必须先执行
        List<AuthenticationExecutionModel> executions = findExecutionsToRun();

        for (AuthenticationExecutionModel model : executions) {

            // 转换成client认证器
            ClientAuthenticatorFactory factory = (ClientAuthenticatorFactory) processor.getSession().getKeycloakSessionFactory().getProviderFactory(ClientAuthenticator.class, model.getAuthenticator());
            if (factory == null) {
                throw new AuthenticationFlowException("Could not find ClientAuthenticatorFactory for: " + model.getAuthenticator(), AuthenticationFlowError.INTERNAL_ERROR);
            }
            ClientAuthenticator authenticator = factory.create();
            logger.debugv("client authenticator: {0}", factory.getId());

            AuthenticationProcessor.Result context = processor.createClientAuthenticatorContext(model, authenticator, executions);

            // 进行认证后 会将结果设置到context中
            authenticator.authenticateClient(context);

            // 认证成功时 会找到client 然后设置到processor上
            ClientModel client = processor.getClient();
            if (client != null) {
                String expectedClientAuthType = client.getClientAuthenticatorType();

                // Fallback to secret just in case (for backwards compatibility)
                if (expectedClientAuthType == null) {
                    expectedClientAuthType = KeycloakModelUtils.getDefaultClientAuthenticatorType();
                    ServicesLogger.LOGGER.authMethodFallback(client.getClientId(), expectedClientAuthType);
                }

                // Check if client authentication matches
                // 判断与client自身期望的认证方式是否一致  如果与期望方式不符 验证是没有意义的
                if (factory.getId().equals(expectedClientAuthType)) {

                    // 代表出现了结果期望用户优先处理 无法继续接下来的流程了
                    Response response = processResult(context);
                    if (response != null) return response;

                    if (!context.getStatus().equals(FlowStatus.SUCCESS)) {
                        throw new AuthenticationFlowException("Expected success, but for an unknown reason the status was " + context.getStatus(), AuthenticationFlowError.INTERNAL_ERROR);
                    } else {
                        success = true;
                    }

                    logger.debugv("Client {0} authenticated by {1}", client.getClientId(), factory.getId());
                    processor.getEvent().detail(Details.CLIENT_AUTH_METHOD, factory.getId());
                    return null;
                }
            }
        }

        // 如果在本轮中没有被检测出来 也是报错

        // Check if any alternative challenge was identified
        if (alternativeChallenge != null) {
            processor.getEvent().error(Errors.INVALID_CLIENT);
            return alternativeChallenge;
        }
        throw new AuthenticationFlowException("Invalid client credentials", AuthenticationFlowError.INVALID_CREDENTIALS);
    }

    /**
     * 找到接下来要执行的所有execution
     * @return
     */
    protected List<AuthenticationExecutionModel> findExecutionsToRun() {
        List<AuthenticationExecutionModel> executionsToRun = new LinkedList<>();
        List<AuthenticationExecutionModel> finalExecutionsToRun = executionsToRun;

        // 同级的flow下 如果存在必须执行项 此时先完成
        Optional<AuthenticationExecutionModel> first = processor.getRealm().getAuthenticationExecutionsStream(flow.getId())
                .filter(e -> {
                    // 一旦发现下个必须要处理的execution 就可以直接返回了
                    if (e.isRequired()) {
                        return true;
                        // 这些是作为备选方案 在到达下个必须完成的execution之前 不会有影响
                    } else if (e.isAlternative()){
                        finalExecutionsToRun.add(e);
                        return false;
                    }
                    return false;
                }).findFirst();

        // 一旦发现了必选项 就返回
        if (first.isPresent())
            executionsToRun = Arrays.asList(first.get());
        else
            // 没有必选项  就返回所有可选项
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
     * 处理result的结果
     * @param result
     * @return
     */
    protected Response processResult(AuthenticationProcessor.Result result) {
        AuthenticationExecutionModel execution = result.getExecution();

        // 描述此时处理结果状态
        FlowStatus status = result.getStatus();

        logger.debugv("client authenticator {0}: {1}", status.toString(), execution.getAuthenticator());

        // 处理成功 不需要提前返回结果
        if (status == FlowStatus.SUCCESS) {
            return null;
        }

        // 需要返回一些信息给用户 比如错误信息  或者跳转到其他页面 以便用户填充信息
        if (status == FlowStatus.FAILED) {
            if (result.getChallenge() != null) {
                return sendChallenge(result, execution);
            } else {
                throw new AuthenticationFlowException(result.getError());
            }

            // 必选项 要求必须触发challenge
        } else if (status == FlowStatus.FORCE_CHALLENGE) {
            return sendChallenge(result, execution);

            // CHALLENGE 对应的是可选项
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
