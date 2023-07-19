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
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.Constants;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 默认的认证流对象
 */
public class DefaultAuthenticationFlow implements AuthenticationFlow {
    private static final Logger logger = Logger.getLogger(DefaultAuthenticationFlow.class);
    private final List<AuthenticationExecutionModel> executions;
    private final AuthenticationProcessor processor;
    private final AuthenticationFlowModel flow;
    private boolean successful;

    /**
     * 存储可能出现的所有错误
     */
    private List<AuthenticationFlowException> afeList = new ArrayList<>();

    public DefaultAuthenticationFlow(AuthenticationProcessor processor, AuthenticationFlowModel flow) {
        this.processor = processor;
        this.flow = flow;
        // 获取flow关联的多个认证动作
        this.executions = processor.getRealm().getAuthenticationExecutionsStream(flow.getId()).collect(Collectors.toList());
    }

    protected boolean isProcessed(AuthenticationExecutionModel model) {
        return isProcessed(processor, model);
    }

    /**
     * 判断是否已经处理完所有认证行为
     * @param processor
     * @param model
     * @return
     */
    protected static boolean isProcessed(AuthenticationProcessor processor, AuthenticationExecutionModel model) {
        if (model.isDisabled()) return true;

        // 获取该execution此时的状态
        AuthenticationSessionModel.ExecutionStatus status = processor.getAuthenticationSession().getExecutionStatus().get(model.getId());
        // 代表还未为该过程设置状态 也就是还未执行
        if (status == null) return false;
        return status == AuthenticationSessionModel.ExecutionStatus.SUCCESS || status == AuthenticationSessionModel.ExecutionStatus.SKIPPED
                || status == AuthenticationSessionModel.ExecutionStatus.ATTEMPTED
                || status == AuthenticationSessionModel.ExecutionStatus.SETUP_REQUIRED;
    }

    /**
     * 创建认证器
     * @param factory
     * @return
     */
    protected Authenticator createAuthenticator(AuthenticatorFactory factory) {
        String display = processor.getAuthenticationSession().getAuthNote(OAuth2Constants.DISPLAY);
        if (display == null) return factory.create(processor.getSession());

        if (factory instanceof DisplayTypeAuthenticatorFactory) {
            Authenticator authenticator = ((DisplayTypeAuthenticatorFactory) factory).createDisplay(processor.getSession(), display);
            if (authenticator != null) return authenticator;
        }
        // todo create a provider for handling lack of display support
        if (OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(display)) {
            processor.getAuthenticationSession().removeAuthNote(OAuth2Constants.DISPLAY);
            throw new AuthenticationFlowException(AuthenticationFlowError.DISPLAY_NOT_SUPPORTED,
                    ConsoleDisplayMode.browserContinue(processor.getSession(), processor.getRefreshUrl(true).toString()));
        } else {
            return factory.create(processor.getSession());
        }
    }

    /**
     * action是处理用户提交的表单数据
     * @param actionExecution
     * @return
     */
    @Override
    public Response processAction(String actionExecution) {
        logger.debugv("processAction: {0}", actionExecution);

        if (actionExecution == null || actionExecution.isEmpty()) {
            throw new AuthenticationFlowException("action is not in current execution", AuthenticationFlowError.INTERNAL_ERROR);
        }
        // 先查找本次对应的execution
        AuthenticationExecutionModel model = processor.getRealm().getAuthenticationExecutionById(actionExecution);
        if (model == null) {
            throw new AuthenticationFlowException("Execution not found", AuthenticationFlowError.INTERNAL_ERROR);
        }

        if (HttpMethod.POST.equals(processor.getRequest().getHttpMethod())) {
            MultivaluedMap<String, String> inputData = processor.getRequest().getDecodedFormParameters();
            // 从请求参数中获取executionId
            String authExecId = inputData.getFirst(Constants.AUTHENTICATION_EXECUTION);

            // User clicked on "try another way" link
            // TODO
            if (inputData.containsKey("tryAnotherWay")) {
                logger.trace("User clicked on link 'Try Another Way'");

                List<AuthenticationSelectionOption> selectionOptions = createAuthenticationSelectionList(model);

                AuthenticationProcessor.Result result = processor.createAuthenticatorContext(model, null, null);
                result.setAuthenticationSelections(selectionOptions);
                return result.form().createSelectAuthenticator();
            }

            // check if the user has switched to a new authentication execution, and if so switch to it.
            // 代表用户的请求中指向了其他的execution  要进行切换
            if (authExecId != null && !authExecId.isEmpty()) {

                // 简单理解就是产生了一组认证对象
                List<AuthenticationSelectionOption> selectionOptions = createAuthenticationSelectionList(model);

                // Check if switch to the requested authentication execution is allowed
                // 检查本次req中的认证器是否存在
                selectionOptions.stream()
                        .filter(authSelectionOption -> authExecId.equals(authSelectionOption.getAuthExecId()))
                        .findFirst()
                        .orElseThrow(() -> new AuthenticationFlowException("Requested authentication execution is not allowed",
                                AuthenticationFlowError.INTERNAL_ERROR)
                        );

                // 获取该execution
                model = processor.getRealm().getAuthenticationExecutionById(authExecId);

                // 执行请求的认证器
                Response response = processSingleFlowExecutionModel(model, false);
                if (response == null) {
                    // 继续执行其他的
                    return continueAuthenticationAfterSuccessfulAction(model);
                } else
                    // 需要提前与用户交互
                    return response;
            }
        }

        //handle case where execution is a flow - This can happen during user registration for example
        // 该execution是一个flow
        if (model.isAuthenticatorFlow()) {
            logger.debug("execution is flow");
            AuthenticationFlow authenticationFlow = processor.createFlowExecution(model.getFlowId(), model);
            Response flowChallenge = authenticationFlow.processAction(actionExecution);
            if (flowChallenge == null) {
                checkAndValidateParentFlow(model);
                // 继续执行整个flow
                return processFlow();
            } else {
                // 需要提前返回
                processor.getAuthenticationSession().setExecutionStatus(model.getId(), AuthenticationSessionModel.ExecutionStatus.CHALLENGED);
                return flowChallenge;
            }
        }

        //handle normal execution case
        AuthenticatorFactory factory = getAuthenticatorFactory(model);
        Authenticator authenticator = createAuthenticator(factory);
        AuthenticationProcessor.Result result = processor.createAuthenticatorContext(model, authenticator, executions);
        result.setAuthenticationSelections(createAuthenticationSelectionList(model));

        logger.debugv("action: {0}", model.getAuthenticator());
        authenticator.action(result);
        Response response = processResult(result, true);
        if (response == null) {
            return continueAuthenticationAfterSuccessfulAction(model);
        } else return response;
    }


    /**
     * Called after "actionExecutionModel" execution is finished (Either successful or attempted). Find the next appropriate authentication
     * flow where the authentication should continue and continue with authentication process.
     *
     * @param actionExecutionModel
     * @return Response if some more forms should be displayed during authentication. Null otherwise.
     * 当某个action成功后 继续认证
     */
    private Response continueAuthenticationAfterSuccessfulAction(AuthenticationExecutionModel actionExecutionModel) {

        // 之前在执行认证器时 如果需要先重定向到别的页面 比如让用户填充信息时  需要先记录执行到哪了  以便回来后继续流程
        processor.getAuthenticationSession().removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);

        // 检查父流是否都执行完了
        String firstUnfinishedParentFlowId = checkAndValidateParentFlow(actionExecutionModel);
        AuthenticationExecutionModel parentFlowExecution = processor.getRealm().getAuthenticationExecutionByFlowId(firstUnfinishedParentFlowId);

        // 代表顶层未执行完 继续执行
        if (parentFlowExecution == null) {
            // This means that 1st unfinished ancestor flow is the top flow. We can just process it from the start
            return processFlow();
        } else {
            // 执行父流
            Response response = processSingleFlowExecutionModel(parentFlowExecution, false);
            if (response == null) {
                processor.getAuthenticationSession().removeAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION);
                return processFlow();
            } else {
                return response;
            }
        }
    }


    /**
     * This method makes sure that the parent flow's corresponding execution is considered successful if its contained
     * executions are successful.
     * The purpose is for when an execution is validated through an action, to make sure its parent flow can be successful
     * when re-evaluation the flow tree. If the flow is successful, we will recursively check it's parent flow as well
     *
     * @param model An execution model.
     * @return flowId of the 1st ancestor flow, which is not yet successfully finished and may require some further processing
     *
     * 相当于是在检查父流已经执行成功了  如果不成功 返回父流的flowId
     */
    private String checkAndValidateParentFlow(AuthenticationExecutionModel model) {
        while (true) {
            // 找到父流
            AuthenticationExecutionModel parentFlowExecutionModel = processor.getRealm().getAuthenticationExecutionByFlowId(model.getParentFlow());

            if (parentFlowExecutionModel != null) {
                List<AuthenticationExecutionModel> requiredExecutions = new LinkedList<>();
                List<AuthenticationExecutionModel> alternativeExecutions = new LinkedList<>();
                fillListsOfExecutions(processor.getRealm().getAuthenticationExecutionsStream(model.getParentFlow()),
                        requiredExecutions, alternativeExecutions);

                // Note: If we evaluate alternative execution, we will also doublecheck that there are not required elements in same subflow
                // 条件中的成立 都算成功
                if ((model.isRequired() && requiredExecutions.stream().allMatch(processor::isSuccessful)) ||
                        (model.isAlternative() && alternativeExecutions.stream().anyMatch(processor::isSuccessful) && requiredExecutions.isEmpty())) {
                    logger.debugf("Flow '%s' successfully finished after children executions success", logExecutionAlias(parentFlowExecutionModel));
                    processor.getAuthenticationSession().setExecutionStatus(parentFlowExecutionModel.getId(), AuthenticationSessionModel.ExecutionStatus.SUCCESS);

                    // Flow is successfully finished. Recursively check whether it's parent flow is now successful as well
                    model = parentFlowExecutionModel;
                } else {
                    return model.getParentFlow();
                }
            } else {
                return model.getParentFlow();
            }
        }
    }

    /**
     * 执行认证流  如果执行过程中遇到需要跟用户交互的情况 需要先返回
     * @return
     */
    @Override
    public Response processFlow() {
        logger.debugf("processFlow: %s", flow.getAlias());

        //separate flow elements into required and alternative elements
        List<AuthenticationExecutionModel> requiredList = new ArrayList<>();
        List<AuthenticationExecutionModel> alternativeList = new ArrayList<>();

        // 将execution分组 如果出现必选的  那么可选的就不需要了
        fillListsOfExecutions(executions.stream(), requiredList, alternativeList);

        //handle required elements : all required elements need to be executed
        boolean requiredElementsSuccessful = true;
        Iterator<AuthenticationExecutionModel> requiredIListIterator = requiredList.listIterator();

        // 先处理必选的
        while (requiredIListIterator.hasNext()) {
            AuthenticationExecutionModel required = requiredIListIterator.next();
            //Conditional flows must be considered disabled (non-existent) if their condition evaluates to false.
            // 是条件类型 且不满足的 就没有执行的意义了
            if (required.isConditional() && isConditionalSubflowDisabled(required)) {
                requiredIListIterator.remove();
                continue;
            }

            // 执行某个认证器 并产生了结果
            Response response = processSingleFlowExecutionModel(required, true);

            // 处理成功 或者需要装配 (需要装配的就会被跳过)
            requiredElementsSuccessful &= processor.isSuccessful(required) || isSetupRequired(required);

            // 认证器需要将错误信息返回 或者需要返回表单让用户补充信息
            if (response != null) {
                return response;
            }

            // 如果顺利的话 会执行所有required认证器

            // Some required elements were not successful and did not return response.
            // We can break as we know that the whole subflow would be considered unsuccessful as well
            if (!requiredElementsSuccessful) {
                break;
            }
        }

        //Evaluate alternative elements only if there are no required elements. This may also occur if there was only condition elements
        // 对应的是只有备选的情况
        if (requiredList.isEmpty()) {
            //check if an alternative is already successful, in case we are returning in the flow after an action
            // 任意一个满足条件就是成功
            if (alternativeList.stream().anyMatch(alternative -> processor.isSuccessful(alternative) || isSetupRequired(alternative))) {
                successful = true;
                return null;
            }

            //handle alternative elements: the first alternative element to be satisfied is enough
            for (AuthenticationExecutionModel alternative : alternativeList) {
                try {
                    // 即使是备选的 一旦产生了response 就需要返回 因为可能是需要用户补充信息
                    Response response = processSingleFlowExecutionModel(alternative, true);
                    if (response != null) {
                        return response;
                    }
                    if (processor.isSuccessful(alternative) || isSetupRequired(alternative)) {
                        successful = true;
                        return null;
                    }
                } catch (AuthenticationFlowException afe) {
                    //consuming the error is not good here from an administrative point of view, but the user, since he has alternatives, should be able to go to another alternative and continue
                    afeList.add(afe);
                    processor.getAuthenticationSession().setExecutionStatus(alternative.getId(), AuthenticationSessionModel.ExecutionStatus.ATTEMPTED);
                }
            }
        } else {

            // 设置结果
            successful = requiredElementsSuccessful;
        }
        return null;
    }


    /**
     * Just iterates over executionsToProcess and fill "requiredList" and "alternativeList" according to it
     * 根据execution的类型 分发到不同list
     */
    void fillListsOfExecutions(Stream<AuthenticationExecutionModel> executionsToProcess, List<AuthenticationExecutionModel> requiredList, List<AuthenticationExecutionModel> alternativeList) {
        executionsToProcess
                .filter(((Predicate<AuthenticationExecutionModel>) this::isConditionalAuthenticator).negate())
                .forEachOrdered(execution -> {
                    // 分组进入不同list
                    if (execution.isRequired() || execution.isConditional()) {
                        requiredList.add(execution);
                    } else if (execution.isAlternative()) {
                        alternativeList.add(execution);
                    }
                });

        // 两种都存在
        if (!requiredList.isEmpty() && !alternativeList.isEmpty()) {
            // 把可选的清理掉了
            List<String> alternativeIds = alternativeList.stream()
                    .map(AuthenticationExecutionModel::getAuthenticator)
                    .collect(Collectors.toList());

            logger.warnf("REQUIRED and ALTERNATIVE elements at same level! Those alternative executions will be ignored: %s", alternativeIds);
            alternativeList.clear();
        }
    }


    /**
     * Checks if the conditional subflow passed in parameter is disabled.
     * @param model
     * @return
     */
    boolean isConditionalSubflowDisabled(AuthenticationExecutionModel model) {
        // 首先要求入参是一个子流 其次要求子流中所有条件认证器都满足条件
        if (model == null || !model.isAuthenticatorFlow() || !model.isConditional()) {
            return false;
        };
        List<AuthenticationExecutionModel> modelList = processor.getRealm()
                .getAuthenticationExecutionsStream(model.getFlowId()).collect(Collectors.toList());
        List<AuthenticationExecutionModel> conditionalAuthenticatorList = modelList.stream()
                .filter(this::isConditionalAuthenticator)
                .filter(s -> s.isEnabled())
                .collect(Collectors.toList());
        // 只要有一个不匹配就不行
        return conditionalAuthenticatorList.isEmpty() || conditionalAuthenticatorList.stream()
                .anyMatch(m -> conditionalNotMatched(m, modelList));
    }

    private boolean isConditionalAuthenticator(AuthenticationExecutionModel model) {
        return !model.isAuthenticatorFlow() && model.getAuthenticator() != null && createAuthenticator(getAuthenticatorFactory(model)) instanceof ConditionalAuthenticator;
    }

    private AuthenticatorFactory getAuthenticatorFactory(AuthenticationExecutionModel model) {
        AuthenticatorFactory factory = (AuthenticatorFactory) processor.getSession().getKeycloakSessionFactory().getProviderFactory(Authenticator.class, model.getAuthenticator());
        if (factory == null) {
            throw new RuntimeException("Unable to find factory for AuthenticatorFactory: " + model.getAuthenticator() + " did you forget to declare it in a META-INF/services file?");
        }
        return factory;
    }

    /**
     * 判断条件是否匹配
     * @param model   条件处理器
     * @param executionList  本次包含条件处理器的集合
     * @return
     */
    private boolean conditionalNotMatched(AuthenticationExecutionModel model, List<AuthenticationExecutionModel> executionList) {
        AuthenticatorFactory factory = getAuthenticatorFactory(model);

        // 针对条件认证器
        ConditionalAuthenticator authenticator = (ConditionalAuthenticator) createAuthenticator(factory);
        AuthenticationProcessor.Result context = processor.createAuthenticatorContext(model, authenticator, executionList);

       boolean matchCondition;

        // Retrieve previous evaluation result if any, else evaluate and store result for future re-evaluation
        // 之前已经被设置成EVALUATED_TRUE 就是匹配成功
        if (processor.isEvaluatedTrue(model)) {
            matchCondition = true;
        } else if (processor.isEvaluatedFalse(model)) {
            matchCondition = false;
        } else {
            // 存储匹配结果
            matchCondition = authenticator.matchCondition(context);
            processor.getAuthenticationSession().setExecutionStatus(model.getId(),
                    matchCondition ? AuthenticationSessionModel.ExecutionStatus.EVALUATED_TRUE : AuthenticationSessionModel.ExecutionStatus.EVALUATED_FALSE);
        }

        return !matchCondition;
    }

    private boolean isSetupRequired(AuthenticationExecutionModel model) {
        return AuthenticationSessionModel.ExecutionStatus.SETUP_REQUIRED.equals(processor.getAuthenticationSession().getExecutionStatus().get(model.getId()));
    }


    /**
     * 执行某个execution
     * @param model
     * @param calledFromFlow
     * @return
     */
    private Response processSingleFlowExecutionModel(AuthenticationExecutionModel model, boolean calledFromFlow) {
        logger.debugf("check execution: '%s', requirement: '%s'", logExecutionAlias(model), model.getRequirement());

        // 已经执行过了
        if (isProcessed(model)) {
            logger.debugf("execution '%s' is processed", logExecutionAlias(model));
            return null;
        }
        //handle case where execution is a flow
        if (model.isAuthenticatorFlow()) {
            AuthenticationFlow authenticationFlow = processor.createFlowExecution(model.getFlowId(), model);

            // 处理认证流程 每个execution可能展开又是一个flow
            Response flowChallenge = authenticationFlow.processFlow();

            // 记录执行结果
            if (flowChallenge == null) {
                if (authenticationFlow.isSuccessful()) {
                    logger.debugf("Flow '%s' successfully finished", logExecutionAlias(model));
                    processor.getAuthenticationSession().setExecutionStatus(model.getId(), AuthenticationSessionModel.ExecutionStatus.SUCCESS);
                } else {
                    logger.debugf("Flow '%s' failed", logExecutionAlias(model));
                    processor.getAuthenticationSession().setExecutionStatus(model.getId(), AuthenticationSessionModel.ExecutionStatus.FAILED);
                }
                return null;
            } else {
                processor.getAuthenticationSession().setExecutionStatus(model.getId(), AuthenticationSessionModel.ExecutionStatus.CHALLENGED);
                return flowChallenge;
            }
        }

        // 正常情况 仅执行这个execution

        //handle normal execution case
        AuthenticatorFactory factory = getAuthenticatorFactory(model);
        Authenticator authenticator = createAuthenticator(factory);
        logger.debugv("authenticator: {0}", factory.getId());
        UserModel authUser = processor.getAuthenticationSession().getAuthenticatedUser();

        //If executions are alternative, get the actual execution to show based on user preference
        // 衍生出一组认证器
        List<AuthenticationSelectionOption> selectionOptions = createAuthenticationSelectionList(model);
        if (!selectionOptions.isEmpty() && calledFromFlow) {

            // 发现没有满足条件的认证器 不需要处理了
            List<AuthenticationSelectionOption> finalSelectionOptions = selectionOptions.stream().filter(aso -> !aso.getAuthenticationExecution().isAuthenticatorFlow() && !isProcessed(aso.getAuthenticationExecution())).collect(Collectors.toList());
            if (finalSelectionOptions.isEmpty()) {
                //move to next
                return null;
            }

            // 这里更换了认证器
            model = finalSelectionOptions.get(0).getAuthenticationExecution();
            factory = (AuthenticatorFactory) processor.getSession().getKeycloakSessionFactory().getProviderFactory(Authenticator.class, model.getAuthenticator());
            if (factory == null) {
                throw new RuntimeException("Unable to find factory for AuthenticatorFactory: " + model.getAuthenticator() + " did you forget to declare it in a META-INF/services file?");
            }
            authenticator = createAuthenticator(factory);
        }
        AuthenticationProcessor.Result context = processor.createAuthenticatorContext(model, authenticator, executions);
        context.setAuthenticationSelections(selectionOptions);

        // 代表该认证器需要会话先绑定用户
        if (authenticator.requiresUser()) {
            if (authUser == null) {
                throw new AuthenticationFlowException("authenticator: " + factory.getId(), AuthenticationFlowError.UNKNOWN_USER);
            }
            // 配置失败
            if (!authenticator.configuredFor(processor.getSession(), processor.getRealm(), authUser)) {
                if (factory.isUserSetupAllowed() && model.isRequired() && authenticator.areRequiredActionsEnabled(processor.getSession(), processor.getRealm())) {
                    //This means that having even though the user didn't validate the
                    logger.debugv("authenticator SETUP_REQUIRED: {0}", factory.getId());
                    processor.getAuthenticationSession().setExecutionStatus(model.getId(), AuthenticationSessionModel.ExecutionStatus.SETUP_REQUIRED);
                    authenticator.setRequiredActions(processor.getSession(), processor.getRealm(), processor.getAuthenticationSession().getAuthenticatedUser());
                    return null;
                } else {
                    throw new AuthenticationFlowException("authenticator: " + factory.getId(), AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED);
                }
            }
        }
        logger.debugv("invoke authenticator.authenticate: {0}", factory.getId());

        // 进行认证 并将结果存在context中
        authenticator.authenticate(context);

        return processResult(context, false);
    }

    // Used for debugging purpose only. Log alias of authenticator (for non-flow executions) or alias of authenticationFlow (for flow executions)
    private String logExecutionAlias(AuthenticationExecutionModel executionModel) {
        if (executionModel.isAuthenticatorFlow()) {
            // Resolve authenticationFlow model in case of debug logging. Otherwise don't lookup flowModel just because of logging and return only flowId
            if (logger.isDebugEnabled()) {
                AuthenticationFlowModel flowModel = processor.getRealm().getAuthenticationFlowById(executionModel.getFlowId());
                if (flowModel != null) {
                    return flowModel.getAlias() + " flow";
                }
            }
            return executionModel.getFlowId() + " flow";
        } else {
            return executionModel.getAuthenticator();
        }
    }

    /**
     * This method creates the list of authenticators that is presented to the user. For a required execution, this is
     * only the credentials associated to the authenticator, and for an alternative execution, this is all other alternative
     * executions in the flow, including the credentials.
     * <p>
     * In both cases, the credentials take precedence, with the order selected by the user (or his administrator).
     *
     * @param model The current execution model
     * @return an ordered list of the authentication selection options to present the user.
     * 根据一个执行器信息产生了一组执行器
     */
    private List<AuthenticationSelectionOption> createAuthenticationSelectionList(AuthenticationExecutionModel model) {
        return AuthenticationSelectionResolver.createAuthenticationSelectionList(processor, model);
    }


    /**
     * 处理结果
     * @param result
     * @param isAction
     * @return
     */
    public Response processResult(AuthenticationProcessor.Result result, boolean isAction) {
        AuthenticationExecutionModel execution = result.getExecution();
        FlowStatus status = result.getStatus();
        switch (status) {
            case SUCCESS:
                logger.debugv("authenticator SUCCESS: {0}", execution.getAuthenticator());
                // 将该认证器的结果设置到会话上下文中
                processor.getAuthenticationSession().setExecutionStatus(execution.getId(), AuthenticationSessionModel.ExecutionStatus.SUCCESS);
                return null;
            case FAILED:
                logger.debugv("authenticator FAILED: {0}", execution.getAuthenticator());
                processor.logFailure();
                processor.getAuthenticationSession().setExecutionStatus(execution.getId(), AuthenticationSessionModel.ExecutionStatus.FAILED);
                if (result.getChallenge() != null) {
                    return sendChallenge(result, execution);
                }
                throw new AuthenticationFlowException(result.getError());
                // 外面会捕获该异常 并进行新一轮的认证
            case FORK:
                logger.debugv("reset browser login from authenticator: {0}", execution.getAuthenticator());
                processor.getAuthenticationSession().setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, execution.getId());
                throw new ForkFlowException(result.getSuccessMessage(), result.getErrorMessage());
            case FORCE_CHALLENGE:
            case CHALLENGE:
                processor.getAuthenticationSession().setExecutionStatus(execution.getId(), AuthenticationSessionModel.ExecutionStatus.CHALLENGED);
                return sendChallenge(result, execution);
            case FAILURE_CHALLENGE:
                logger.debugv("authenticator FAILURE_CHALLENGE: {0}", execution.getAuthenticator());
                processor.logFailure();
                processor.getAuthenticationSession().setExecutionStatus(execution.getId(), AuthenticationSessionModel.ExecutionStatus.CHALLENGED);
                return sendChallenge(result, execution);
                // 代表触发了该认证器 但是无法生效  也无法提供challenge
            case ATTEMPTED:
                logger.debugv("authenticator ATTEMPTED: {0}", execution.getAuthenticator());
                processor.getAuthenticationSession().setExecutionStatus(execution.getId(), AuthenticationSessionModel.ExecutionStatus.ATTEMPTED);
                return null;
            case FLOW_RESET:
                processor.resetFlow();
                // 重新进行认证
                return processor.authenticate();
            default:
                logger.debugv("authenticator INTERNAL_ERROR: {0}", execution.getAuthenticator());
                ServicesLogger.LOGGER.unknownResultStatus();
                throw new AuthenticationFlowException(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    public Response sendChallenge(AuthenticationProcessor.Result result, AuthenticationExecutionModel execution) {
        // 标记在处理哪个execution时  产生了challenge  需要用户先补充信息 才能继续流程
        processor.getAuthenticationSession().setAuthNote(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION, execution.getId());
        return result.getChallenge();
    }

    @Override
    public boolean isSuccessful() {
        return successful;
    }

    @Override
    public List<AuthenticationFlowException> getFlowExceptions(){
        return afeList;
    }
}
