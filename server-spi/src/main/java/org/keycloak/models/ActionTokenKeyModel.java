/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.models;

import org.keycloak.common.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * 通过这些字段可以确定唯一的token  也就是作为token的key
 * @author hmlnarik
 */
public interface ActionTokenKeyModel {

    /**
     * @return ID of user which this token is for.
     */
    String getUserId();

    /**
     * @return Action identifier this token is for.
     */
    String getActionId();

    /**
     * Returns absolute number of seconds since the epoch in UTC timezone when the token expires.
     * 可以获取token的过期时间
     */
    int getExpiration();

    /**
     * @return Single-use random value used for verification whether the relevant action is allowed.
     * 一串随机数字
     */
    UUID getActionVerificationNonce();

    default String serializeKey() {
        String userId = getUserId();
        String encodedUserId = userId == null ? "" : Base64.encodeBytes(userId.getBytes(StandardCharsets.UTF_8));
        return String.format("%s.%d.%s.%s", encodedUserId, getExpiration(), getActionVerificationNonce(), getActionId());
    }
}
