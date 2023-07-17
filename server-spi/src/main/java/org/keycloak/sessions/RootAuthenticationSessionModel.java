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

package org.keycloak.sessions;

import java.util.Map;

import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.SearchableModelField;

/**
 * Represents usually one browser session with potentially many browser tabs. Every browser tab is represented by
 * {@link AuthenticationSessionModel} of different client.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 * 可以理解为一个总会话 可以关联多个子会话
 */
public interface RootAuthenticationSessionModel {

    /**
     * 代表可作为检索条件的字段
     */
    public static class SearchableFields {
        public static final SearchableModelField<RootAuthenticationSessionModel> ID              = new SearchableModelField<>("id", String.class);
        public static final SearchableModelField<RootAuthenticationSessionModel> REALM_ID        = new SearchableModelField<>("realmId", String.class);
    }

    /**
     * Returns id of the root authentication session.
     * @return {@code String}
     */
    String getId();

    /**
     * Returns realm associated to the root authentication session.
     * @return {@code RealmModel}
     */
    RealmModel getRealm();

    /**
     * Returns timestamp when the root authentication session was created or updated.
     * @return {@code int}
     */
    int getTimestamp();

    /**
     * Sets a timestamp when the root authentication session was created or updated.
     * It also updates the expiration time for the root authentication session entity.
     * @param timestamp {@code int}
     */
    void setTimestamp(int timestamp);

    /**
     * Returns authentication sessions for the root authentication session.
     * Key is tabId, Value is AuthenticationSessionModel.
     * @return {@code Map<String, AuthenticationSessionModel>} authentication sessions or empty map if no
     * authentication sessions are present. Never return null.
     *
     * 返回关联的认证会话信息
     */
    Map<String, AuthenticationSessionModel> getAuthenticationSessions();

    /**
     * Returns an authentication session for the particular client and tab or null if it doesn't yet exists.
     * @param client {@code ClientModel} If {@code null} is provided the method will return {@code null}.
     * @param tabId {@code String} If {@code null} is provided the method will return {@code null}.
     * @return {@code AuthenticationSessionModel} or {@code null} in no authentication session is found.
     * 检索某个client的认证会话
     */
    AuthenticationSessionModel getAuthenticationSession(ClientModel client, String tabId);

    /**
     * Create a new authentication session and returns it.
     * @param client {@code ClientModel} Can't be {@code null}.
     * @return {@code AuthenticationSessionModel} non-null fresh authentication session. Never returns {@code null}.
     * 在root认证会话下 产生跟某个client挂钩的子认证会话
     */
    AuthenticationSessionModel createAuthenticationSession(ClientModel client);

    /**
     * Removes the authentication session specified by tab id from the root authentication session.
     * If there's no child authentication session left in the root authentication session, it's removed as well.
     * @param tabId {@code String} Can't be {@code null}.
     *                            移除tabId 对应的会话
     */
    void removeAuthenticationSessionByTabId(String tabId);

    /**
     * Will completely restart whole state of authentication session. It will just keep same ID. It will setup it with provided realm.
     * @param realm {@code RealmModel} Associated realm to the root authentication session.
     * 完全重启某个realm下的所有会话
     */
    void restartSession(RealmModel realm);

}
