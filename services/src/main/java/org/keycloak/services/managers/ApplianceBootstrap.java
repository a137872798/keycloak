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
package org.keycloak.services.managers;

import org.keycloak.Config;
import org.keycloak.common.Version;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.DefaultKeyProviders;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.ServicesLogger;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 * 应用引导
 */
public class ApplianceBootstrap {

    // 可以通过session拿到各种对象
    private final KeycloakSession session;

    public ApplianceBootstrap(KeycloakSession session) {
        this.session = session;
    }

    // 代表默认realm还没有创建
    public boolean isNewInstall() {
        // 表中已经有默认realm数据
        if (session.realms().getRealm(Config.getAdminRealm()) != null) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * 代表 master realm下还没有用户
     * @return
     */
    public boolean isNoMasterUser() {
        RealmModel realm = session.realms().getRealmByName(Config.getAdminRealm());
        return session.users().getUsersCount(realm) == 0;
    }

    // 创建master realm 并存储到持久层
    public boolean createMasterRealm() {
        if (!isNewInstall()) {
            throw new IllegalStateException("Can't create default realm as realms already exists");
        }

        // 获取default realm名
        String adminRealmName = Config.getAdminRealm();
        ServicesLogger.LOGGER.initializingAdminRealm(adminRealmName);

        RealmManager manager = new RealmManager(session);
        // 填入名字创建realm  这里会有一个冗长的创建流程
        RealmModel realm = manager.createRealm(adminRealmName, adminRealmName);

        // 设置一些默认参数
        realm.setName(adminRealmName);
        realm.setDisplayName(Version.NAME);
        realm.setDisplayNameHtml(Version.NAME_HTML);
        realm.setEnabled(true);
        realm.addRequiredCredential(CredentialRepresentation.PASSWORD);
        realm.setDefaultSignatureAlgorithm(Constants.DEFAULT_SIGNATURE_ALGORITHM);
        realm.setSsoSessionIdleTimeout(1800);
        realm.setAccessTokenLifespan(60);
        realm.setAccessTokenLifespanForImplicitFlow(Constants.DEFAULT_ACCESS_TOKEN_LIFESPAN_FOR_IMPLICIT_FLOW_TIMEOUT);
        realm.setSsoSessionMaxLifespan(36000);
        realm.setOfflineSessionIdleTimeout(Constants.DEFAULT_OFFLINE_SESSION_IDLE_TIMEOUT);
        // KEYCLOAK-7688 Offline Session Max for Offline Token
        realm.setOfflineSessionMaxLifespanEnabled(false);
        realm.setOfflineSessionMaxLifespan(Constants.DEFAULT_OFFLINE_SESSION_MAX_LIFESPAN);
        realm.setAccessCodeLifespan(60);
        realm.setAccessCodeLifespanUserAction(300);
        realm.setAccessCodeLifespanLogin(1800);
        realm.setSslRequired(SslRequired.EXTERNAL);
        realm.setRegistrationAllowed(false);
        realm.setRegistrationEmailAsUsername(false);

        // 将新建的realm 设置到本次会话中
        session.getContext().setRealm(realm);
        DefaultKeyProviders.createProviders(realm);

        return true;
    }

    /**
     * 创建realm的默认用户
     * @param username
     * @param password
     */
    public void createMasterRealmUser(String username, String password) {
        RealmModel realm = session.realms().getRealmByName(Config.getAdminRealm());
        session.getContext().setRealm(realm);

        if (session.users().getUsersCount(realm) > 0) {
            throw new IllegalStateException("Can't create initial user as users already exists");
        }

        // 创建默认用户
        UserModel adminUser = session.users().addUser(realm, username);
        adminUser.setEnabled(true);

        // 将密码作为用户凭证
        UserCredentialModel usrCredModel = UserCredentialModel.password(password);
        // 更新用户凭证信息
        session.userCredentialManager().updateCredential(realm, adminUser, usrCredModel);

        // 设置默认角色 会触发db的写入操作
        RoleModel adminRole = realm.getRole(AdminRoles.ADMIN);
        adminUser.grantRole(adminRole);
    }

}
