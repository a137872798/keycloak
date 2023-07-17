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

package org.keycloak.models.utils;

import org.keycloak.models.RealmModel;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class RealmInfoUtil {

    /**
     * 获取 realm 层面的会话存活时间
     * @param realm
     * @return
     */
    public static int getDettachedClientSessionLifespan(RealmModel realm) {

        // 取下面3个中最长的
        int lifespan = realm.getAccessCodeLifespanLogin();
        if (realm.getAccessCodeLifespanUserAction() > lifespan) {
            lifespan = realm.getAccessCodeLifespanUserAction();
        }
        if (realm.getAccessCodeLifespan() > lifespan) {
            lifespan = realm.getAccessCodeLifespan();
        }
        return lifespan;
    }

}
