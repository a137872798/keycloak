package org.keycloak.provider.wildfly;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.common.util.ResteasyProvider;

// 该rest服务对应wildfly服务器   简单来看是一个map
public class Resteasy3Provider implements ResteasyProvider {

    @Override
    public <R> R getContextData(Class<R> type) {
        return ResteasyProviderFactory.getInstance().getContextData(type);
    }

    @Override
    public void pushDefaultContextObject(Class type, Object instance) {
        ResteasyProviderFactory.getInstance().getContextData(Dispatcher.class).getDefaultContextObjects()
                .put(type, instance);
    }

    @Override
    public void pushContext(Class type, Object instance) {
        ResteasyProviderFactory.getInstance().pushContext(type, instance);
    }

    @Override
    public void clearContextData() {
        ResteasyProviderFactory.getInstance().clearContextData();
    }

}
