package org.keycloak.common.util;

// 代表提供rest服务能力的对象接口
public interface ResteasyProvider {

    // 获取上下文数据
    <R> R getContextData(Class<R> type);

    // 将对象存储到容器中
    void pushDefaultContextObject(Class type, Object instance);

    // 乍一看与上面的方法一样
    void pushContext(Class type, Object instance);

    // 清空容器
    void clearContextData();

}
