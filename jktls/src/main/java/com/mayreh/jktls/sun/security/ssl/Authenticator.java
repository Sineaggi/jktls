package com.mayreh.jktls.sun.security.ssl;

import static com.mayreh.jktls.reflection.Utils.classForName;
import static com.mayreh.jktls.reflection.Utils.doReflection;
import static com.mayreh.jktls.reflection.Utils.getMethod;

import java.lang.reflect.Method;

/**
 * Mirror of `sun.security.ssl.Authenticator` for exposure
 */
public class Authenticator {
    private static final Class<?> clazz = classForName("sun.security.ssl.Authenticator");
    private static final Method sequenceNumber = getMethod(clazz, "sequenceNumber");

    private final Object obj;

    public Authenticator(Object obj) {
        this.obj = obj;
    }

    public byte[] sequenceNumber() {
        return doReflection(() -> (byte[]) sequenceNumber.invoke(obj));
    }
}
