package com.mayreh.jktls.sun.nio.ch;

import java.io.FileDescriptor;
import java.lang.reflect.Method;

import static com.mayreh.jktls.reflection.Utils.classForName;
import static com.mayreh.jktls.reflection.Utils.doReflection;
import static com.mayreh.jktls.reflection.Utils.getMethod;

/**
 * Mirror of `sun.nio.ch.SocketChannelImpl` for exposure
 */
public class SocketChannelImpl {
    private static final Class<?> clazz = classForName("sun.nio.ch.SocketChannelImpl");
    private static final Method getFD = getMethod(clazz, "getFD");

    private final Object obj;

    public SocketChannelImpl(Object obj) {
        this.obj = obj;
    }

    public FileDescriptor getFD() {
        return (FileDescriptor) doReflection(() -> getFD.invoke(obj));
    }

    public static boolean isInstance(Object obj) {
        return clazz.isInstance(obj);
    }
}
