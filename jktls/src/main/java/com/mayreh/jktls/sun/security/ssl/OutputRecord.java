package com.mayreh.jktls.sun.security.ssl;

import java.lang.reflect.Field;

import static com.mayreh.jktls.reflection.Utils.classForName;
import static com.mayreh.jktls.reflection.Utils.doReflection;
import static com.mayreh.jktls.reflection.Utils.getField;

/**
 * Mirror of `sun.security.ssl.OutputRecord` for exposure
 */
public class OutputRecord {
    private static final Class<?> clazz = classForName("sun.security.ssl.OutputRecord");
    private static final Field writeCipher = getField(clazz, "writeCipher");

    private final Object obj;

    public OutputRecord(Object obj) {
        this.obj = obj;
    }

    public SSLWriteCipher writeCipher() {
        return new SSLWriteCipher(doReflection(() -> writeCipher.get(obj)));
    }
}
