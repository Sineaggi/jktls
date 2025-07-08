package com.mayreh.jktls.sun.security.ssl;

import com.mayreh.jktls.sun.security.ssl.SSLWriteCipher.WriteCipherContextExtractor.T12Gcm;

import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.util.Optional;

import static com.mayreh.jktls.reflection.Utils.classForName;
import static com.mayreh.jktls.reflection.Utils.doReflection;
import static com.mayreh.jktls.reflection.Utils.getField;

/**
 * Mirror of `sun.security.ssl.SSLCipher$SSLWriteCipher` for exposure
 */
public class SSLWriteCipher {
    private static final Class<?> clazz = classForName("sun.security.ssl.SSLCipher$SSLWriteCipher");
    private static final Field authenticator = getField(clazz, "authenticator");

    private final Object obj;

    public SSLWriteCipher(Object obj) {
        this.obj = obj;
    }

    public Authenticator authenticator() {
        return new Authenticator(doReflection(() -> authenticator.get(obj)));
    }

    public Optional<WriteCipherContext> context() {
        for (WriteCipherType type : WriteCipherType.values()) {
            if (type.isSupported(this)) {
                return Optional.of(type.extractor.extract(this));
            }
        }
        return Optional.empty();
    }

    /**
     * Context information to configure kTLS socket's parameters
     */
    public static final class WriteCipherContext {
        private final byte[] iv;
        private final byte[] key;
        private final byte[] salt;
        private final byte[] recSeq;

        public WriteCipherContext(byte[] iv, byte[] key, byte[] salt, byte[] recSeq) {
            this.iv = iv;
            this.key = key;
            this.salt = salt;
            this.recSeq = recSeq;
        }

        public byte[] getIv() {
            return this.iv;
        }

        public byte[] getKey() {
            return this.key;
        }

        public byte[] getSalt() {
            return this.salt;
        }

        public byte[] getRecSeq() {
            return this.recSeq;
        }

        public boolean equals(final Object o) {
            if (o == this) return true;
            if (!(o instanceof WriteCipherContext)) return false;
            final WriteCipherContext other = (WriteCipherContext) o;
            if (!java.util.Arrays.equals(this.getIv(), other.getIv())) return false;
            if (!java.util.Arrays.equals(this.getKey(), other.getKey())) return false;
            if (!java.util.Arrays.equals(this.getSalt(), other.getSalt())) return false;
            if (!java.util.Arrays.equals(this.getRecSeq(), other.getRecSeq())) return false;
            return true;
        }

        public int hashCode() {
            final int PRIME = 59;
            int result = 1;
            result = result * PRIME + java.util.Arrays.hashCode(this.getIv());
            result = result * PRIME + java.util.Arrays.hashCode(this.getKey());
            result = result * PRIME + java.util.Arrays.hashCode(this.getSalt());
            result = result * PRIME + java.util.Arrays.hashCode(this.getRecSeq());
            return result;
        }

        public String toString() {
            return "SSLWriteCipher.WriteCipherContext(iv=" + java.util.Arrays.toString(this.getIv()) + ", key=" + java.util.Arrays.toString(this.getKey()) + ", salt=" + java.util.Arrays.toString(this.getSalt()) + ", recSeq=" + java.util.Arrays.toString(this.getRecSeq()) + ")";
        }
    }

    public enum WriteCipherType {
        T12_GCM(new T12Gcm()),
        ;
        final WriteCipherContextExtractor extractor;

        WriteCipherType(WriteCipherContextExtractor extractor) {
            this.extractor = extractor;
        }

        boolean isSupported(SSLWriteCipher cipher) {
            return extractor.clazz.isInstance(cipher.obj);
        }
    }

    /**
     * Extract {@link WriteCipherContext} from given cipher object
     */
    abstract static class WriteCipherContextExtractor {
        final Class<?> clazz;

        protected WriteCipherContextExtractor(Class<?> clazz) {
            this.clazz = clazz;
        }

        abstract WriteCipherContext extract(SSLWriteCipher cipher);

        static class T12Gcm extends WriteCipherContextExtractor {
            private static final Class<?> clazz =
                    classForName("sun.security.ssl.SSLCipher$T12GcmWriteCipherGenerator$GcmWriteCipher");
            private static final Field key = getField(clazz, "key");
            private static final Field fixedIv = getField(clazz, "fixedIv");

            T12Gcm() {
                super(clazz);
            }

            @Override
            WriteCipherContext extract(SSLWriteCipher cipher) {
                SecretKeySpec keySpec = (SecretKeySpec) doReflection(() -> key.get(cipher.obj));
                byte[] salt = (byte[]) doReflection(() -> fixedIv.get(cipher.obj));
                byte[] seq = cipher.authenticator().sequenceNumber();

                return new WriteCipherContext(seq, keySpec.getEncoded(), salt, seq);
            }
        }
    }
}
