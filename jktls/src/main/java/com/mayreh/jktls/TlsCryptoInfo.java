package com.mayreh.jktls;

import com.mayreh.jktls.sun.security.ssl.SSLEngineImpl;
import com.mayreh.jktls.sun.security.ssl.SSLWriteCipher;

import javax.net.ssl.SSLEngine;

public final class TlsCryptoInfo {
    private final String protocol;
    private final String cipherSuite;
    private final byte[] iv;
    private final byte[] key;
    private final byte[] salt;
    private final byte[] recSeq;

    public TlsCryptoInfo(String protocol, String cipherSuite, byte[] iv, byte[] key, byte[] salt, byte[] recSeq) {
        this.protocol = protocol;
        this.cipherSuite = cipherSuite;
        this.iv = iv;
        this.key = key;
        this.salt = salt;
        this.recSeq = recSeq;
    }

    public static TlsCryptoInfo from(SSLEngine engine) {
        if (!SSLEngineImpl.isInstance(engine)) {
            throw new UnsupportedOperationException("Unsupported SSLEngine implementation");
        }
        SSLWriteCipher writeCipher = new SSLEngineImpl(engine)
                .conContext()
                .outputRecord()
                .writeCipher();
        return writeCipher.context()
                          .map(ctx -> new TlsCryptoInfo(
                                  engine.getSession().getProtocol(),
                                  engine.getSession().getCipherSuite(),
                                  ctx.getIv(),
                                  ctx.getKey(),
                                  ctx.getSalt(),
                                  ctx.getRecSeq()))
                          .orElseThrow(() -> new UnsupportedOperationException(
                                  String.format("Unsupported protocol or cipher suite: protocol=%s, suite=%s",
                                                engine.getSession().getProtocol(),
                                                engine.getSession().getCipherSuite())));
    }

    public String protocol() {
        return this.protocol;
    }

    public String cipherSuite() {
        return this.cipherSuite;
    }

    public byte[] iv() {
        return this.iv;
    }

    public byte[] key() {
        return this.key;
    }

    public byte[] salt() {
        return this.salt;
    }

    public byte[] recSeq() {
        return this.recSeq;
    }

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof TlsCryptoInfo)) return false;
        final TlsCryptoInfo other = (TlsCryptoInfo) o;
        final Object this$protocol = this.protocol();
        final Object other$protocol = other.protocol();
        if (this$protocol == null ? other$protocol != null : !this$protocol.equals(other$protocol)) return false;
        final Object this$cipherSuite = this.cipherSuite();
        final Object other$cipherSuite = other.cipherSuite();
        if (this$cipherSuite == null ? other$cipherSuite != null : !this$cipherSuite.equals(other$cipherSuite))
            return false;
        if (!java.util.Arrays.equals(this.iv(), other.iv())) return false;
        if (!java.util.Arrays.equals(this.key(), other.key())) return false;
        if (!java.util.Arrays.equals(this.salt(), other.salt())) return false;
        if (!java.util.Arrays.equals(this.recSeq(), other.recSeq())) return false;
        return true;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $protocol = this.protocol();
        result = result * PRIME + ($protocol == null ? 43 : $protocol.hashCode());
        final Object $cipherSuite = this.cipherSuite();
        result = result * PRIME + ($cipherSuite == null ? 43 : $cipherSuite.hashCode());
        result = result * PRIME + java.util.Arrays.hashCode(this.iv());
        result = result * PRIME + java.util.Arrays.hashCode(this.key());
        result = result * PRIME + java.util.Arrays.hashCode(this.salt());
        result = result * PRIME + java.util.Arrays.hashCode(this.recSeq());
        return result;
    }

    public String toString() {
        return "TlsCryptoInfo(protocol=" + this.protocol() + ", cipherSuite=" + this.cipherSuite() + ", iv=" + java.util.Arrays.toString(this.iv()) + ", key=" + java.util.Arrays.toString(this.key()) + ", salt=" + java.util.Arrays.toString(this.salt()) + ", recSeq=" + java.util.Arrays.toString(this.recSeq()) + ")";
    }
}
