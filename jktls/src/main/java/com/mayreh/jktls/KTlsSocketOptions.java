package com.mayreh.jktls;

import java.net.SocketOption;

/**
 * Defines the socket options to enable kernel TLS.
 */
public final class KTlsSocketOptions {
    private KTlsSocketOptions() {}

    /**
     * Configure upper layer protocol for the socket.
     */
    public static final SocketOption<String> TCP_ULP =
            new SockOption<>("TCP_ULP", String.class);

    /**
     * Enable encryption of application data sent over this socket.
     */
    public static final SocketOption<TlsCryptoInfo> TLS_TX =
            new SockOption<>("TLS_TX", TlsCryptoInfo.class);

    private static final class SockOption<T> implements SocketOption<T> {
        private final String name;
        private final Class<T> type;

        public SockOption(String name, Class<T> type) {
            this.name = name;
            this.type = type;
        }

        public String name() {
            return this.name;
        }

        public Class<T> type() {
            return this.type;
        }

        public boolean equals(final Object o) {
            if (o == this) return true;
            if (!(o instanceof SockOption)) return false;
            final SockOption<?> other = (SockOption<?>) o;
            final Object this$name = this.name();
            final Object other$name = other.name();
            if (this$name == null ? other$name != null : !this$name.equals(other$name)) return false;
            final Object this$type = this.type();
            final Object other$type = other.type();
            if (this$type == null ? other$type != null : !this$type.equals(other$type)) return false;
            return true;
        }

        public int hashCode() {
            final int PRIME = 59;
            int result = 1;
            final Object $name = this.name();
            result = result * PRIME + ($name == null ? 43 : $name.hashCode());
            final Object $type = this.type();
            result = result * PRIME + ($type == null ? 43 : $type.hashCode());
            return result;
        }

        public String toString() {
            return "KTlsSocketOptions.SockOption(name=" + this.name() + ", type=" + this.type() + ")";
        }
    }
}
