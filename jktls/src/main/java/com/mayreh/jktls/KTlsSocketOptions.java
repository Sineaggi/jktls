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

    private record SockOption<T>(
        String name,
        Class<T> type
    ) implements SocketOption<T> {
    }
}
