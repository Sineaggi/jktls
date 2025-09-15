package com.mayreh.jktls.testing;

import com.mayreh.jktls.testing.KTlsServer.Handler;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

@RequiredArgsConstructor
public class KTlsServerClientExtension implements BeforeEachCallback, AfterEachCallback {
    private KTlsServer server;
    @Getter
    private TlsClient client;
    private final String[] enabledCipherSuites;

    public KTlsServerClientExtension() {
        this(null);
    }

    public int port() {
        return server.getPort();
    }

    public void setHandler(Handler handler) {
        server.setHandler(handler);
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        server = new KTlsServer(0, enabledCipherSuites);
        server.start();
        client = new TlsClient("localhost", server.getPort());
    }

    @Override
    public void afterEach(ExtensionContext context) {
        server.close();
        client.close();
    }
}
