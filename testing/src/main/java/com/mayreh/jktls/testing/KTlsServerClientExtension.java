package com.mayreh.jktls.testing;

import com.mayreh.jktls.testing.KTlsServer.Handler;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class KTlsServerClientExtension implements BeforeEachCallback, AfterEachCallback {
    private KTlsServer server;
    private TlsClient client;
    private final String[] enabledCipherSuites;

    public KTlsServerClientExtension() {
        this(null);
    }

    public KTlsServerClientExtension(String[] enabledCipherSuites) {
        this.enabledCipherSuites = enabledCipherSuites;
    }

    public TlsClient getClient() {
        return this.client;
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
