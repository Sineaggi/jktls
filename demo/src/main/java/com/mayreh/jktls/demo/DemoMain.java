package com.mayreh.jktls.demo;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.mayreh.jktls.testing.KTlsServer;

public class DemoMain {
    private static final System.Logger logger = System.getLogger(DemoMain.class.getName());

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9090;

        Path resourceDir = Files.createTempDirectory("resource");
        Path file = resourceDir.resolve("lorem-ipsum.txt");
        try (InputStream is = DemoMain.class.getClassLoader().getResourceAsStream("lorem-ipsum.txt")) {
            Files.copy(is, file);
        }

        FileChannel fileChannel = FileChannel.open(file);
        KTlsServer tlsServer = new KTlsServer(port, new String[]{"TLS_RSA_WITH_AES_128_GCM_SHA256"});
        tlsServer.setHandler((channel, m) -> {
            String message = new String(m, StandardCharsets.UTF_8).trim();
            logger.log(System.Logger.Level.INFO, "Received: {0}", message);
            if ("lorem-ipsum".equals(message)) {
                fileChannel.position(0);
                channel.transferFrom(fileChannel, 0, fileChannel.size());
            } else {
                ByteBuffer buf = ByteBuffer.allocate(m.length);
                buf.put(m);
                buf.flip();
                channel.write(buf);
            }
        });
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            tlsServer.close();
            try {
                fileChannel.close();
                Utils.delete(resourceDir);
            } catch (IOException e) {
                logger.log(System.Logger.Level.INFO, "Failed to delete directory: {0}", resourceDir);
                throw new UncheckedIOException(e);
            }
        }));
        tlsServer.start();
    }
}
