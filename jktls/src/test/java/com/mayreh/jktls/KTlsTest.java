package com.mayreh.jktls;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import com.mayreh.jktls.testing.KTlsServerClientExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class KTlsTest {
    @RegisterExtension
    public KTlsServerClientExtension extension = new KTlsServerClientExtension(new String[] {
            "TLS_RSA_WITH_AES_128_GCM_SHA256"
    });

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    public void testEcho() {
        extension.setHandler((channel, message) -> {
            ByteBuffer buf = ByteBuffer.allocate(message.length);
            buf.put(message);
            buf.flip();
            channel.write(buf);
        });

        assertEquals("hello", extension.getClient().sendAndWaitReply("hello"));
    }

    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    public void testSendfile(@TempDir Path folder) throws Exception {
        Path file = folder.resolve("file.tmp");
        Files.write(file, "sendfile!!\n".getBytes(StandardCharsets.UTF_8));
        try (FileChannel fileChannel = FileChannel.open(file)) {
            extension.setHandler((channel, message) -> {
                channel.transferFrom(fileChannel, 0, fileChannel.size());
            });

            assertEquals("sendfile!!", extension.getClient().sendAndWaitReply("hello"));
        }
    }
}
