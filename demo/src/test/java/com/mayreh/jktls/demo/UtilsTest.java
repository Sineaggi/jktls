package com.mayreh.jktls.demo;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class UtilsTest {
    @Test
    public void testDelete(@TempDir Path folder) throws Exception {
        Path testDir = Files.createDirectories(folder.resolve("test"));
        Files.write(testDir.resolve("foo.txt"),
                    "foo bar baz".getBytes(StandardCharsets.UTF_8));

        Utils.delete(testDir);
        assertFalse(Files.exists(testDir));
    }
}
