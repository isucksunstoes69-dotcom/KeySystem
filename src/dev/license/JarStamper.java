package dev.license;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;

/**
 * Bakes a license key into a copy of a mod jar. A .jar is just a zip, so we copy
 * the base jar and write/replace a single {@code license.key} entry at its root
 * using the JDK zip FileSystem (every other entry is preserved byte-for-byte).
 *
 * The mod reads this back at runtime via getResourceAsStream("/license.key").
 */
public final class JarStamper {

    private JarStamper() {}

    /** Root entry the mod looks for. */
    public static final String LICENSE_ENTRY = "license.key";

    public static byte[] stampKey(Path baseJar, String licenseKey) throws IOException {
        return stamp(baseJar, LICENSE_ENTRY, licenseKey.getBytes(StandardCharsets.UTF_8));
    }

    /** Write/replace an arbitrary entry (e.g. cz/onix/protection/license.key) in a copy of the jar. */
    public static byte[] stamp(Path baseJar, String entryPath, byte[] content) throws IOException {
        Path tmp = Files.createTempFile("stamped-", ".jar");
        try {
            Files.copy(baseJar, tmp, StandardCopyOption.REPLACE_EXISTING);
            URI uri = URI.create("jar:" + tmp.toUri());
            try (FileSystem fs = FileSystems.newFileSystem(uri, new HashMap<String, String>())) {
                Path inside = fs.getPath("/" + entryPath);
                if (inside.getParent() != null) Files.createDirectories(inside.getParent());
                Files.write(inside, content); // create or overwrite
            }
            return Files.readAllBytes(tmp);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
