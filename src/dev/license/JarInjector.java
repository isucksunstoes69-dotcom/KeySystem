package dev.license;

import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Injects the license client into a Fabric mod jar so the mod self-enforces
 * with no source changes by the mod author.
 *
 * On {@link #inject}, it:
 *   1. compiles the client classes under {@code <basePackage>.protection}
 *      (rewritten package line -> any package works, no bytecode relocation),
 *   2. generates a {@code LicenseGate} ModInitializer that reads the baked-in
 *      key + config, validates against the server, and CRASHES the mod if
 *      invalid,
 *   3. patches {@code fabric.mod.json} to register that entrypoint,
 *   4. drops a package marker so the download step knows where to stamp the key.
 *
 * Requires a JDK at runtime (javax.tools.JavaCompiler). Fabric mods only.
 */
public final class JarInjector {

    /** Root marker file -> holds the injected package path, e.g. "cz/onix/protection". */
    public static final String MARKER = "META-INF/mclicense.pkg";

    /** Client source files (from the dev.license source dir) compiled into the mod. */
    private static final String[] CLIENT_FILES = {
        "Crypto.java", "HWIDGrabber.java", "Canonical.java", "Form.java",
        "LicenseRequest.java", "LicenseResponse.java", "LicenseResult.java",
        "Session.java", "AuthClient.java"
    };

    public static final class Config {
        public String baseUrl;
        public String publicKeyB64;
        public String product;
        public String version = "1.0";
    }

    private final Path clientSrcDir;

    public JarInjector(Path clientSrcDir) { this.clientSrcDir = clientSrcDir; }

    public static boolean compilerAvailable() { return ToolProvider.getSystemJavaCompiler() != null; }

    /** Returns the injected package path stored in the jar, or null if not injected. */
    public static String readPackagePath(Path jar) throws IOException {
        try (ZipInputStream z = new ZipInputStream(Files.newInputStream(jar))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) {
                if (e.getName().equals(MARKER)) return new String(z.readAllBytes(), StandardCharsets.UTF_8).trim();
            }
        }
        return null;
    }

    public byte[] inject(Path baseJar, String basePackage, Config cfg) throws IOException {
        if (!basePackage.matches("[a-zA-Z_][a-zA-Z0-9_]*(\\.[a-zA-Z_][a-zA-Z0-9_]*)*"))
            throw new IOException("invalid package name: " + basePackage);
        JavaCompiler jc = ToolProvider.getSystemJavaCompiler();
        if (jc == null) throw new IOException("no JDK compiler available - run the server on a JDK");

        String pkg = basePackage + ".protection";
        String pkgPath = pkg.replace('.', '/');
        String keyPath = pkgPath + "/license.key";

        Path work = Files.createTempDirectory("inject");
        try {
            Path srcOut = work.resolve("src");
            Path binOut = work.resolve("bin");
            Path pkgDir = srcOut.resolve(pkgPath);
            Files.createDirectories(pkgDir);
            Files.createDirectories(binOut);

            // 1. rewrite + collect client sources
            List<Path> sources = new ArrayList<>();
            for (String f : CLIENT_FILES) {
                String body = Files.readString(clientSrcDir.resolve(f));
                body = body.replaceFirst("package\\s+dev\\.license\\s*;", "package " + pkg + ";");
                Path out = pkgDir.resolve(f);
                Files.writeString(out, body);
                sources.add(out);
            }
            // 2. gate entrypoint
            Path gate = pkgDir.resolve("LicenseGate.java");
            Files.writeString(gate, gateSource(pkg));
            sources.add(gate);
            // fabric ModInitializer stub (compiled against, NOT shipped)
            Path stubDir = srcOut.resolve("net/fabricmc/api");
            Files.createDirectories(stubDir);
            Path stub = stubDir.resolve("ModInitializer.java");
            Files.writeString(stub, "package net.fabricmc.api; public interface ModInitializer { void onInitialize(); }");
            sources.add(stub);

            // 3. compile
            try (StandardJavaFileManager fm = jc.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
                fm.setLocation(StandardLocation.CLASS_OUTPUT, List.of(binOut.toFile()));
                Iterable<? extends JavaFileObject> units = fm.getJavaFileObjectsFromPaths(sources);
                ByteArrayOutputStream errs = new ByteArrayOutputStream();
                boolean ok = jc.getTask(new PrintWriter(errs), fm, null, List.of("-nowarn"), null, units).call();
                if (!ok) throw new IOException("client compile failed:\n" + errs.toString(StandardCharsets.UTF_8));
            }

            // 4. gather compiled classes (skip the fabric stub - Fabric provides it)
            Map<String, byte[]> add = new LinkedHashMap<>();
            List<Path> classes = new ArrayList<>();
            Files.walk(binOut).filter(Files::isRegularFile).forEach(classes::add);
            for (Path p : classes) {
                String rel = binOut.relativize(p).toString().replace('\\', '/');
                if (rel.startsWith("net/fabricmc/")) continue;
                add.put(rel, Files.readAllBytes(p));
            }
            // config + marker
            String config = "baseUrl=" + cfg.baseUrl + "\npublicKey=" + cfg.publicKeyB64
                    + "\nproduct=" + cfg.product + "\nversion=" + cfg.version + "\nkeyPath=" + keyPath + "\n";
            add.put(pkgPath + "/config.properties", config.getBytes(StandardCharsets.UTF_8));
            add.put(MARKER, pkgPath.getBytes(StandardCharsets.UTF_8));

            // 5. rewrite the jar: copy everything, patch fabric.mod.json, add our files
            return rebuild(baseJar, add, pkg + ".LicenseGate");
        } finally {
            deleteTree(work);
        }
    }

    private static byte[] rebuild(Path baseJar, Map<String, byte[]> add, String entrypoint) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        boolean patched = false;
        Set<String> written = new HashSet<>();
        byte[] buf = new byte[8192];
        try (ZipInputStream zin = new ZipInputStream(Files.newInputStream(baseJar));
             ZipOutputStream zout = new ZipOutputStream(bos)) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                String name = e.getName();
                if (add.containsKey(name) || written.contains(name)) { zin.closeEntry(); continue; }
                if (name.equals("fabric.mod.json")) {
                    byte[] np = patchFabricJson(zin.readAllBytes(), entrypoint);
                    writeEntry(zout, name, np);
                    patched = true;
                } else if (name.endsWith("/")) {
                    zout.putNextEntry(new ZipEntry(name)); zout.closeEntry();
                } else {
                    ByteArrayOutputStream tmp = new ByteArrayOutputStream();
                    int n; while ((n = zin.read(buf)) > 0) tmp.write(buf, 0, n);
                    writeEntry(zout, name, tmp.toByteArray());
                }
                written.add(name);
                zin.closeEntry();
            }
            if (!patched) throw new IOException("no fabric.mod.json at jar root - not a Fabric mod");
            for (Map.Entry<String, byte[]> a : add.entrySet()) {
                if (written.contains(a.getKey())) continue;
                writeEntry(zout, a.getKey(), a.getValue());
            }
        }
        return bos.toByteArray();
    }

    @SuppressWarnings("unchecked")
    private static byte[] patchFabricJson(byte[] orig, String entrypoint) {
        Object root = MiniJson.parse(new String(orig, StandardCharsets.UTF_8));
        if (!(root instanceof Map)) throw new RuntimeException("fabric.mod.json is not an object");
        Map<String, Object> m = (Map<String, Object>) root;

        Object epObj = m.get("entrypoints");
        Map<String, Object> eps;
        if (epObj instanceof Map) eps = (Map<String, Object>) epObj;
        else { eps = new LinkedHashMap<>(); m.put("entrypoints", eps); }

        Object mainObj = eps.get("main");
        List<Object> list;
        if (mainObj instanceof List) list = (List<Object>) mainObj;
        else {
            list = new ArrayList<>();
            if (mainObj != null) list.add(mainObj); // was a single string
            eps.put("main", list);
        }
        if (!list.contains(entrypoint)) list.add(entrypoint);
        return MiniJson.write(m).getBytes(StandardCharsets.UTF_8);
    }

    private static void writeEntry(ZipOutputStream zout, String name, byte[] data) throws IOException {
        zout.putNextEntry(new ZipEntry(name));
        zout.write(data);
        zout.closeEntry();
    }

    private static void deleteTree(Path root) {
        try {
            Files.walk(root).sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.deleteIfExists(p); } catch (IOException ignored) { }
            });
        } catch (IOException ignored) { }
    }

    private static String gateSource(String pkg) {
        return String.join("\n",
            "package " + pkg + ";",
            "import java.io.InputStream;",
            "import java.nio.charset.StandardCharsets;",
            "import java.util.Properties;",
            "public final class LicenseGate implements net.fabricmc.api.ModInitializer {",
            "  public void onInitialize() {",
            "    try {",
            "      Properties cfg = new Properties();",
            "      try (InputStream in = LicenseGate.class.getResourceAsStream(\"config.properties\")) {",
            "        if (in == null) { fail(\"no config\"); return; }",
            "        cfg.load(in);",
            "      }",
            "      String key = read(\"/\" + cfg.getProperty(\"keyPath\", \"\"));",
            "      if (key.isEmpty()) { fail(\"no license baked in\"); return; }",
            "      String hwid = HWIDGrabber.getHWID();",
            "      AuthClient client = new AuthClient(cfg.getProperty(\"baseUrl\"), cfg.getProperty(\"publicKey\"),",
            "          cfg.getProperty(\"product\"), cfg.getProperty(\"version\", \"1.0\"), 300000L);",
            "      LicenseResult r = client.validate(key, hwid);",
            "      if (!r.ok) { fail(r.reason); return; }",
            "      System.out.println(\"[License] valid for \" + (r.session != null ? r.session.getUsername() : \"user\"));",
            "    } catch (RuntimeException re) {",
            "      throw re;",
            "    } catch (Throwable t) {",
            "      fail(String.valueOf(t.getMessage()));",
            "    }",
            "  }",
            "  private static void fail(String why) {",
            "    throw new RuntimeException(\"[License] check failed: \" + why);",
            "  }",
            "  private static String read(String res) {",
            "    try (InputStream in = LicenseGate.class.getResourceAsStream(res)) {",
            "      if (in == null) return \"\";",
            "      return new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();",
            "    } catch (Exception e) { return \"\"; }",
            "  }",
            "}");
    }
}
