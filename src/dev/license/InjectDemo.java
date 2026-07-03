package dev.license;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Proves the injector end-to-end: inject the client into a synthetic Fabric jar
 * under package cz.onix, stamp a key, then class-load the generated LicenseGate
 * and run it against a live server - valid key passes, invalid/revoked crashes.
 *
 *   java -cp out dev.license.InjectDemo
 */
public final class InjectDemo {

    private static int passed = 0, failed = 0;

    public static void main(String[] args) throws Exception {
        if (!JarInjector.compilerAvailable()) {
            System.out.println("[SKIP] no JDK compiler - run on a JDK"); System.exit(0);
        }

        KeyPair kp = Crypto.generateKeyPair();
        String pub = Crypto.encodeKey(kp.getPublic());
        Path tmp = Files.createTempDirectory("injtest");
        Db db = new Db(tmp.resolve("license.db"));
        LicenseStore store = new LicenseStore(db);
        LicenseAuthority authority = new LicenseAuthority(store, kp.getPrivate());
        LicenseServer server = new LicenseServer(0, authority, store, "tok");
        int port = server.start();
        String baseUrl = "http://127.0.0.1:" + port;

        // stub classpath dir so the injected LicenseGate's ModInitializer resolves at load time
        Path stubDir = compileFabricStub(tmp);

        try {
            // synthetic Fabric mod jar with an existing entrypoint we must preserve
            Path baseJar = tmp.resolve("base.jar");
            Files.write(baseJar, makeFabricJar());

            JarInjector.Config cfg = new JarInjector.Config();
            cfg.baseUrl = baseUrl; cfg.publicKeyB64 = pub; cfg.product = "TestMod"; cfg.version = "1.0";
            JarInjector injector = new JarInjector(Path.of("src/dev/license"));
            byte[] injected = injector.inject(baseJar, "cz.onix", cfg);
            Path injJar = tmp.resolve("injected.jar");
            Files.write(injJar, injected);

            // ---- structural assertions ----
            check("injected client class present", entryExists(injJar, "cz/onix/protection/AuthClient.class"));
            check("gate entrypoint class present", entryExists(injJar, "cz/onix/protection/LicenseGate.class"));
            check("config embedded", entryExists(injJar, "cz/onix/protection/config.properties"));
            check("package marker present", "cz/onix/protection".equals(JarInjector.readPackagePath(injJar)));
            check("fabric stub NOT shipped", !entryExists(injJar, "net/fabricmc/api/ModInitializer.class"));
            String fmj = new String(entryBytes(injJar, "fabric.mod.json"), StandardCharsets.UTF_8);
            check("fabric.mod.json keeps original entrypoint", fmj.contains("com.example.TestMain"));
            check("fabric.mod.json registers the gate", fmj.contains("cz.onix.protection.LicenseGate"));

            String pkgPath = JarInjector.readPackagePath(injJar);
            String keyPath = pkgPath + "/license.key";

            // ---- runtime enforcement: VALID key ----
            String validKey = store.create("TestMod", "Dave", "d@x.com", 0, "");
            Path validJar = tmp.resolve("valid.jar");
            Files.write(validJar, JarStamper.stamp(injJar, keyPath, validKey.getBytes(StandardCharsets.UTF_8)));
            String v = runGate(validJar, stubDir);
            check("valid license -> gate passes (no crash)", v.equals("OK"));

            // ---- runtime enforcement: NO key baked in ----
            String none = runGate(injJar, stubDir); // never stamped
            check("missing license -> gate crashes", none.startsWith("THREW"));

            // ---- runtime enforcement: REVOKED key ----
            String revKey = store.create("TestMod", "Eve", "e@x.com", 0, "");
            store.revoke(revKey);
            Path revJar = tmp.resolve("revoked.jar");
            Files.write(revJar, JarStamper.stamp(injJar, keyPath, revKey.getBytes(StandardCharsets.UTF_8)));
            String rev = runGate(revJar, stubDir);
            check("revoked license -> gate crashes", rev.startsWith("THREW") && rev.contains("REVOKED"));

        } finally {
            server.stop();
        }

        System.out.println();
        System.out.println("==== " + passed + " passed, " + failed + " failed ====");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** Load the injected LicenseGate from the jar and invoke onInitialize(). Returns "OK" or "THREW: ...". */
    private static String runGate(Path jar, Path stubDir) throws Exception {
        URL[] urls = { jar.toUri().toURL(), stubDir.toUri().toURL() };
        try (URLClassLoader cl = new URLClassLoader(urls, InjectDemo.class.getClassLoader())) {
            Class<?> gate = Class.forName("cz.onix.protection.LicenseGate", true, cl);
            Object inst = gate.getDeclaredConstructor().newInstance();
            Method onInit = gate.getMethod("onInitialize");
            try {
                onInit.invoke(inst);
                return "OK";
            } catch (InvocationTargetException e) {
                return "THREW: " + e.getCause().getMessage();
            }
        }
    }

    private static Path compileFabricStub(Path dir) throws Exception {
        Path src = dir.resolve("stubsrc/net/fabricmc/api");
        Files.createDirectories(src);
        Files.writeString(src.resolve("ModInitializer.java"),
                "package net.fabricmc.api; public interface ModInitializer { void onInitialize(); }");
        Path out = dir.resolve("stubbin");
        Files.createDirectories(out);
        JavaCompiler jc = ToolProvider.getSystemJavaCompiler();
        try (StandardJavaFileManager fm = jc.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            fm.setLocation(StandardLocation.CLASS_OUTPUT, List.of(out.toFile()));
            jc.getTask(null, fm, null, null, null,
                    fm.getJavaFileObjectsFromPaths(List.of(src.resolve("ModInitializer.java")))).call();
        }
        return out;
    }

    private static byte[] makeFabricJar() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream z = new ZipOutputStream(bos)) {
            z.putNextEntry(new ZipEntry("fabric.mod.json"));
            z.write(("{\"schemaVersion\":1,\"id\":\"testmod\",\"version\":\"1.0.0\",\"name\":\"Test Mod\","
                    + "\"entrypoints\":{\"main\":[\"com.example.TestMain\"]}}").getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
            z.putNextEntry(new ZipEntry("assets/testmod/x.txt"));
            z.write("hi".getBytes(StandardCharsets.UTF_8));
            z.closeEntry();
        }
        return bos.toByteArray();
    }

    private static boolean entryExists(Path jar, String name) throws Exception {
        return entryBytesOrNull(jar, name) != null;
    }
    private static byte[] entryBytes(Path jar, String name) throws Exception {
        byte[] b = entryBytesOrNull(jar, name);
        if (b == null) throw new IllegalStateException("missing entry " + name);
        return b;
    }
    private static byte[] entryBytesOrNull(Path jar, String name) throws Exception {
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(Files.readAllBytes(jar)))) {
            ZipEntry e;
            while ((e = z.getNextEntry()) != null) if (e.getName().equals(name)) return z.readAllBytes();
        }
        return null;
    }

    private static void check(String name, boolean ok) {
        if (ok) { passed++; System.out.println("[PASS] " + name); }
        else    { failed++; System.out.println("[FAIL] " + name); }
    }
}
