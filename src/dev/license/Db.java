package dev.license;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Shared SQLite connection + schema. One database file holds licenses,
 * resellers, users, and bans. All four stores share this single connection and
 * serialize on it (SQLite is single-writer), which is plenty for this workload.
 *
 * Needs the sqlite-jdbc driver on the classpath (lib/sqlite-jdbc-*.jar).
 * On a Docker/VPS host, point LICENSE_DB at a file on the mounted volume.
 */
public final class Db implements AutoCloseable {

    private final Connection conn;

    public Db(Path file) throws IOException {
        try {
            if (file.getParent() != null) Files.createDirectories(file.getParent());
            conn = DriverManager.getConnection("jdbc:sqlite:" + file.toString());
            try (Statement st = conn.createStatement()) {
                st.execute("PRAGMA journal_mode=WAL");
                st.execute("PRAGMA busy_timeout=5000");
                st.execute("CREATE TABLE IF NOT EXISTS licenses("
                        + "key TEXT PRIMARY KEY, product TEXT, owner TEXT, email TEXT, uid INTEGER, "
                        + "expiry INTEGER, revoked INTEGER, hwid TEXT, allowed_hwids TEXT, "
                        + "reseller TEXT, customer TEXT, reset_at INTEGER)");
                st.execute("CREATE TABLE IF NOT EXISTS resellers("
                        + "id TEXT PRIMARY KEY, name TEXT, api_key TEXT, created INTEGER)");
                st.execute("CREATE TABLE IF NOT EXISTS users("
                        + "username TEXT PRIMARY KEY, pass TEXT, license_key TEXT, reseller TEXT, created INTEGER)");
                st.execute("CREATE TABLE IF NOT EXISTS bans("
                        + "type TEXT, value TEXT, reason TEXT, PRIMARY KEY(type,value))");
                st.execute("CREATE INDEX IF NOT EXISTS idx_lic_reseller ON licenses(reseller)");
                st.execute("CREATE INDEX IF NOT EXISTS idx_res_apikey ON resellers(api_key)");
                st.execute("CREATE INDEX IF NOT EXISTS idx_user_key ON users(license_key)");
            }
        } catch (SQLException e) {
            throw new IOException("failed to open SQLite db at " + file + ": " + e.getMessage(), e);
        }
    }

    /** Shared connection - callers must synchronize on it for writes. */
    public Connection conn() { return conn; }

    @Override
    public void close() {
        try { conn.close(); } catch (SQLException ignored) { }
    }
}
