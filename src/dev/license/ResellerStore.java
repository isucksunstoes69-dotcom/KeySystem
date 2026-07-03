package dev.license;

import java.io.IOException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Reseller (tenant) accounts, backed by SQLite (table {@code resellers}).
 * Same public API as before; constructor now takes a shared {@link Db}.
 */
public final class ResellerStore {

    private static final char[] ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789".toCharArray();
    private static final SecureRandom RNG = new SecureRandom();

    private final Connection c;

    public ResellerStore(Db db) { this.c = db.conn(); }

    public boolean exists(String id) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT 1 FROM resellers WHERE id=?")) {
                ps.setString(1, id);
                try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    public String name(String id)   { return get("name", id); }
    public String apiKey(String id)  { return get("api_key", id); }

    public long created(String id) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT created FROM resellers WHERE id=?")) {
                ps.setString(1, id);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getLong(1) : 0L; }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    /** Create a reseller, return {id, apiKey}. */
    public String[] create(String name) throws IOException {
        synchronized (c) {
            try {
                String id = "rs_" + slug(6);
                while (exists(id)) id = "rs_" + slug(6);
                String apiKey = "rk_" + slug(24);
                try (PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO resellers(id,name,api_key,created) VALUES(?,?,?,?)")) {
                    ps.setString(1, id); ps.setString(2, nn(name)); ps.setString(3, apiKey);
                    ps.setLong(4, System.currentTimeMillis());
                    ps.executeUpdate();
                }
                return new String[]{ id, apiKey };
            } catch (SQLException e) { throw new IOException(e); }
        }
    }

    public String resolveApiKey(String apiKey) {
        if (apiKey == null || apiKey.isEmpty()) return null;
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT id FROM resellers WHERE api_key=?")) {
                ps.setString(1, apiKey);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getString(1) : null; }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    public List<String> listIds() {
        synchronized (c) {
            List<String> out = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement("SELECT id FROM resellers ORDER BY id");
                 ResultSet rs = ps.executeQuery()) { while (rs.next()) out.add(rs.getString(1)); }
            catch (SQLException e) { throw new RuntimeException(e); }
            return out;
        }
    }

    private String get(String col, String id) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT " + col + " FROM resellers WHERE id=?")) {
                ps.setString(1, id);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? nz(rs.getString(1)) : ""; }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    private static String slug(int n) {
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) sb.append(ALPHABET[RNG.nextInt(ALPHABET.length)]);
        return sb.toString();
    }
    private static String nn(String s) { return s == null ? "" : s; }
    private static String nz(String s) { return s == null ? "" : s; }
}
