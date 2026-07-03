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
 * License records, backed by SQLite (table {@code licenses}). Public API is
 * unchanged from the old file-based version, so nothing that calls it changed
 * except the constructor, which now takes a shared {@link Db}.
 */
public final class LicenseStore {

    private static final char[] ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray(); // no 0/O/1/I
    private static final SecureRandom RNG = new SecureRandom();

    private final Connection c;

    public LicenseStore(Db db) { this.c = db.conn(); }

    // ---- lookups ----------------------------------------------------------

    public boolean exists(String key) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT 1 FROM licenses WHERE key=?")) {
                ps.setString(1, key);
                try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    public String product(String key)   { return getStr("product", key); }
    public String owner(String key)      { return getStr("owner", key); }
    public String email(String key)      { return getStr("email", key); }
    public int    uid(String key)        { return (int) getLong("uid", key); }
    public long   expiry(String key)     { return getLong("expiry", key); }
    public boolean revoked(String key)   { return getLong("revoked", key) != 0; }
    public String boundHwid(String key)  { return getStr("hwid", key); }
    public String reseller(String key)   { return getStr("reseller", key); }
    public String customer(String key)   { return getStr("customer", key); }
    public long   lastReset(String key)  { return getLong("reset_at", key); }

    public List<String> allowedHwids(String key) {
        String raw = getStr("allowed_hwids", key).trim();
        List<String> out = new ArrayList<>();
        if (!raw.isEmpty()) for (String s : raw.split(",")) { String t = s.trim(); if (!t.isEmpty()) out.add(t); }
        return out;
    }

    // ---- mutations --------------------------------------------------------

    public String create(String product, String owner, String email, int days, String presetHwid) throws IOException {
        return create(product, owner, email, days, presetHwid, "", "");
    }

    public String create(String product, String owner, String email, int days, String presetHwid,
                          String reseller, String customer) throws IOException {
        synchronized (c) {
            try {
                String key = generateKey();
                while (exists(key)) key = generateKey();
                long expiry = days <= 0 ? 0L : System.currentTimeMillis() + days * 86_400_000L;
                int uid = nextUid();
                try (PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO licenses(key,product,owner,email,uid,expiry,revoked,hwid,allowed_hwids,reseller,customer,reset_at) "
                        + "VALUES(?,?,?,?,?,?,0,?,'',?,?,0)")) {
                    ps.setString(1, key); ps.setString(2, nn(product)); ps.setString(3, nn(owner));
                    ps.setString(4, nn(email)); ps.setInt(5, uid); ps.setLong(6, expiry);
                    ps.setString(7, nn(presetHwid)); ps.setString(8, nn(reseller)); ps.setString(9, nn(customer));
                    ps.executeUpdate();
                }
                return key;
            } catch (SQLException e) { throw new IOException(e); }
        }
    }

    public void bindHwid(String key, String hwid) throws IOException { updateStr("hwid", nn(hwid), key); }
    public void setExpiry(String key, long epochMillis) throws IOException { updateLong("expiry", epochMillis, key); }
    public void setLastReset(String key, long epochMillis) throws IOException { updateLong("reset_at", epochMillis, key); }
    public void revoke(String key) throws IOException { updateLong("revoked", 1, key); }
    public void rebind(String key) throws IOException { updateStr("hwid", "", key); }

    public String findKey(String reseller, String product, String customer) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT key FROM licenses WHERE reseller=? AND product=? AND customer=? LIMIT 1")) {
                ps.setString(1, reseller); ps.setString(2, product); ps.setString(3, customer);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getString(1) : null; }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    public List<String> listKeys() {
        synchronized (c) {
            List<String> out = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement("SELECT key FROM licenses ORDER BY key");
                 ResultSet rs = ps.executeQuery()) { while (rs.next()) out.add(rs.getString(1)); }
            catch (SQLException e) { throw new RuntimeException(e); }
            return out;
        }
    }

    public List<String> listKeys(String reseller) {
        synchronized (c) {
            List<String> out = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement("SELECT key FROM licenses WHERE reseller=? ORDER BY key")) {
                ps.setString(1, reseller);
                try (ResultSet rs = ps.executeQuery()) { while (rs.next()) out.add(rs.getString(1)); }
            } catch (SQLException e) { throw new RuntimeException(e); }
            return out;
        }
    }

    // ---- internals (column names are fixed literals, never user input) ----

    private String getStr(String col, String key) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT " + col + " FROM licenses WHERE key=?")) {
                ps.setString(1, key);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? nz(rs.getString(1)) : ""; }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    private long getLong(String col, String key) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT " + col + " FROM licenses WHERE key=?")) {
                ps.setString(1, key);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getLong(1) : 0L; }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    private void updateStr(String col, String val, String key) throws IOException {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("UPDATE licenses SET " + col + "=? WHERE key=?")) {
                ps.setString(1, val); ps.setString(2, key); ps.executeUpdate();
            } catch (SQLException e) { throw new IOException(e); }
        }
    }

    private void updateLong(String col, long val, String key) throws IOException {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("UPDATE licenses SET " + col + "=? WHERE key=?")) {
                ps.setLong(1, val); ps.setString(2, key); ps.executeUpdate();
            } catch (SQLException e) { throw new IOException(e); }
        }
    }

    private int nextUid() throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("SELECT COALESCE(MAX(uid),1000)+1 FROM licenses");
             ResultSet rs = ps.executeQuery()) { rs.next(); return rs.getInt(1); }
    }

    private static String generateKey() {
        StringBuilder sb = new StringBuilder();
        for (int g = 0; g < 4; g++) {
            if (g > 0) sb.append('-');
            for (int i = 0; i < 5; i++) sb.append(ALPHABET[RNG.nextInt(ALPHABET.length)]);
        }
        return sb.toString();
    }

    private static String nn(String s) { return s == null ? "" : s; }
    private static String nz(String s) { return s == null ? "" : s; }
}
