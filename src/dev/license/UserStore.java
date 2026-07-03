package dev.license;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * End-user accounts, backed by SQLite (table {@code users}). Same public API;
 * constructor now takes a shared {@link Db}.
 */
public final class UserStore {

    private final Connection c;

    public UserStore(Db db) { this.c = db.conn(); }

    public static boolean validName(String name) {
        return name != null && name.matches("[A-Za-z0-9_.-]{1,32}");
    }

    public boolean exists(String name) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT 1 FROM users WHERE username=?")) {
                ps.setString(1, name);
                try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    public String passHash(String name) { return get("pass", name); }
    public String key(String name)      { return get("license_key", name); }
    public String reseller(String name) { return get("reseller", name); }

    public void create(String name, String passHash, String key, String reseller) throws IOException {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement(
                    "INSERT INTO users(username,pass,license_key,reseller,created) VALUES(?,?,?,?,?)")) {
                ps.setString(1, name); ps.setString(2, passHash); ps.setString(3, nn(key));
                ps.setString(4, nn(reseller)); ps.setLong(5, System.currentTimeMillis());
                ps.executeUpdate();
            } catch (SQLException e) { throw new IOException(e); }
        }
    }

    public void delete(String name) throws IOException {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("DELETE FROM users WHERE username=?")) {
                ps.setString(1, name); ps.executeUpdate();
            } catch (SQLException e) { throw new IOException(e); }
        }
    }

    /** Username that claimed this license key, or null. */
    public String userForKey(String key) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT username FROM users WHERE license_key=? LIMIT 1")) {
                ps.setString(1, key);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getString(1) : null; }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    public List<String> list() {
        synchronized (c) {
            List<String> out = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement("SELECT username FROM users ORDER BY username");
                 ResultSet rs = ps.executeQuery()) { while (rs.next()) out.add(rs.getString(1)); }
            catch (SQLException e) { throw new RuntimeException(e); }
            return out;
        }
    }

    public List<String> listByReseller(String reseller) {
        synchronized (c) {
            List<String> out = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement("SELECT username FROM users WHERE reseller=? ORDER BY username")) {
                ps.setString(1, reseller);
                try (ResultSet rs = ps.executeQuery()) { while (rs.next()) out.add(rs.getString(1)); }
            } catch (SQLException e) { throw new RuntimeException(e); }
            return out;
        }
    }

    private String get(String col, String name) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT " + col + " FROM users WHERE username=?")) {
                ps.setString(1, name);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? nz(rs.getString(1)) : ""; }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    private static String nn(String s) { return s == null ? "" : s; }
    private static String nz(String s) { return s == null ? "" : s; }
}
