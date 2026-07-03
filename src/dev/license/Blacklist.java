package dev.license;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Ban list for users, HWIDs, and IPs, backed by SQLite (table {@code bans}).
 * Same public API; constructor now takes a shared {@link Db}.
 */
public final class Blacklist {

    private final Connection c;

    public Blacklist(Db db) { this.c = db.conn(); }

    public boolean isUserBanned(String u)  { return u != null && has("user", u); }
    public boolean isHwidBanned(String h)  { return h != null && !h.isEmpty() && has("hwid", h); }
    public boolean isIpBanned(String ip)   { return ip != null && !ip.isEmpty() && has("ip", ip); }

    public void ban(String type, String value, String reason) throws IOException {
        String t = norm(type);
        if (t == null || value == null || value.isEmpty()) return;
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("INSERT OR REPLACE INTO bans(type,value,reason) VALUES(?,?,?)")) {
                ps.setString(1, t); ps.setString(2, value); ps.setString(3, reason == null ? "" : reason);
                ps.executeUpdate();
            } catch (SQLException e) { throw new IOException(e); }
        }
    }

    public void unban(String type, String value) throws IOException {
        String t = norm(type);
        if (t == null || value == null) return;
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("DELETE FROM bans WHERE type=? AND value=?")) {
                ps.setString(1, t); ps.setString(2, value); ps.executeUpdate();
            } catch (SQLException e) { throw new IOException(e); }
        }
    }

    /** Rows as {type, value, reason}. */
    public List<String[]> list() {
        synchronized (c) {
            List<String[]> out = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement("SELECT type,value,reason FROM bans ORDER BY type,value");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(new String[]{ rs.getString(1), rs.getString(2), nz(rs.getString(3)) });
            } catch (SQLException e) { throw new RuntimeException(e); }
            return out;
        }
    }

    private boolean has(String type, String value) {
        synchronized (c) {
            try (PreparedStatement ps = c.prepareStatement("SELECT 1 FROM bans WHERE type=? AND value=?")) {
                ps.setString(1, type); ps.setString(2, value);
                try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
            } catch (SQLException e) { throw new RuntimeException(e); }
        }
    }

    private static String norm(String type) {
        if (type == null) return null;
        String t = type.toLowerCase();
        return (t.equals("user") || t.equals("hwid") || t.equals("ip")) ? t : null;
    }
    private static String nz(String s) { return s == null ? "" : s; }
}
