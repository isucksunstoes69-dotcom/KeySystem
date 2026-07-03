package dev.license;

/**
 * Verified identity attached to a successfully validated license. Populated on
 * the client only AFTER the server's signature has been checked, so these
 * values are trustworthy.
 */
public final class Session {

    private final int uid;
    private final String username;
    private final String email;
    private final String licenseKey;
    private final String hwid;
    private final long expiry; // epoch millis, 0 = perpetual

    public Session(int uid, String username, String email,
                   String licenseKey, String hwid, long expiry) {
        this.uid = uid;
        this.username = username == null ? "" : username;
        this.email = email == null ? "" : email;
        this.licenseKey = licenseKey == null ? "" : licenseKey;
        this.hwid = hwid == null ? "" : hwid;
        this.expiry = expiry;
    }

    public int getUid()          { return uid; }
    public String getUsername()  { return username; }
    public String getEmail()     { return email; }
    public String getLicenseKey(){ return licenseKey; }
    public String getHwid()      { return hwid; }
    public long getExpiry()      { return expiry; }
    public boolean isPerpetual() { return expiry == 0L; }

    @Override
    public String toString() {
        return "Session{uid=" + uid + ", username='" + username + "', email='" + email
                + "', expiry=" + (expiry == 0 ? "never" : expiry) + "}";
    }
}
