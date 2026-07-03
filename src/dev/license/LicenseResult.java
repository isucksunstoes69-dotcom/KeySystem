package dev.license;

/** Outcome of a client-side validation attempt. */
public final class LicenseResult {

    public final boolean ok;
    public final String reason;
    public final Session session; // non-null only when ok == true

    private LicenseResult(boolean ok, String reason, Session session) {
        this.ok = ok;
        this.reason = reason;
        this.session = session;
    }

    public static LicenseResult valid(Session s) { return new LicenseResult(true, "OK", s); }
    public static LicenseResult invalid(String reason) { return new LicenseResult(false, reason, null); }

    @Override
    public String toString() {
        return "LicenseResult{ok=" + ok + ", reason='" + reason + "'"
                + (session != null ? ", " + session : "") + "}";
    }
}
