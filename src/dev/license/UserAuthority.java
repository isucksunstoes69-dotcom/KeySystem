package dev.license;

import java.io.IOException;

/**
 * KeyAuth-style account flows layered on top of the signed license system:
 * register / login (username + password + key) and bare-key license, all with
 * ban enforcement. Every path that grants access returns the SIGNED
 * {@link LicenseResponse} so the client verifies it against the embedded key.
 */
public final class UserAuthority {

    private final UserStore users;
    private final LicenseStore store;
    private final LicenseAuthority authority;
    private final Blacklist blacklist;

    public UserAuthority(UserStore users, LicenseStore store, LicenseAuthority authority, Blacklist blacklist) {
        this.users = users;
        this.store = store;
        this.authority = authority;
        this.blacklist = blacklist;
    }

    public static final class Result {
        public boolean success;
        public String status;   // machine code
        public String message;  // human message
        public String username; // set on login/register
        public LicenseResponse license; // signed, when access is granted or license-related

        static Result of(boolean ok, String status, String msg) {
            Result r = new Result(); r.success = ok; r.status = status; r.message = msg; return r;
        }
    }

    // ---- bare license key -------------------------------------------------
    public Result license(String key, String hwid, String ip) {
        if (blacklist.isHwidBanned(hwid) || blacklist.isIpBanned(ip)) return Result.of(false, "BANNED", "Banned");
        LicenseRequest req = new LicenseRequest("", key, hwid, Crypto.newNonce(), "");
        // product isn't known on the bare path; validate against the license's own product.
        LicenseResponse lr = authority.validate(new LicenseRequest(store.product(key), key, hwid, req.nonce, ""));
        Result r = Result.of(lr.valid, lr.reason, lr.valid ? "Licensed" : lr.reason);
        r.license = lr;
        return r;
    }

    // ---- register ---------------------------------------------------------
    public Result register(String username, String password, String key, String hwid, String ip) throws IOException {
        if (blacklist.isHwidBanned(hwid) || blacklist.isIpBanned(ip)) return Result.of(false, "BANNED", "Banned");
        if (!UserStore.validName(username)) return Result.of(false, "INVALID_USERNAME", "Invalid username");
        if (password == null || password.length() < 4) return Result.of(false, "WEAK_PASSWORD", "Password too short");
        if (users.exists(username)) return Result.of(false, "USERNAME_TAKEN", "Username already taken");
        if (!store.exists(key)) return Result.of(false, "UNKNOWN_KEY", "Invalid license key");
        if (users.userForKey(key) != null) return Result.of(false, "KEY_ALREADY_USED", "License already registered");

        LicenseResponse lr = authority.validate(new LicenseRequest(store.product(key), key, hwid, Crypto.newNonce(), ""));
        if (!lr.valid) { Result r = Result.of(false, lr.reason, lr.reason); r.license = lr; return r; }

        users.create(username, Passwords.hash(password), key, store.reseller(key));
        Result r = Result.of(true, "OK", "Registered");
        r.username = username; r.license = lr;
        return r;
    }

    // ---- login ------------------------------------------------------------
    public Result login(String username, String password, String hwid, String ip) {
        if (blacklist.isUserBanned(username) || blacklist.isHwidBanned(hwid) || blacklist.isIpBanned(ip))
            return Result.of(false, "BANNED", "Banned");
        if (!users.exists(username) || !Passwords.verify(password, users.passHash(username)))
            return Result.of(false, "INVALID_CREDENTIALS", "Invalid username or password");

        String key = users.key(username);
        LicenseResponse lr = authority.validate(new LicenseRequest(store.product(key), key, hwid, Crypto.newNonce(), ""));
        Result r = Result.of(lr.valid, lr.valid ? "OK" : lr.reason, lr.valid ? "Logged in" : lr.reason);
        r.username = username; r.license = lr;
        return r;
    }
}
