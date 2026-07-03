package dev.license;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tiny JSON parser/serializer (JDK-only) - just enough to read and patch a
 * {@code fabric.mod.json}. Objects -> LinkedHashMap, arrays -> ArrayList,
 * strings -> String, numbers -> Long/Double, plus Boolean/null.
 */
public final class MiniJson {

    private final String s;
    private int i;

    private MiniJson(String s) { this.s = s; }

    public static Object parse(String json) {
        MiniJson p = new MiniJson(json);
        p.ws();
        Object v = p.value();
        p.ws();
        return v;
    }

    private Object value() {
        char c = peek();
        switch (c) {
            case '{': return obj();
            case '[': return arr();
            case '"': return str();
            case 't': expect("true"); return Boolean.TRUE;
            case 'f': expect("false"); return Boolean.FALSE;
            case 'n': expect("null"); return null;
            default:  return num();
        }
    }

    private Map<String, Object> obj() {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        i++; ws();
        if (peek() == '}') { i++; return m; }
        while (true) {
            ws(); String k = str(); ws();
            if (s.charAt(i) != ':') throw err("expected ':'"); i++; ws();
            m.put(k, value()); ws();
            char c = s.charAt(i++);
            if (c == '}') break;
            if (c != ',') throw err("expected ',' or '}'");
        }
        return m;
    }

    private List<Object> arr() {
        ArrayList<Object> a = new ArrayList<>();
        i++; ws();
        if (peek() == ']') { i++; return a; }
        while (true) {
            ws(); a.add(value()); ws();
            char c = s.charAt(i++);
            if (c == ']') break;
            if (c != ',') throw err("expected ',' or ']'");
        }
        return a;
    }

    private String str() {
        if (s.charAt(i) != '"') throw err("expected string"); i++;
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = s.charAt(i++);
            if (c == '"') break;
            if (c == '\\') {
                char e = s.charAt(i++);
                switch (e) {
                    case '"': b.append('"'); break;
                    case '\\': b.append('\\'); break;
                    case '/': b.append('/'); break;
                    case 'n': b.append('\n'); break;
                    case 't': b.append('\t'); break;
                    case 'r': b.append('\r'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'u': b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; break;
                    default: b.append(e);
                }
            } else b.append(c);
        }
        return b.toString();
    }

    private Object num() {
        int st = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        String n = s.substring(st, i);
        if (n.indexOf('.') >= 0 || n.indexOf('e') >= 0 || n.indexOf('E') >= 0) return Double.parseDouble(n);
        try { return Long.parseLong(n); } catch (Exception e) { return Double.parseDouble(n); }
    }

    private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
    private char peek() { return s.charAt(i); }
    private void expect(String w) { if (!s.startsWith(w, i)) throw err("expected " + w); i += w.length(); }
    private RuntimeException err(String m) { return new RuntimeException("JSON@" + i + ": " + m); }

    // ---- serialize --------------------------------------------------------

    public static String write(Object o) {
        StringBuilder b = new StringBuilder();
        w(o, b);
        return b.toString();
    }

    private static void w(Object o, StringBuilder b) {
        if (o == null) { b.append("null"); }
        else if (o instanceof String) { ws((String) o, b); }
        else if (o instanceof Map) {
            b.append('{'); boolean f = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) o).entrySet()) {
                if (!f) b.append(','); f = false;
                ws(String.valueOf(e.getKey()), b); b.append(':'); w(e.getValue(), b);
            }
            b.append('}');
        } else if (o instanceof List) {
            b.append('['); boolean f = true;
            for (Object e : (List<?>) o) { if (!f) b.append(','); f = false; w(e, b); }
            b.append(']');
        } else if (o instanceof Boolean || o instanceof Number) {
            b.append(o.toString());
        } else {
            ws(o.toString(), b);
        }
    }

    private static void ws(String s, StringBuilder b) {
        b.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default: if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        b.append('"');
    }
}
