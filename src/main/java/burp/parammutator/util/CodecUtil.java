package burp.parammutator.util;

import burp.parammutator.model.CodecOp;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

public final class CodecUtil {

    private CodecUtil() { }

    public static String applyDecodeChain(String value, List<CodecOp> chain) {
        String v = value;
        if (chain == null) {
            return v;
        }
        for (CodecOp op : chain) {
            try {
                v = switch (op) {
                    case NO_OP -> v;
                    case URL_DECODE -> urlDecode(v);
                    case BASE64_DECODE -> base64Decode(v);
                    case UNICODE_DECODE -> unicodeDecode(v);
                    case UPPERCASE -> v.toUpperCase();
                    case LOWERCASE -> v.toLowerCase();
                    default -> v;
                };
            } catch (Exception ignored) {
            }
        }
        return v;
    }

    public static String applyEncodeChain(String value, List<CodecOp> chain) {
        String v = value;
        if (chain == null) {
            return v;
        }
        for (CodecOp op : chain) {
            try {
                v = switch (op) {
                    case NO_OP -> v;
                    case URL_ENCODE -> urlEncode(v);
                    case BASE64_ENCODE -> base64Encode(v);
                    case UNICODE_ENCODE -> unicodeEncode(v);
                    case UPPERCASE -> v.toUpperCase();
                    case LOWERCASE -> v.toLowerCase();
                    default -> v;
                };
            } catch (Exception ignored) {
            }
        }
        return v;
    }

    private static String urlDecode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String base64Decode(String s) {
        return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
    }

    private static String base64Encode(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String unicodeDecode(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length();) {
            char c = s.charAt(i);
            if (c == '\\' && i + 5 < s.length() && s.charAt(i + 1) == 'u') {
                String hex = s.substring(i + 2, i + 6);
                try {
                    int code = Integer.parseInt(hex, 16);
                    out.append((char) code);
                    i += 6;
                    continue;
                } catch (NumberFormatException ignored) {
                }
            }
            out.append(c);
            i++;
        }
        return out.toString();
    }

    private static String unicodeEncode(String s) {
        StringBuilder out = new StringBuilder(s.length() * 6);
        for (char c : s.toCharArray()) {
            if (c < 0x30 || (c > 0x39 && c < 0x41) || (c > 0x5A && c < 0x61) || c > 0x7e ) {
                out.append("\\u");
                String hex = Integer.toHexString(c);
                while (hex.length() < 4) {
                    hex = "0" + hex;
                }
                out.append(hex);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}
