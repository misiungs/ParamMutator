package burp.parammutator.util;

import burp.parammutator.model.RandomType;

import java.util.concurrent.ThreadLocalRandom;

public final class RandomUtil {

    private static final String NUM = "0123456789";
    private static final String ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final String ALPHANUM = NUM + ALPHA;

    private RandomUtil() { }

    public static String randomString(RandomType type, int length) {
        String chars;
        switch (type) {
            case NUMERIC -> chars = NUM;
            case ALPHA -> chars = ALPHA;
            default -> chars = ALPHANUM;
        }
        ThreadLocalRandom rnd = ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder(length <= 0 ? 1 : length);
        int len = Math.max(length, 1);
        for (int i = 0; i < len; i++) {
            sb.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
