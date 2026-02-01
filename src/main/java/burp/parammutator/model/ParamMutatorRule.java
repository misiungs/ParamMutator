package burp.parammutator.model;

import java.util.List;
import java.util.regex.Pattern;

public final class ParamMutatorRule {

    private String pattern;

    // OLD:
    // private boolean regex;
    //
    // NEW: replace boolean regex with a type enum
    public enum ParamPatternType {
        NORMAL,
        REGEX,
        USER_DEF
    }

    private ParamPatternType paramType;

    private boolean pathEnabled;
    private String pathPattern;
    private boolean pathRegex;
    private MutationMode mutationMode = MutationMode.RANDOM;
    private RandomType type;
    private int length;
    private String text;
    private Position position;
    private List<CodecOp> decodeChain;
    private List<CodecOp> encodeChain;
    private transient Pattern compiledPattern;
    private transient Pattern compiledPathPattern;

    public ParamMutatorRule() {
        // default
    }

    // convenience ctor for existing usage – treat regex flag as NORMAL/REGEX
    public ParamMutatorRule(String pattern,
                            boolean regex,
                            RandomType type,
                            Position position,
                            int length,
                            List<CodecOp> decodeChain,
                            List<CodecOp> encodeChain) {
        this(pattern,
                regex ? ParamPatternType.REGEX : ParamPatternType.NORMAL,
                MutationMode.RANDOM,
                type,
                position,
                length,
                null,
                decodeChain,
                encodeChain,
                false,
                "",
                false);
    }

    public ParamMutatorRule(String pattern,
                            boolean regex,
                            MutationMode mutationMode,
                            RandomType type,
                            Position position,
                            int length,
                            String text,
                            List<CodecOp> decodeChain,
                            List<CodecOp> encodeChain) {
        this(pattern,
                regex ? ParamPatternType.REGEX : ParamPatternType.NORMAL,
                mutationMode,
                type,
                position,
                length,
                text,
                decodeChain,
                encodeChain,
                false,
                "",
                false);
    }

    // NEW canonical ctor using ParamPatternType
    public ParamMutatorRule(String pattern,
                            ParamPatternType paramType,
                            MutationMode mutationMode,
                            RandomType type,
                            Position position,
                            int length,
                            String text,
                            List<CodecOp> decodeChain,
                            List<CodecOp> encodeChain,
                            boolean pathEnabled,
                            String pathPattern,
                            boolean pathRegex) {
        this.pattern = pattern;
        this.paramType = paramType == null ? ParamPatternType.NORMAL : paramType;

        this.mutationMode = mutationMode == null ? MutationMode.RANDOM : mutationMode;
        this.type = type;
        this.position = position;
        this.length = length;
        this.text = text;

        this.decodeChain = decodeChain;
        this.encodeChain = encodeChain;

        this.pathEnabled = pathEnabled;
        this.pathPattern = pathPattern;
        this.pathRegex = pathRegex;

        compilePattern();
        compilePathPattern();
    }

    // helper used by legacy constructors
    private void compilePattern() {
        if (paramType == ParamPatternType.REGEX && pattern != null && !pattern.isEmpty()) {
            compiledPattern = Pattern.compile(pattern);
        } else {
            compiledPattern = null;
        }
    }

    public void compilePathPattern() {
        if (pathEnabled && pathRegex && pathPattern != null && !pathPattern.isEmpty()) {
            compiledPathPattern = Pattern.compile(pathPattern);
        } else {
            compiledPathPattern = null;
        }
    }

    public boolean matches(String paramName) {
        String name = paramName == null ? "" : paramName;
        String pat = pattern == null ? "" : pattern;

        return switch (paramType) {
            case REGEX -> {
                if (compiledPattern == null && !pat.isEmpty()) {
                    compilePattern();
                }
                yield compiledPattern != null && compiledPattern.matcher(name).matches();
            }
            case NORMAL -> name.equals(pat);
            case USER_DEF -> {
                // USER_DEF rules are matched by placeholder replacement, not by parameter list
                yield false;
            }
        };
    }

    public boolean matchesPath(String requestPath) {
        if (!pathEnabled) {
            return true;
        }

        String p = requestPath == null ? "" : requestPath;
        String filter = pathPattern == null ? "" : pathPattern;

        if (filter.isEmpty()) {
            return false;
        }

        if (pathRegex) {
            if (compiledPathPattern == null) {
                compilePathPattern();
            }
            return compiledPathPattern != null && compiledPathPattern.matcher(p).matches();
        }

        return p.equals(filter);
    }

    public String getPattern() {
        return pattern;
    }

    // NEW getter / setter
    public ParamPatternType getParamType() {
        return paramType == null ? ParamPatternType.NORMAL : paramType;
    }

    public void setParamType(ParamPatternType paramType) {
        this.paramType = paramType == null ? ParamPatternType.NORMAL : paramType;
        compilePattern();
    }

    // legacy compatibility for UI/table code that still calls isRegex()
    public boolean isRegex() {
        return getParamType() == ParamPatternType.REGEX;
    }

    public MutationMode getMutationMode() {
        return mutationMode == null ? MutationMode.RANDOM : mutationMode;
    }

    public RandomType getType() {
        return type;
    }

    public Position getPosition() {
        return position;
    }

    public int getLength() {
        return length;
    }

    public String getText() {
        return text;
    }

    public List<CodecOp> getDecodeChain() {
        return decodeChain;
    }

    public List<CodecOp> getEncodeChain() {
        return encodeChain;
    }

    public boolean isPathEnabled() {
        return pathEnabled;
    }

    public String getPathPattern() {
        return pathPattern;
    }

    public boolean isPathRegex() {
        return pathRegex;
    }
}
