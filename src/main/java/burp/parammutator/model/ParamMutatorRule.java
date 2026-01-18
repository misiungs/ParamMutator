package burp.parammutator.model;

import java.util.List;
import java.util.regex.Pattern;

public final class ParamMutatorRule {

    private String pattern;
    private boolean regex;
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
        // .
    }
    public ParamMutatorRule(String pattern,
                           boolean regex,
                           RandomType type,
                           Position position,
                           int length,
                           List<CodecOp> decodeChain,
                           List<CodecOp> encodeChain) {
        this(pattern, regex, MutationMode.RANDOM, type, position, length, null, decodeChain, encodeChain,
                false, "", false);
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
        this(pattern, regex, mutationMode, type, position, length, text, decodeChain, encodeChain,
                false, "", false);
    }

    public ParamMutatorRule(String pattern,
                           boolean regex,
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
        this.regex = regex;

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

    public void compilePattern() {
        if (regex && pattern != null && !pattern.isEmpty()) {
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
        if (regex) {
            if (compiledPattern == null) {
                compilePattern();
            }
            return compiledPattern != null && compiledPattern.matcher(paramName).matches();
        }
        return paramName.equals(paramName == null ? "" : pattern);
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

    public boolean isRegex() {
        return regex;
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
