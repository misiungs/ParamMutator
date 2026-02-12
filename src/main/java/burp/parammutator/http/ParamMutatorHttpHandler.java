package burp.parammutator.http;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.HttpService;
import burp.parammutator.log.LogLevel;
import burp.parammutator.log.Logger;
import burp.parammutator.model.ExtensionConfig;
import burp.parammutator.model.MutationMode;
import burp.parammutator.model.ParamMutatorRule;
import burp.parammutator.model.Position;
import burp.parammutator.util.CodecUtil;
import burp.parammutator.util.RandomUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;

public class ParamMutatorHttpHandler implements HttpHandler {
    private final AtomicReference<ExtensionConfig> configRef;
    private final Logger logger = Logger.getInstance();

    // user-def placeholder pattern: {$name$}
    // Tighter pattern to avoid accidental cross-boundary matches
    private static final Pattern USER_DEF_PLACEHOLDER = Pattern.compile("\\{\\$([^\\}]+)\\$\\}");

    public ParamMutatorHttpHandler(AtomicReference<ExtensionConfig> configRef) {
        this.configRef = configRef;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        long tStart = System.nanoTime();
        ExtensionConfig cfg = configRef.get();
        Annotations annotations = requestToBeSent.annotations();

        if (cfg == null) {
            return RequestToBeSentAction.continueWith(requestToBeSent, annotations);
        }

        String origin = buildOrigin(requestToBeSent.httpService());
        String reqPath = requestToBeSent.path();
 
        List<ParsedHttpParameter> originalParams = requestToBeSent.parameters();
        List<HttpParameter> newParams = new ArrayList<>();

        Map<String, String> allParamValues = new HashMap<>();
        Map<String, String> changedParamValues = new HashMap<>();
        Map<String, String> substitutedParams = new HashMap<>();

        boolean hasSubstituteRules = false;
        for (ParamMutatorRule rule : cfg.getRules()) {
            if (rule.getParamType() == ParamMutatorRule.ParamPatternType.SUBSTITUTE) {
                hasSubstituteRules = true;
                break;
            }
        }

                for (ParsedHttpParameter param : originalParams) {
            String name = param.name();
            String value = param.value();
            var type = param.type();
            String transformed = value;
            boolean mutated = false;

            for (ParamMutatorRule rule : cfg.getRules()) {
                // path filter
                if (!rule.matchesPath(reqPath)) {
                    continue;
                }
                // skip user_def rules here – they are handled on full request
                if (rule.getParamType() == ParamMutatorRule.ParamPatternType.SUBSTITUTE) {
                    continue;
                }
                if (!rule.matches(name)) {
                    continue;
                }

                try {
                    String decoded = CodecUtil.applyDecodeChain(transformed, rule.getDecodeChain());

                    String insert;
                    if (rule.getMutationMode() == MutationMode.STRING) {
                        insert = rule.getText() == null ? "" : rule.getText();
                    } else {
                        insert = RandomUtil.randomString(rule.getType(), rule.getLength());
                    }

                    String mutatedValue;
                    if (rule.getPosition() == Position.PREFIX) {
                        mutatedValue = insert + decoded;
                    } else {
                        mutatedValue = decoded + insert;
                    }

                    transformed = CodecUtil.applyEncodeChain(mutatedValue, rule.getEncodeChain());
                    mutated = true;
                } catch (Exception ex) {
                    logger.log(LogLevel.DEBUG, origin, reqPath,
                            "Exception mutating param " + name + ": " + ex);
                }
            }

            allParamValues.put(name, mutated ? transformed : value);

            if (mutated && !transformed.equals(value)) {
                newParams.add(HttpParameter.parameter(name, transformed, type));
                changedParamValues.put(name, transformed);
            } else {
                newParams.add(param);
            }
        }
 
        HttpRequest mutatedRequest = requestToBeSent.withUpdatedParameters(newParams);
 
        // 2) user_def placeholder replacement on the full message
        Map<String, String> userDefReplacements = new HashMap<>();

        String fullMessage = mutatedRequest.toString();

        StringBuilder sb = new StringBuilder();
        int lastEnd = 0;

        Matcher m = USER_DEF_PLACEHOLDER.matcher(fullMessage);
        while (m.find()) {
            String placeholderFull = m.group(0);
            String placeholderName = m.group(1); // content inside {$ $}

            // find matching user_def rule with matching path (matchesPath already enforces path filter)
            ParamMutatorRule matchingRule = null;
            for (ParamMutatorRule rule : cfg.getRules()) {
                if (rule.getParamType() != ParamMutatorRule.ParamPatternType.SUBSTITUTE) {
                    continue;
                }
                if (!rule.matchesPath(reqPath)) {
                    continue;
                }
                // be permissive: allow rule.pattern to be stored as raw name, wrapped "{$name$}", or full placeholder
                String rulePattern = rule.getPattern() == null ? "" : rule.getPattern();
                if (placeholderName.equals(rulePattern)
                        || placeholderFull.equals(rulePattern)
                        || ("{$" + placeholderName + "$}").equals(rulePattern)) {
                    matchingRule = rule;
                    break;
                }
            }

            if (matchingRule == null) {
                if (logger.getLogLevel() == LogLevel.DEBUG) {
                    // collect available user-def patterns for debugging
                    StringBuilder available = new StringBuilder();
                    for (ParamMutatorRule r : cfg.getRules()) {
                        if (r.getParamType() == ParamMutatorRule.ParamPatternType.SUBSTITUTE && r.matchesPath(reqPath)) {
                            if (available.length() > 0) available.append(", ");
                            available.append("'").append(r.getPattern()).append("'");
                        }
                    }
                }
                continue;
            }

            // generate / reuse replacement for this user_def name
            String replacement = userDefReplacements.get(placeholderName);
            if (replacement == null) {
                if (matchingRule.getMutationMode() == MutationMode.STRING) {
                    replacement = matchingRule.getText() == null ? "" : matchingRule.getText();
                } else {
                    replacement = RandomUtil.randomString(matchingRule.getType(), matchingRule.getLength());
                }
                // apply encode chain (decode is meaningless for user_def)
                replacement = CodecUtil.applyEncodeChain(replacement, matchingRule.getEncodeChain());
                userDefReplacements.put(placeholderName, replacement);
            }

            // Track substituted parameters
            substitutedParams.put(placeholderName, replacement);

            // WARN if replacement contains CR/LF which can break request framing
            if (replacement.indexOf('\r') != -1 || replacement.indexOf('\n') != -1) {
                if (logger.getLogLevel() == LogLevel.DEBUG) {
                    String sanitized = replacement.replace("\r", "\\r").replace("\n", "\\n");
                    logger.log(LogLevel.DEBUG, origin, reqPath,
                            "Replacement for user-def '" + placeholderName + "' contains CR/LF, this may break request framing: " + sanitized);
                }
            }

            sb.append(fullMessage, lastEnd, m.start());
            sb.append(replacement);
            lastEnd = m.end();
        }

        if (lastEnd == 0 && userDefReplacements.isEmpty()) {
            // no user_def replacements
        } else {
            sb.append(fullMessage.substring(lastEnd));
            fullMessage = sb.toString();

            // --- CHANGED: adjust Content-Length when body size changed (unless chunked) ---
            int headerBodySepIndex = fullMessage.indexOf("\r\n\r\n");
            if (headerBodySepIndex != -1) {
                String headersPart = fullMessage.substring(0, headerBodySepIndex);
                String bodyPart = fullMessage.substring(headerBodySepIndex + 4);

                // don't modify if Transfer-Encoding: chunked is present
                Pattern transferChunked = Pattern.compile("(?mi)^Transfer-Encoding:\s*chunked\s*$", Pattern.MULTILINE);
                if (!transferChunked.matcher(headersPart).find()) {
                    byte[] bodyBytes = bodyPart.getBytes(StandardCharsets.ISO_8859_1);

                    // replace existing Content-Length header if present
                    Pattern clPattern = Pattern.compile("(?mi)^(Content-Length:\s*)(\\d+)\s*$", Pattern.MULTILINE);
                    Matcher clMatcher = clPattern.matcher(headersPart);
                    if (clMatcher.find()) {
                        String prefix = clMatcher.group(1);
                        headersPart = clMatcher.replaceFirst(prefix + bodyBytes.length);
                        fullMessage = headersPart + "\r\n\r\n" + bodyPart;
                    }
                    // if Content-Length not present, do not add it automatically to avoid changing semantics
                }
            }
            // --- END CHANGED ---

            // Try to construct request from mutated raw message; if it fails, fall back to previous request
            try {
                // parse request line / headers / body from fullMessage
                int headerBodySep = fullMessage.indexOf("\r\n\r\n");
                String headers = headerBodySep >= 0 ? fullMessage.substring(0, headerBodySep) : fullMessage;
                String body = headerBodySep >= 0 ? fullMessage.substring(Math.min(fullMessage.length(), headerBodySep + 4)) : "";
                int bodyBytes = body.getBytes(StandardCharsets.ISO_8859_1).length;

                // Extract request line and path
                String[] headerLines = headers.split("\r\n");
                if (headerLines.length == 0) {
                    throw new IllegalStateException("No request line in headers");
                }
                String requestLine = headerLines[0];
                String[] rlParts = requestLine.split(" ");
                if (rlParts.length >= 2) {
                    String newPath = rlParts[1];
                    try {
                        mutatedRequest = mutatedRequest.withPath(newPath);
                    } catch (Exception exPath) {
                        logger.log(LogLevel.DEBUG, origin, reqPath, "withPath failed: " + exPath);
                    }
                }

                // Apply headers (skip request line)
                for (int i = 1; i < headerLines.length; i++) {
                    String line = headerLines[i];
                    int idx = line.indexOf(':');
                    if (idx <= 0) continue;
                    String name = line.substring(0, idx).trim();
                    String value = line.substring(idx + 1).trim();
                    try {
                        mutatedRequest = mutatedRequest.withHeader(name, value);
                    } catch (Exception exHdr) {
                        // ignore header failures
                    }
                }

                // Apply body in-place (ISO_8859_1 bytes)
                try {
                    mutatedRequest = mutatedRequest.withBody(body);
                } catch (Exception exBody) {
                    // ignore body failures
                }

                // Update parsed URL/query parameters in-place for any user-def placeholders
                if (!userDefReplacements.isEmpty()) {
                    try {
                        List<HttpParameter> updatedParams = new ArrayList<>();
                        for (ParsedHttpParameter p : mutatedRequest.parameters()) {
                            String pname = p.name();
                            String pvalue = p.value();
                            boolean changed = false;
                            for (Map.Entry<String, String> rep : userDefReplacements.entrySet()) {
                                String ph = "{$" + rep.getKey() + "$}";
                                String rv = rep.getValue();
                                if (pname.contains(ph)) {
                                    pname = pname.replace(ph, rv);
                                    changed = true;
                                }
                                if (pvalue.contains(ph)) {
                                    pvalue = pvalue.replace(ph, rv);
                                    changed = true;
                                }
                            }
                            if (changed) {
                                updatedParams.add(HttpParameter.parameter(pname, pvalue, p.type()));
                            } else {
                                updatedParams.add(p);
                            }
                        }
                        // apply updated parameters only if something changed
                        mutatedRequest = mutatedRequest.withUpdatedParameters(updatedParams);
                    } catch (Exception exParams) {
                        logger.log(LogLevel.DEBUG, origin, reqPath, "withUpdatedParameters (user-def) failed: " + exParams);
                    }
                }
            } catch (Exception ex) {
                logger.log(LogLevel.DEBUG, origin, reqPath,
                        "Failed to apply in-place updates from mutated full message, falling back to parameter-mutated request: " + ex);
                // keep mutatedRequest as the one built from parameters to avoid blocking/silently failing
            }
        }

        // Logging based on mode and log level
        try {
            String jsonLog = buildLogJson(allParamValues, changedParamValues, substitutedParams, hasSubstituteRules);
            if (jsonLog != null && !jsonLog.isEmpty()) {
                logger.log(logger.getLogLevel(), origin, reqPath, jsonLog);
            }
        } catch (Exception ex) {
            logger.log(LogLevel.DEBUG, origin, reqPath, "Exception building JSON log: " + ex);
        }

        // Return mutated request
        return RequestToBeSentAction.continueWith(mutatedRequest, annotations);
    }

    private String buildLogJson(Map<String, String> allParams, Map<String, String> changedParams, 
                                  Map<String, String> substitutedParams, boolean hasSubstituteRules) {
        LogLevel currentLevel = logger.getLogLevel();
        
        Map<String, String> logData = new HashMap<>();
        
        if (hasSubstituteRules) {
            // Substitute mode logging
            if (currentLevel == LogLevel.DEBUG) {
                // DEBUG: log all parameters + substituted parameters
                logData.putAll(allParams);
                logData.putAll(substitutedParams);
            } else {
                // INFO: log only substituted parameters
                logData.putAll(substitutedParams);
            }
        } else {
            // Normal/Regex mode logging
            if (currentLevel == LogLevel.DEBUG) {
                // DEBUG: log all parameters
                logData.putAll(allParams);
            } else {
                // INFO: log only mutated parameters
                logData.putAll(changedParams);
            }
        }
        
        if (logData.isEmpty()) {
            return null;
        }
        
        return mapToJson(logData);
    }

    private String mapToJson(Map<String, String> map) {
        if (map == null || map.isEmpty()) {
            return "{}";
        }
        
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (!first) {
                json.append(",");
            }
            first = false;
            json.append("\"").append(escapeJson(entry.getKey())).append("\":");
            json.append("\"").append(escapeJson(entry.getValue())).append("\"");
        }
        json.append("}");
        return json.toString();
    }

    private String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private String buildOrigin(HttpService service) {
        String scheme = service.secure() ? "https" : "http";
        String host = service.host();
        int port = service.port();

        boolean isStandard =
                (!service.secure() && port == 80) ||
                        (service.secure() && port == 443);

        if (isStandard || port <= 0) {
            return scheme + "://" + host;
        }
        return scheme + "://" + host + ":" + port;
    }
}