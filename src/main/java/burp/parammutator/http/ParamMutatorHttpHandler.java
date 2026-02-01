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

public class ParamMutatorHttpHandler implements HttpHandler {
    private final AtomicReference<ExtensionConfig> configRef;
    private final Logger logger = Logger.getInstance();

    // user-def placeholder pattern: {$name$}
    private static final Pattern USER_DEF_PLACEHOLDER = Pattern.compile("\\{\\$(.+?)\\$}");

    public ParamMutatorHttpHandler(AtomicReference<ExtensionConfig> configRef) {
        this.configRef = configRef;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
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

        // 1) Normal / regex rule application on parameters
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
                if (rule.getParamType() == ParamMutatorRule.ParamPatternType.USER_DEF) {
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
                if (rule.getParamType() != ParamMutatorRule.ParamPatternType.USER_DEF) {
                    continue;
                }
                if (!rule.matchesPath(reqPath)) {
                    continue;
                }
                if (placeholderName.equals(rule.getPattern())) {
                    matchingRule = rule;
                    break;
                }
            }

            if (matchingRule == null) {
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

            // log for DEBUG/INFO using unified structure (key: "{$name$}" -> replacement value)
            changedParamValues.put(placeholderFull, replacement);
            allParamValues.put(placeholderFull, replacement);

            sb.append(fullMessage, lastEnd, m.start());
            sb.append(replacement);
            lastEnd = m.end();
        }

        if (lastEnd == 0 && userDefReplacements.isEmpty()) {
            // no user_def replacements
        } else {
            sb.append(fullMessage.substring(lastEnd));
            fullMessage = sb.toString();
            mutatedRequest = HttpRequest.httpRequest(fullMessage);
        }

        // 3) Logging – if any user_def changes occurred they are already in changedParamValues/allParamValues
        if (logger.getLogLevel() == LogLevel.DEBUG) {
            logger.logFullJson(origin, reqPath, allParamValues);
        } else if (logger.getLogLevel() == LogLevel.INFO) {
            logger.logInfoJson(origin, reqPath, changedParamValues);
        }

        return RequestToBeSentAction.continueWith(mutatedRequest, annotations);
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
