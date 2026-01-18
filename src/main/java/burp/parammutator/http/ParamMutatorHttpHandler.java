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

public class ParamMutatorHttpHandler implements HttpHandler {
    private final AtomicReference<ExtensionConfig> configRef;
    private final Logger logger = Logger.getInstance();

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

        for (ParsedHttpParameter param : originalParams) {
            String name = param.name();
            String value = param.value();
            var type = param.type();
            String transformed = value;
            boolean mutated = false;

            for (ParamMutatorRule rule : cfg.getRules()) {
                if (!rule.matchesPath(reqPath)) {
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
                    logger.log(LogLevel.FULL, origin, reqPath,
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

        // Logging behavior
        // FULL: log all parameters
        if (logger.getLogLevel() == LogLevel.FULL) {
            logger.logFullJson(origin, reqPath, allParamValues);
        } else if (logger.getLogLevel() == LogLevel.INFO) {
            // INFO: log only mutated params; if none mutated, nothing logged
            logger.logInfoJson(origin, reqPath, changedParamValues);
        }

        HttpRequest mutatedRequest = requestToBeSent.withUpdatedParameters(newParams);
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
