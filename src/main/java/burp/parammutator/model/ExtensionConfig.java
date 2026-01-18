package burp.parammutator.model;

import java.util.ArrayList;
import java.util.List;

public final class ExtensionConfig {

    private List<ParamMutatorRule> rules;
    private boolean httpEnabled;

    public ExtensionConfig() {
        this.rules = new ArrayList<>();
        this.httpEnabled = false; // default off
    }

    public ExtensionConfig(List<ParamMutatorRule> rules,
                           boolean httpEnabled) {
        this.rules = new ArrayList<>(rules);
        this.httpEnabled = httpEnabled;
    }

    public boolean isHttpEnabled() {
        return httpEnabled;
    }

    public List<ParamMutatorRule> getRules() {
        return rules;
    }

    public static ExtensionConfig empty() {
        return new ExtensionConfig();
    }
}
