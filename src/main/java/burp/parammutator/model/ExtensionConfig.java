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
        // ensure "user_def" (substitute) rules are placed first in the internal list
        this.rules = new ArrayList<>();
        if (rules != null) {
            // first add USER_DEF rules (preserve their relative order)
            for (ParamMutatorRule r : rules) {
                if (r != null && r.getParamType() == ParamMutatorRule.ParamPatternType.SUBSTITUTE) {
                    this.rules.add(r);
                }
            }
            // then add all other rules (preserve their relative order)
            for (ParamMutatorRule r : rules) {
                if (r != null && r.getParamType() != ParamMutatorRule.ParamPatternType.SUBSTITUTE) {
                     this.rules.add(r);
                 }
             }
         }
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
