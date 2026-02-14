package burp.parammutator;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.parammutator.model.ExtensionConfig;
import burp.parammutator.http.ParamMutatorHttpHandler;
import burp.parammutator.ui.LogPanel;
import burp.parammutator.ui.ParamMutatorConfigPanel;

import javax.swing.*;
import java.awt.*;
import java.util.concurrent.atomic.AtomicReference;

public class ParamMutatorExtension implements BurpExtension {
    private final AtomicReference<ExtensionConfig> configRef =
            new AtomicReference<>(ExtensionConfig.empty());
    private Registration httpRegistration = null;
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Param Mutator");

        // Register unload handler
        api.extension().registerUnloadingHandler(this::onUnload);

        JPanel mainPanel = new JPanel(new BorderLayout());
        JTabbedPane mainTabs = new JTabbedPane();

        ParamMutatorConfigPanel configPanel = new ParamMutatorConfigPanel(this::onConfigChanged);
        LogPanel logPanel = new LogPanel(api);

        mainTabs.addTab("Configuration", configPanel);
        mainTabs.addTab("Log", logPanel);

        mainPanel.add(mainTabs, BorderLayout.CENTER);

        api.userInterface().registerSuiteTab("Param Mutator", mainPanel);

        onConfigChanged(configRef.get());
    }

    private void onConfigChanged(ExtensionConfig newConfig) {
        configRef.set(newConfig);

        try {
            if (httpRegistration != null) {
                httpRegistration.deregister();
                httpRegistration = null;
            }
        } catch (Exception ignored) {
        }

        if (newConfig.isHttpEnabled()) {
            httpRegistration = api.http().registerHttpHandler(
                new ParamMutatorHttpHandler(configRef)
            );
        }
    }

    private void onUnload() {
        // Clean up HTTP handler registration
        try {
            if (httpRegistration != null) {
                httpRegistration.deregister();
                httpRegistration = null;
            }
        } catch (Exception e) {
            api.logging().logToError("Error during unload: " + e.getMessage());
        }
    }
}
