# Param Mutator

Param Mutator is a Burp Suite extension that applies configurable mutations to HTTP request parameters before they are sent, with flexible path-based scoping, encoding/decoding chains, and integrated logging.

## Overview

Param Mutator lets you define per-parameter rules that automatically modify request parameters as traffic flows through Burp. Rules can be scoped by request path, use either random or fixed string payloads, and support chained codecs such as URL, Base64, and Unicode encode/decode.

## Features

- **Rule-based mutations**: Configure up to 100 rules, each targeting parameters by exact name or regular expression.  
- Path-aware scoping: Optionally restrict rules to specific request paths, with literal or regex path matching.  
- Random and fixed payloads: Choose between random strings (numeric, alpha, alphanumeric) of configurable length or fixed text payloads.  
- Flexible position: Insert payloads as prefix or suffix of the decoded parameter value.  
- Codec chains: Apply ordered decode and encode chains per rule, supporting URL, Base64, and Unicode transformations.  
- Integrated logging: View mutations in a dedicated Log tab, with adjustable log level, size limit, table sorting, and CSV export.  
- Runtime toggle: Enable or disable HTTP handling globally from the UI without unloading the extension.

## How it works

The extension registers an HTTP handler that inspects each outgoing request when HTTP processing is enabled. For every parameter, it finds matching rules (parameter pattern and optional path filters), decodes the value using the configured decode chain, applies the mutation (random or fixed string, prefix or suffix), then re-encodes the result with the encode chain and updates the request before it is sent. Logging captures either all parameter values or only the mutated ones, depending on the selected log level.

## Building

The project is a Maven-based Java 17 Burp extension using the Montoya API.

```bash
# Clone the repository
git clone https://github.com/misiungs/ParamMutator.git
cd ParamMutator

# Build the extension JAR
mvn clean package
```

The compiled JAR is available under Releases.

## Usage

1. Load the JAR into Burp Suite via the Extender tab (Extensions → Add → Select JAR).  
2. Open the "Param Mutator" tab and configure rules in the **Configuration** view.  
   - Set the number of visible rules.  
   - For each rule, define:  
     - Parameter pattern and "Is regex?" flag.  
     - Optional path filter (enabled flag, path pattern, and "Is regex?" for the path).  
     - Mode: RANDOM (with type and length) or STRING (with custom text).  
     - Position: PREFIX or SUFFIX.  
     - Decode and encode chains (Dec1–Dec4, Enc1–Enc4).  
3. Toggle "Enable Param Mutator" to start mutating outgoing HTTP requests.  
4. Use the **Log** tab to:  
   - Switch between FULL (all parameters) and INFO (only mutated parameters) logging.  
   - Adjust maximum log size in MB, clear logs, and export them to CSV for detailed analysis.  
