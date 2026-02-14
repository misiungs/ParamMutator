# Param Mutator

Param Mutator is a Burp Suite extension that applies configurable mutations to HTTP request parameters before they are sent. It supports flexible path-based scoping, encoding/decoding chains, and integrated logging. It is useful for testing (both manual and scanning) of endpoints that require some parameters to be unique, allowing automated scans to proceed without being rejected due to duplicate parameter values.

## Overview

Param Mutator lets you define per-parameter rules that automatically modify request parameters as traffic flows through Burp. Rules can be scoped by request path, use either random or fixed string payloads, and support chained codecs such as URL, Base64, and Unicode encode/decode. This is particularly valuable when testing endpoints that require unique parameters, such as email addresses, usernames, transaction IDs, or nonce values — the extension ensures automatic scanning tools can test these endpoints without requests being rejected for using duplicate values.

## Features

- Rule-based mutations: configure rules that target parameters by exact name, regex, or substitute placeholders.  
- Substitute rules: define named placeholders (e.g. `{$token$}`) and a rule that provides the replacement value (fixed or random). The same placeholder can appear multiple times in one request and will be replaced consistently.
- Mode: choose RANDOM (with alphabet type and length) or STRING (fixed text) for each rule.
- Path-aware scoping: restrict rules to specific request paths (literal or regex).
- In-place updates: the extension uses Montoya's withPath/withHeader/withBody/withUpdatedParameters methods to perform safe, metadata-preserving updates to requests.
- Codec chains: apply ordered decode and encode chains per rule (URL, Base64, Unicode, etc.).
- Integrated logging: view mutations in the Log tab. Log level controls whether full parameter dumps or only mutated parameters are stored.
- Runtime toggle: enable or disable HTTP handling from the UI without unloading the extension.

## How it works (brief)

When enabled, the extension:
1. Applies normal/regex parameter rules against parsed parameters.
2. Scans the full request text for substitute placeholders ({$name$}).
3. Generates or reuses replacement values for matching Substitute rules.
4. Applies replacements in-place:
   - Updates the request path (withPath) if placeholders appear in the request line.
   - Updates headers (withHeader) if placeholders appear in header names/values.
   - Updates the body (withBody) when placeholders appear in the body.
   - Updates parsed URL/query parameters (withUpdatedParameters) to reflect substitutions in parameter names or values.
5. Adjusts Content-Length if the body size changed (unless chunked).
6. Returns the updated HttpRequest object to Montoya, preserving internal metadata so Burp will send the request normally.

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
2. Open the "Param Mutator" tab and configure rules in the "Configuration" view.  
   - For each rule, define:
     - Parameter pattern (one of three modes - Normal, Regex, and Subsitute).
     - Normal and Regex mode search for parameters based on their names.
     - Optional path filter (enabled flag, path pattern, and "Is regex?" for the path).
     - Mode: RANDOM (with alphabet/type and length) or STRING (with constant text).
     - Position: PREFIX or SUFFIX (applies when inserting into decoded values).
     - Decode and encode chains (Dec1–Dec4, Enc1–Enc4).
3. If substitution mode is used, use placeholders in requests: put `{$name$}` in path, headers, query, or body; for configured Substitute rule named "name" to control the replacement value.
4. Toggle "Enable Param Mutator" to start mutating outgoing HTTP requests.  
5. Check the "Log" tab to review substitutions and mutated parameters.

## Video Tutorial

Watch this tutorial to learn how to use the Param Mutator extension:

[![Param Mutator Tutorial](https://img.youtube.com/vi/deF-g6HTBTM/0.jpg)](https://www.youtube.com/watch?v=deF-g6HTBTM)
