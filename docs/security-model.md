# Sentinel Security Model

## Threat model

Sentinel is a deterministic policy-enforcement layer for text-based AI applications. It covers selected prompt-injection and jailbreak patterns, credential/secret exposure patterns, selected PII patterns, unauthorized tools, and oversized inputs.

## Enforcement

1. Scan input or output.
2. Produce structured findings.
3. Apply a severity threshold.
4. Block high/critical findings.
5. Redact selected PII when configured.
6. Enforce explicit tool allowlists/blocklists.
7. Attach request IDs at the API boundary.

## Limitations

Pattern matching is not a complete AI-security solution. Sentinel does not claim semantic understanding of arbitrary prompt injection, novel jailbreaks, model behavior, data provenance, supply-chain compromise, or authorization semantics outside configured policies.

Production deployments should combine deterministic controls with authentication/authorization, sandboxing, model-specific adversarial testing, monitoring, secret management, and security review.
