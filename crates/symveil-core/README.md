# symveil-core

Free Apache-2.0 library behind the [SymVeil](https://symveil.dev) local proxy.

It masks secrets, IP addresses, and configured internal hostnames before a request leaves the machine, and restores the placeholders in the response. The vault stays local.

Identifier and code-name masking is not in this crate. The `symveil` binary does not declare an `identifiers` feature, and this package does not depend on a proprietary masker.

Repository: <https://github.com/magnusmalm/symveil>
