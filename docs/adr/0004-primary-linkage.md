# ADR 0004: Require a primary linkage when bindings compose

Status: accepted

The status model has one linkage facet while pattern composition permits a
claim to carry several valid bindings. A claim with more than one admitted
binding must therefore select `primary_linkage` in its manifest. The summary
uses that binding and the detailed closure retains all others. An absent or
incompatible selection fails closed as ambiguous.

