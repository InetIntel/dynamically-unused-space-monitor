# MORP4:A Dynamic Network Telescope

A _network telescope_ passively monitors traffic reaching Internet
address space that is not assigned to any hosts but is advertised to
the global routing system. This traffic is by definition unsolicited. For
more than two decades, network telescopes have enabled research
breakthroughs by allowing global visibility into a wide range of
Internet phenomena. However, network telescopes are afflicted by
two main issues: progressive erosion, due to the increasing scarcity
and commercial value of address space, and blacklisting.

To overcome these issues, we propose MORP4, a programmable
data plane framework implementing a “dynamic” network telescope. MORP4 adaptively tracks unused space of an organization’s
network with configurable time and space granularity and captures
only traffic directed towards unused addresses. MORP4 enables
an organization not only to “recover” unused space for capturing
unsolicited traffic but it also provides greater utility than a static
telescope by countering blacklisting and monitoring addresses adjacent to used ones. We provide an implementation of MORP4 in P4
and Python, and deploy it on an actual Tofino switch. We show that
it can detect unused (IPv4) address space at the finest granularity
(/32) while operating at line rate and leaving enough resources for
other applications running on the switch.
