# BGP MRT Export Parse Tool

This is a tool to read BGP MRT exports and display the data in a human readable format. I'm building it as an exercise to learn more about BGP and RFC specifications.

## Useful resources

[RFC 6396](https://datatracker.ietf.org/doc/html/rfc6396#section-4.3.3) is a good starting point to understand the MRT format. Though you will quickly need to refer to [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271) to understand the BGP update messages, which are the encoding spec for RIB entry BGP attributes. Even then you'll need to refer to a bunch of other RFCs, which it seems like most are aggregated [here](https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2).
