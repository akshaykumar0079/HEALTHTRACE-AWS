"""Cross-system event correlation.

Events from different sources are normalised to one interface
(``NormalizedEvent``) and linked only by explicit, documented rules that
require a shared key (actor, request id, host or an exact resource). Two
events are never linked because they merely happened at about the same time.
"""
