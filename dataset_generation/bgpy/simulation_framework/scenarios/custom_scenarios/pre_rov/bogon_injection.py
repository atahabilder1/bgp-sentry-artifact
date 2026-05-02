from typing import TYPE_CHECKING, Optional

from bgpy.shared.enums import Prefixes, Timestamps
from bgpy.simulation_framework.scenarios.scenario import Scenario

if TYPE_CHECKING:
    from bgpy.simulation_engine import Announcement as Ann
    from bgpy.simulation_engine import BaseSimulationEngine


class BogonInjection(Scenario):
    """Bogon injection attack where attacker announces reserved/private IP space

    Bogon prefixes are IP addresses that should never appear in the global
    routing table (RFC 1918 private addresses, reserved blocks, etc.).
    An attacker injecting bogon routes is either misconfigured or malicious.
    """

    def _get_announcements(
        self,
        *,
        engine: Optional["BaseSimulationEngine"] = None,
    ) -> tuple["Ann", ...]:
        """Returns bogon announcements from attackers

        Unlike prefix hijacks, there is no legitimate victim announcement
        for bogon routes - they should never exist in global BGP.
        """

        anns = list()
        for attacker_asn in self.attacker_asns:
            anns.append(
                self.scenario_config.AnnCls(
                    prefix=Prefixes.BOGON_PREFIX.value,
                    as_path=(attacker_asn,),
                    timestamp=Timestamps.get_attacker_timestamp(),
                )
            )
        return tuple(anns)
