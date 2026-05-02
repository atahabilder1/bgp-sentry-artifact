from typing import TYPE_CHECKING, Optional
import random

from bgpy.shared.enums import Prefixes, Relationships, Timestamps
from bgpy.simulation_framework.scenarios.custom_scenarios.victims_prefix import (
    VictimsPrefix,
)

if TYPE_CHECKING:
    from bgpy.simulation_engine import Announcement as Ann
    from bgpy.simulation_engine import BaseSimulationEngine


class RouteFlapping(VictimsPrefix):
    """Route flapping attack where attacker causes route instability

    Route flapping occurs when BGP routes oscillate between being
    available and unavailable, or when AS path attributes change
    frequently. This causes network instability and increased
    convergence time.

    In this scenario, the attacker announces the victim's prefix
    similar to a prefix hijack, but represents route instability.
    """

    def _get_announcements(
        self,
        *,
        engine: Optional["BaseSimulationEngine"] = None,
    ) -> tuple["Ann", ...]:
        """Returns victim and attacker announcements for route flapping

        The attacker announces the same prefix as victim, representing
        a flapping/unstable route scenario.
        """

        # First get the victim's announcements
        victim_anns = super()._get_announcements(engine=engine)
        assert isinstance(victim_anns, tuple), "mypy"

        # Add attacker announcements (route flapping attack)
        attacker_anns = list()
        for attacker_asn in self.attacker_asns:
            attacker_anns.append(
                self.scenario_config.AnnCls(
                    prefix=Prefixes.PREFIX.value,
                    as_path=(attacker_asn,),
                    timestamp=Timestamps.get_attacker_timestamp(),
                )
            )

        return victim_anns + tuple(attacker_anns)
