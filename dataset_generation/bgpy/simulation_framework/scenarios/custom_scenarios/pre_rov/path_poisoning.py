import random
from typing import TYPE_CHECKING, Optional

from bgpy.shared.enums import Prefixes, Timestamps
from bgpy.simulation_framework.scenarios.custom_scenarios.victims_prefix import (
    VictimsPrefix,
)

if TYPE_CHECKING:
    from bgpy.simulation_engine import Announcement as Ann
    from bgpy.simulation_engine import BaseSimulationEngine


class PathPoisoning(VictimsPrefix):
    """Path Poisoning Scenario

    The attacker announces the victim's prefix with a fabricated AS-path
    containing a phantom AS that has no CAIDA relationship with the attacker.
    The poisoned path is (attacker, phantom, victim), which introduces a
    forged adjacency (attacker -> phantom) detectable by the PATH_POISONING
    detector.
    """

    def _get_announcements(
        self,
        *,
        engine: Optional["BaseSimulationEngine"] = None,
    ) -> tuple["Ann", ...]:
        """Returns victim and attacker announcements for path poisoning"""

        # First get victim's announcements
        victim_anns = super()._get_announcements(engine=engine)
        assert isinstance(victim_anns, tuple), "mypy"
        attacker_anns = self._get_path_poisoning_attacker_anns(engine=engine)
        return victim_anns + attacker_anns

    def _get_path_poisoning_attacker_anns(
        self,
        *,
        engine: Optional["BaseSimulationEngine"] = None,
    ) -> tuple["Ann", ...]:
        """Returns attacker announcements with a poisoned AS-path

        The AS-path is (attacker_asn, phantom_asn, victim_asn) where
        phantom_asn has no CAIDA relationship with attacker_asn.
        Uses the same prefix as the victim (from override_announcements
        or Prefixes.PREFIX.value).
        """

        # Use the victim's actual prefix (from override_announcements if available)
        victim_prefix = Prefixes.PREFIX.value
        if self.scenario_config.override_announcements:
            victim_prefix = self.scenario_config.override_announcements[0].prefix

        anns = list()
        for attacker_asn in self.attacker_asns:
            phantom_asn = self._select_phantom_asn(attacker_asn, engine)
            # Use first victim ASN as the supposed origin
            victim_asn = next(iter(self.victim_asns))
            anns.append(
                self.scenario_config.AnnCls(
                    prefix=victim_prefix,
                    as_path=(attacker_asn, phantom_asn, victim_asn),
                    next_hop_asn=attacker_asn,
                    seed_asn=attacker_asn,
                    timestamp=Timestamps.get_attacker_timestamp(),
                )
            )
        return tuple(anns)

    def _select_phantom_asn(
        self,
        attacker_asn: int,
        engine: Optional["BaseSimulationEngine"],
    ) -> int:
        """Selects a phantom AS with no CAIDA relationship to the attacker

        The phantom AS must exist in the graph but have no customer, provider,
        or peer link with the attacker AS.
        """

        assert engine is not None, "Engine required to select phantom ASN"
        attacker_as = engine.as_graph.as_dict[attacker_asn]

        # All ASNs the attacker has a direct relationship with
        connected_asns = attacker_as.neighbor_asns | {attacker_asn}
        # Exclude victim ASNs as well — phantom should be a third party
        excluded = connected_asns | self.victim_asns

        all_asns = set(engine.as_graph.as_dict.keys())
        phantom_candidates = all_asns - excluded

        assert len(phantom_candidates) > 0, (
            f"No phantom ASN candidates for attacker {attacker_asn}"
        )
        return random.choice(sorted(phantom_candidates))
