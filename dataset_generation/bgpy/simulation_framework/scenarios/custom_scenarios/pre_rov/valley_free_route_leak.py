import warnings
from typing import TYPE_CHECKING, Optional

from bgpy.as_graphs.base.as_graph.customer_cone_funcs import _get_cone_size_helper
from bgpy.shared.constants import bgpy_logger
from bgpy.shared.enums import (
    ASGroups,
    Relationships,
    SpecialPercentAdoptions,
    Timestamps,
)
from bgpy.simulation_framework.scenarios.scenario_config import ScenarioConfig

from ..victims_prefix import VictimsPrefix

if TYPE_CHECKING:
    from bgpy.simulation_engine import Announcement as Ann
    from bgpy.simulation_engine import BaseSimulationEngine


class ValleyFreeRouteLeak(VictimsPrefix):
    """A valley-free route leak of a valid prefix

    A valley-free route leak occurs when a customer AS receives a route
    from its provider (or peer) and re-announces it upward to another
    provider (or peer), violating the Gao-Rexford valley-free routing policy.

    This is similar to AccidentalRouteLeak but specifically targets transit
    ASes (ASes with both providers and customers) as attackers, since stubs
    cannot meaningfully perform a valley-free leak.
    """

    min_propagation_rounds: int = 2

    def __init__(
        self,
        *,
        scenario_config: ScenarioConfig,
        percent_adoption: float | SpecialPercentAdoptions = 0,
        engine: Optional["BaseSimulationEngine"] = None,
        attacker_asns: frozenset[int] | None = None,
        victim_asns: frozenset[int] | None = None,
        adopting_asns: frozenset[int] | None = None,
    ):
        assert engine, "Need engine for customer cones"
        self._attackers_customer_cones_asns: set[int] = set()
        super().__init__(
            scenario_config=scenario_config,
            percent_adoption=percent_adoption,
            engine=engine,
            attacker_asns=attacker_asns,
            victim_asns=victim_asns,
            adopting_asns=adopting_asns,
        )
        self.validate_attacker_subcategory()

    def validate_attacker_subcategory(self) -> None:
        """Validates that the attacker's subcategory/ASGroup can leak"""

        if (
            self.scenario_config.attacker_subcategory_attr in self.warning_as_groups
            and not self.scenario_config.override_attacker_asns
        ):
            msg = (
                "You used the ASGroup of "
                f"{self.scenario_config.attacker_subcategory_attr} "
                f"for your scenario {self.__class__.__name__}, "
                f"but {self.__class__.__name__} can't leak from stubs. "
                "To suppress this warning, override warning_as_groups. "
                "To change the ASGroup to something other than stubs, you can "
                " set attacker_subcategory_attr=ASGroups.TRANSIT.value, "
                " in the scenario config after importing like "
                "from bgpy.shared.enums import ASGroups"
            )
            warnings.warn(msg, RuntimeWarning, stacklevel=2)

    # Just returns customer cone
    _get_cone_size_helper = _get_cone_size_helper

    def post_propagation_hook(
        self,
        engine: "BaseSimulationEngine",
        percent_adopt: float | SpecialPercentAdoptions,
        trial: int,
        propagation_round: int,
    ) -> None:
        """Causes a valley-free route leak

        Changes the valid prefix to be received from a customer
        so that in the second propagation round, the AS will export to all
        relationships (including providers and peers), violating valley-free.

        The attacker (a transit AS) receives a route from a provider or peer,
        then re-seeds it as ORIGIN so it propagates to all neighbors.
        """

        if propagation_round == 0:
            announcements: list[Ann] = list(self.announcements)
            assert self.attacker_asns, "You must select at least 1 AS to leak"
            for attacker_asn in self.attacker_asns:
                if not engine.as_graph.as_dict[attacker_asn].policy.local_rib:
                    bgpy_logger.warning(
                        "Attacker did not recieve announcement, can't leak."
                    )
                for _prefix, ann in engine.as_graph.as_dict[
                    attacker_asn
                ].policy.local_rib.items():
                    announcements.append(
                        ann.copy(
                            {
                                "recv_relationship": Relationships.ORIGIN,
                                "seed_asn": attacker_asn,
                                "timestamp": Timestamps.ATTACKER.value,
                            }
                        )
                    )
            self.announcements = tuple(announcements)
            self.setup_engine(engine)
            engine.ready_to_run_round = 1
        elif propagation_round > 1:
            raise NotImplementedError

    def _get_attacker_asns(
        self,
        override_attacker_asns: frozenset[int] | None,
        attacker_asns: frozenset[int] | None,
        engine: Optional["BaseSimulationEngine"],
    ) -> frozenset[int]:
        """Gets attacker ASNs, preferring transit ASes

        Transit ASes have both providers and customers, making them
        capable of performing a valley-free route leak by re-announcing
        a route received from a provider to another provider or peer.
        """

        assert engine, "Need engine for attacker customer cones"
        attacker_asns = super()._get_attacker_asns(
            override_attacker_asns, attacker_asns, engine
        )
        # Stores customer cones of attacker ASNs
        # used in untrackable func and when selecting victims
        for attacker_asn in attacker_asns:
            self._attackers_customer_cones_asns.update(
                self._get_cone_size_helper(
                    engine.as_graph.as_dict[attacker_asn],
                    dict(),
                ),
            )
        return attacker_asns

    def _get_possible_victim_asns(
        self,
        engine: "BaseSimulationEngine",
        percent_adoption: float | SpecialPercentAdoptions,
    ) -> frozenset[int]:
        """Returns possible victim ASNs, defaulted from config

        Modified to not allow victims to be in attackers customer cone,
        since if a victim is the customer of leaker, it's not really a leak
        """

        possible_asns = super()._get_possible_victim_asns(engine, percent_adoption)
        # Remove attacker's customer cones from possible victims
        possible_asns = possible_asns.difference(self._attackers_customer_cones_asns)
        return possible_asns

    @property
    def warning_as_groups(self) -> frozenset[str]:
        """Returns a frozenset of ASGroups that should raise a warning"""

        return frozenset(
            [
                ASGroups.STUBS_OR_MH.value,
                ASGroups.STUBS.value,
                ASGroups.ALL_WOUT_IXPS.value,
            ]
        )

    @property
    def _untracked_asns(self) -> frozenset[int]:
        """Returns ASNs that shouldn't be tracked by the metric tracker

        By default just the default adopters and non adopters
        however for the route leak, we don't want to track the customers of the
        leaker, since you can not "leak" to your own customers
        """

        return super()._untracked_asns | self._attackers_customer_cones_asns
