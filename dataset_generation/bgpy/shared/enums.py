from enum import Enum, unique

yamlable_enums: list[type["YamlAbleEnum"]] = []


# Yaml must have unique keys/values
@unique
class YamlAbleEnum(Enum):
    def __init_subclass__(cls: type["YamlAbleEnum"], *args, **kwargs) -> None:
        """This method essentially creates a list of all subclasses

        This is used later in the yaml codec
        """

        super().__init_subclass__(*args, **kwargs)
        yamlable_enums.append(cls)

    @classmethod
    def yaml_suffix(cls: type["YamlAbleEnum"]) -> str:
        return cls.__name__

    @staticmethod
    def yamlable_enums() -> list[type["YamlAbleEnum"]]:
        return yamlable_enums


class Outcomes(YamlAbleEnum):
    ATTACKER_SUCCESS: int = 0
    VICTIM_SUCCESS: int = 1
    DISCONNECTED: int = 2
    UNDETERMINED: int = 3
    DATA_PLANE_LOOP: int = 4


class Relationships(YamlAbleEnum):
    # Must start at one for the priority
    PROVIDERS: int = 1
    PEERS: int = 2
    # Customers have highest priority
    # Economic incentives first!
    CUSTOMERS: int = 3
    # Origin must always remain
    ORIGIN: int = 4
    # Unknown for external programs like extrapoaltor
    UNKNOWN: int = 5


class Plane(YamlAbleEnum):
    # Changing to integers so that this is compatible with c++
    DATA: int = 0  # "data_plane"
    CTRL: int = 1  # "control_plane"


class ROAValidity(YamlAbleEnum):
    """Possible values for ROA Validity

    Note that we cannot differentiate between
    invalid by origin or max length
    because you could get one that is invalid by origin for one roa
    and invalid by max length for another roa
    """

    VALID: int = 0
    UNKNOWN: int = 1
    INVALID: int = 2


# Module-level storage for base timestamp (used by Timestamps class)
_bgp_simulation_base_timestamp: int | None = None


class Timestamps(YamlAbleEnum):
    """Different timestamps to use

    Supports both legacy (0, 1) and realistic Unix timestamps.
    For BGPSentry and realistic simulations, use the generator methods.
    """

    # Legacy values for backwards compatibility
    VICTIM: int = 0
    ATTACKER: int = 1

    @staticmethod
    def set_base_timestamp(timestamp: int | None = None) -> None:
        """Set the base timestamp for realistic timing

        Args:
            timestamp: Unix timestamp to use as base (default: current time)
        """
        import time
        global _bgp_simulation_base_timestamp
        _bgp_simulation_base_timestamp = timestamp if timestamp is not None else int(time.time())

    @staticmethod
    def get_base_timestamp() -> int:
        """Get the base timestamp, initializing if needed"""
        global _bgp_simulation_base_timestamp
        if _bgp_simulation_base_timestamp is None:
            Timestamps.set_base_timestamp()
        return _bgp_simulation_base_timestamp

    @staticmethod
    def reset_base_timestamp() -> None:
        """Reset base timestamp (useful for multiple simulations)"""
        global _bgp_simulation_base_timestamp
        _bgp_simulation_base_timestamp = None

    @staticmethod
    def get_victim_timestamp(base_time: int | None = None) -> int:
        """Generate realistic victim announcement timestamp

        Victims announce early (0-5 minutes after base time).
        This represents normal BGP route establishment.

        Args:
            base_time: Base Unix timestamp (default: use module base_timestamp)

        Returns:
            Unix timestamp for victim announcement
        """
        import random
        if base_time is None:
            base_time = Timestamps.get_base_timestamp()
        # Victim announces early: 0-5 minutes (0-300 seconds)
        return base_time + random.randint(0, 300)

    @staticmethod
    def get_attacker_timestamp(base_time: int | None = None) -> int:
        """Generate realistic attacker announcement timestamp

        Attackers announce later (10-30 minutes after base time).
        This represents hijack happening after legitimate routes.

        Args:
            base_time: Base Unix timestamp (default: use module base_timestamp)

        Returns:
            Unix timestamp for attacker announcement
        """
        import random
        if base_time is None:
            base_time = Timestamps.get_base_timestamp()
        # Attacker announces later: 10-30 minutes (600-1800 seconds)
        return base_time + random.randint(600, 1800)


class Prefixes(YamlAbleEnum):
    """Prefixes to use for attacks

    prefix always belongs to the victim
    """

    SUPERPREFIX: str = "1.0.0.0/8"
    # Prefix always belongs to victim
    PREFIX: str = "1.2.0.0/16"
    SUBPREFIX: str = "1.2.3.0/24"
    # Bogon prefix (RFC 1918 private address space - should never appear in BGP)
    BOGON_PREFIX: str = "10.0.0.0/8"


class ASNs(YamlAbleEnum):
    """Default ASNs for various ASNs"""

    ATTACKER: int = 666
    VICTIM: int = 777


class ASGroups(YamlAbleEnum):
    """AS types"""

    IXPS: str = "ixp"
    # NOTE: only the IXP group has IXPs
    STUBS: str = "stub"
    MULTIHOMED: str = "multihomed"
    STUBS_OR_MH: str = "stub_or_multihomed"
    INPUT_CLIQUE: str = "input_clique"
    # Not stubs, multihomed, or input clique
    ETC: str = "etc"
    # not stubs or multihomed
    TRANSIT: str = "transit"
    ALL_WOUT_IXPS: str = "all_wout_ixps"


class SpecialPercentAdoptions(YamlAbleEnum):
    ALL_BUT_ONE: float = 1
    ONLY_ONE: float = 0

    def __float__(self) -> float:
        return float(self.value)

    def __lt__(self, other):
        if isinstance(other, (SpecialPercentAdoptions, float)):
            return float(self) == float(other)
        else:
            return NotImplemented


class InAdoptingASNs(YamlAbleEnum):
    TRUE: str = "True"
    FALSE: str = "False"
    ANY: str = "Any"
