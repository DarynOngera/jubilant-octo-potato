"""VulnForge error types."""


class VulnForgeError(Exception):
    """Base class for expected VulnForge failures."""


class ConfigError(VulnForgeError):
    """Invalid or missing factory configuration."""


class PackageError(VulnForgeError):
    """A vulnerability package could not be loaded or is structurally invalid."""


class SchemaError(VulnForgeError):
    """A schema or instance could not be validated."""


class LabError(VulnForgeError):
    """A lab could not be planned, built, started, or stopped."""
