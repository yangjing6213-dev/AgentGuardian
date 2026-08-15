from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SensitiveModePolicy:
    """Fail-closed policy for an explicitly enabled high-sensitivity scan."""

    enabled: bool = False
    api_access: bool = False
    raw_persistence: bool = False
    export_requires_confirmation: bool = True

    def __post_init__(self) -> None:
        if any(
            type(value) is not bool
            for value in (
                self.enabled,
                self.api_access,
                self.raw_persistence,
                self.export_requires_confirmation,
            )
        ):
            raise ValueError("SENSITIVE_MODE_INVALID")
        if self.enabled and (
            self.api_access
            or self.raw_persistence
            or not self.export_requires_confirmation
        ):
            raise ValueError("SENSITIVE_MODE_INVALID")

    @classmethod
    def enabled_policy(cls) -> "SensitiveModePolicy":
        return cls(
            enabled=True,
            api_access=False,
            raw_persistence=False,
            export_requires_confirmation=True,
        )

    def validate_export(self, confirmed: bool) -> None:
        if type(confirmed) is not bool:
            raise ValueError("SENSITIVE_EXPORT_CONFIRMATION_INVALID")
        if self.enabled and self.export_requires_confirmation and not confirmed:
            raise PermissionError("SENSITIVE_EXPORT_CONFIRMATION_REQUIRED")
