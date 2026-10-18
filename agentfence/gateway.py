"""A single protected application path for reading reports."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Protocol


class InvalidProposal(ValueError):
    """The proposed tool call cannot be resolved from trusted records."""


class AuthorizationDenied(PermissionError):
    """The report read was not authorized."""


@dataclass(frozen=True, slots=True)
class ToolProposal:
    name: str
    arguments: Mapping[str, object]

    def __post_init__(self) -> None:
        # Snapshot the caller's mapping so later edits cannot change the proposal.
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))


@dataclass(frozen=True, slots=True)
class ActorRecord:
    actor_id: str
    region: str
    clearance_level: int


@dataclass(frozen=True, slots=True)
class ReportRecord:
    report_id: str
    resource_id: str
    region: str
    sensitivity_level: int
    body: str


@dataclass(frozen=True, slots=True)
class SubjectAttributes:
    region: str
    clearance_level: int


@dataclass(frozen=True, slots=True)
class ResourceAttributes:
    region: str
    sensitivity_level: int


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    subject_type: str
    subject_id: str
    object_type: str
    object_id: str
    relation: str
    subject_attributes: SubjectAttributes
    resource_attributes: ResourceAttributes


class Authorizer(Protocol):
    def authorize(self, request: AuthorizationRequest) -> bool: ...


class Resolver:
    """Resolve a proposal using an actor key supplied by trusted caller context."""

    def __init__(
        self,
        actors: Mapping[str, ActorRecord],
        reports: Mapping[str, ReportRecord],
    ) -> None:
        self._actors = MappingProxyType(dict(actors))
        self._reports = MappingProxyType(dict(reports))

    def resolve(
        self, trusted_actor_key: str, proposal: ToolProposal
    ) -> tuple[AuthorizationRequest, str]:
        if proposal.name != "read_report":
            raise InvalidProposal("unsupported tool")
        if len(proposal.arguments) != 1 or "report_id" not in proposal.arguments:
            raise InvalidProposal("read_report accepts only report_id")

        report_id = proposal.arguments["report_id"]
        if type(report_id) is not str or not report_id:
            raise InvalidProposal("report_id must be a nonempty string")

        actor = self._actors.get(trusted_actor_key)
        report = self._reports.get(report_id)
        if actor is None or report is None:
            raise InvalidProposal("unknown actor or report")

        request = AuthorizationRequest(
            subject_type="user",
            subject_id=actor.actor_id,
            object_type="report",
            object_id=report.resource_id,
            relation="viewer",
            subject_attributes=SubjectAttributes(actor.region, actor.clearance_level),
            resource_attributes=ResourceAttributes(report.region, report.sensitivity_level),
        )
        return request, report_id


class _ReadReportExecutor:
    """Execute and record reads; only Gateway invokes this class."""

    def __init__(self, reports: Mapping[str, ReportRecord]) -> None:
        self._reports = MappingProxyType(dict(reports))
        self._calls: list[str] = []

    def read_report(self, report_id: str) -> str:
        self._calls.append(report_id)
        return self._reports[report_id].body

    @property
    def calls(self) -> tuple[str, ...]:
        return tuple(self._calls)


class Gateway:
    """Application entrypoint for protected report reads."""

    def __init__(
        self,
        actors: Mapping[str, ActorRecord],
        reports: Mapping[str, ReportRecord],
        authorizer: Authorizer,
    ) -> None:
        # Both components receive the same trusted record snapshot.
        trusted_actors = dict(actors)
        trusted_reports = dict(reports)
        self._resolver = Resolver(trusted_actors, trusted_reports)
        self._executor = _ReadReportExecutor(trusted_reports)
        self._authorizer = authorizer

    def execute(self, trusted_actor_key: str, proposal: ToolProposal) -> str:
        request, report_id = self._resolver.resolve(trusted_actor_key, proposal)
        try:
            allowed = self._authorizer.authorize(request)
        except Exception as exc:
            raise AuthorizationDenied("authorization failed") from exc
        if allowed is not True:
            raise AuthorizationDenied("report read denied")
        return self._executor.read_report(report_id)

    @property
    def execution_log(self) -> tuple[str, ...]:
        return self._executor.calls
