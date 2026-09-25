"""HTTP transport client for Open Policy Agent (OPA).

Sends canonical CagePolicyInput to OPA and returns structured OpaEvaluationResult.
Does NOT synthesize failures into policy findings; preserves infrastructure status.
"""

import logging
from typing import Any

import httpx
from pydantic import ValidationError

from app.core.config import settings
from app.schemas.enums import OpaStatus
from app.schemas.policy import CagePolicyInput, OpaEvaluationResult, OpaFinding

logger = logging.getLogger("cage.opa_client")


class OpaClient:
    """Client for evaluating declarative policies in Open Policy Agent."""

    def __init__(
        self,
        opa_url: str | None = None,
        timeout_seconds: float | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self.opa_url = (opa_url or settings.opa_url).rstrip("/")
        self.timeout_seconds = (
            timeout_seconds if timeout_seconds is not None else settings.opa_timeout_seconds
        )
        self._custom_client = client

    def _get_client(self) -> httpx.Client:
        if self._custom_client is not None:
            return self._custom_client
        return httpx.Client(timeout=self.timeout_seconds)

    def evaluate(self, policy_input: CagePolicyInput) -> OpaEvaluationResult:
        """Send canonical CagePolicyInput to OPA for policy evaluation.

        Returns OpaEvaluationResult with precise status (SUCCESS, TIMEOUT, UNAVAILABLE,
        INVALID_RESPONSE, EVALUATION_ERROR) and genuine Rego findings on success.
        """
        url = f"{self.opa_url}/v1/data/cage/authorization"
        payload = {"input": policy_input.model_dump()}

        try:
            client = self._get_client()
            # If using internal temporary client, use context manager
            if self._custom_client is None:
                with client:
                    response = client.post(url, json=payload)
            else:
                response = client.post(url, json=payload)

            if response.status_code != 200:
                logger.error("OPA returned non-200 status code: %d", response.status_code)
                return OpaEvaluationResult(
                    status=OpaStatus.EVALUATION_ERROR,
                    findings=[],
                    error_reason=f"OPA returned HTTP {response.status_code}: {response.text[:200]}",
                )

            try:
                data: dict[str, Any] = response.json()
            except Exception as e:
                logger.error("Failed to parse OPA JSON response: %s", e)
                return OpaEvaluationResult(
                    status=OpaStatus.INVALID_RESPONSE,
                    findings=[],
                    error_reason=f"OPA returned malformed JSON: {e}",
                )

            # OPA format: {"result": {"findings": [...]}}
            result_obj = data.get("result")
            if result_obj is None:
                logger.error("OPA response missing 'result' object: %s", data)
                return OpaEvaluationResult(
                    status=OpaStatus.INVALID_RESPONSE,
                    findings=[],
                    error_reason="OPA response missing 'result' wrapper.",
                )

            raw_findings = result_obj.get("findings")
            if raw_findings is None:
                logger.error("OPA result missing 'findings' array: %s", result_obj)
                return OpaEvaluationResult(
                    status=OpaStatus.INVALID_RESPONSE,
                    findings=[],
                    error_reason="OPA response missing 'findings' array.",
                )

            # Invariant 9: Every valid OPA evaluation must emit at least one finding
            if not isinstance(raw_findings, list) or len(raw_findings) == 0:
                logger.warning("OPA returned empty findings list.")
                return OpaEvaluationResult(
                    status=OpaStatus.INVALID_RESPONSE,
                    findings=[],
                    error_reason="OPA returned empty findings list. Valid evaluations must emit at least one baseline finding.",
                )

            # Validate each finding against schema
            parsed_findings: list[OpaFinding] = []
            for idx, item in enumerate(raw_findings):
                try:
                    finding = OpaFinding.model_validate(item)
                    parsed_findings.append(finding)
                except ValidationError as ve:
                    logger.error("OPA finding at index %d failed validation: %s", idx, ve)
                    return OpaEvaluationResult(
                        status=OpaStatus.INVALID_RESPONSE,
                        findings=[],
                        error_reason=f"OPA finding at index {idx} failed schema validation: {ve}",
                    )

            return OpaEvaluationResult(
                status=OpaStatus.SUCCESS,
                findings=parsed_findings,
                error_reason=None,
            )

        except httpx.TimeoutException as e:
            logger.warning("OPA request timed out after %.2fs: %s", self.timeout_seconds, e)
            return OpaEvaluationResult(
                status=OpaStatus.TIMEOUT,
                findings=[],
                error_reason=f"OPA request timed out after {self.timeout_seconds}s.",
            )
        except httpx.ConnectError as e:
            logger.warning("Failed to connect to OPA at %s: %s", self.opa_url, e)
            return OpaEvaluationResult(
                status=OpaStatus.UNAVAILABLE,
                findings=[],
                error_reason=f"OPA connection refused at {self.opa_url}.",
            )
        except Exception as e:
            logger.exception("Unexpected error communicating with OPA: %s", e)
            return OpaEvaluationResult(
                status=OpaStatus.EVALUATION_ERROR,
                findings=[],
                error_reason=f"Unexpected transport error: {e}",
            )

    def check_health(self) -> bool:
        """Check if OPA server is reachable and healthy."""
        try:
            client = self._get_client()
            url = f"{self.opa_url}/health"
            if self._custom_client is None:
                with client:
                    resp = client.get(url, timeout=1.0)
            else:
                resp = client.get(url, timeout=1.0)
            return resp.status_code == 200
        except Exception:
            return False


# Global default instance
default_opa_client = OpaClient()
