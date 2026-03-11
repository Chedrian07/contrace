from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from contrace.artifacts import ArtifactLayout
from contrace.errors import ContraceError, ExitCode
from contrace.intake import PreparedInput
from contrace.subprocess import CommandRunner

LOGGER = logging.getLogger(__name__)

PLATFORM_BY_ARCH = {
    "x86_64": "linux/amd64",
}


@dataclass(slots=True)
class ImageArtifacts:
    tag: str
    platform: str
    inspect_payload: list[dict[str, Any]]
    rootfs_tar: Path


class DockerImageBuilder:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    def build_and_export(
        self,
        prepared: PreparedInput,
        guest_arch: str,
        layout: ArtifactLayout,
    ) -> ImageArtifacts:
        if guest_arch not in PLATFORM_BY_ARCH:
            raise ContraceError(f"unsupported guest arch: {guest_arch}", ExitCode.INVALID_INPUT)

        tag = f"contrace-{uuid.uuid4().hex[:12]}"
        container_name = f"{tag}-ctr"
        platform = PLATFORM_BY_ARCH[guest_arch]

        LOGGER.info("building Docker image for %s", platform)
        build_result = self.runner.run(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                platform,
                "--load",
                "--tag",
                tag,
                str(prepared.source_root),
            ],
            cwd=prepared.source_root,
            check=False,
            exit_code=ExitCode.DOCKER_FAILURE,
        )
        layout.build_log.write_text(build_result.stdout + build_result.stderr, encoding="utf-8")
        if build_result.returncode != 0:
            raise ContraceError(
                f"docker buildx build failed; see {layout.build_log}",
                ExitCode.DOCKER_FAILURE,
            )

        inspect_result = self.runner.run(
            ["docker", "image", "inspect", tag],
            exit_code=ExitCode.DOCKER_FAILURE,
        )
        layout.inspect_json.write_text(inspect_result.stdout, encoding="utf-8")
        inspect_payload = json.loads(inspect_result.stdout)
        if not isinstance(inspect_payload, list) or not inspect_payload:
            raise ContraceError("docker inspect returned an unexpected payload", ExitCode.DOCKER_FAILURE)

        LOGGER.info("exporting Docker root filesystem")
        try:
            create_result = self.runner.run(
                ["docker", "create", "--name", container_name, tag],
                exit_code=ExitCode.DOCKER_FAILURE,
            )
            container_id = create_result.stdout.strip()
            if not container_id:
                raise ContraceError("docker create did not return a container id", ExitCode.DOCKER_FAILURE)
            self.runner.run_to_file(
                ["docker", "export", container_name],
                layout.rootfs_tar,
                exit_code=ExitCode.DOCKER_FAILURE,
            )
        finally:
            self.runner.run(
                ["docker", "rm", "-f", container_name],
                check=False,
                exit_code=ExitCode.DOCKER_FAILURE,
            )

        return ImageArtifacts(
            tag=tag,
            platform=platform,
            inspect_payload=inspect_payload,
            rootfs_tar=layout.rootfs_tar,
        )
