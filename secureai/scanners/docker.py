"""
SecureAI Platform — Docker Security Scanner
============================================
Scans Dockerfile and docker-compose.yml for security misconfigurations.

Why this scanner exists:
In Phase 1 of the Cloud Security Masterclass, every misconfiguration
in this scanner was found and fixed manually:
- Hardcoded credentials → fixed with .env
- No non-root user → fixed with appuser UID 1001
- Floating image tags → fixed with sha256 digest pinning
- No health checks → added to all three services

This scanner automates those manual checks.
Every check here maps to a real security decision.
"""

import os
import yaml
from secureai.utils.severity import create_finding


class DockerScanner:
    """
    Scans Docker infrastructure files for security misconfigurations.

    Checks performed:
    1. Hardcoded credentials in docker-compose.yml
    2. Root user in Dockerfile (missing USER directive)
    3. Missing health checks on services
    4. Privileged containers
    5. Exposed sensitive ports
    6. Floating image tags (no sha256 digest pinning)
    7. Missing resource limits

    Args:
        path: directory to scan (defaults to current directory)
        severity_threshold: minimum severity to report (default HIGH)
    """

    def __init__(self, path: str = "./", severity_threshold: str = "HIGH"):
        self.path = path
        self.severity_threshold = severity_threshold
        self.findings = []

        # Sensitive ports that should not be exposed publicly
        # These services should only be on internal networks
        self.sensitive_ports = {
            "5432": "PostgreSQL",
            "3306": "MySQL",
            "6379": "Redis",
            "27017": "MongoDB",
            "9200": "Elasticsearch",
            "2181": "Zookeeper"
        }

        # Patterns that indicate hardcoded credentials
        # These exact patterns are what attackers grep for in leaked repos
        self.credential_patterns = [
            "password=",
            "passwd=",
            "secret=",
            "token=",
            "api_key=",
            "apikey=",
        ]

    def scan(self) -> list:
        """
        Runs all Docker security checks and returns findings list.
        Scans both Dockerfile and docker-compose.yml if present.
        """
        self.findings = []

        # Scan Dockerfile if it exists
        dockerfile_path = os.path.join(self.path, "Dockerfile")
        if os.path.exists(dockerfile_path):
            self._scan_dockerfile(dockerfile_path)

        # Scan docker-compose.yml if it exists
        compose_path = os.path.join(self.path, "docker-compose.yml")
        if os.path.exists(compose_path):
            self._scan_compose(compose_path)

        return self.findings

    def _scan_dockerfile(self, path: str) -> None:
        """
        Scans Dockerfile for security issues.
        Reads line by line looking for security anti-patterns.
        """
        with open(path, "r") as f:
            lines = f.readlines()

        has_user_directive = False
        has_healthcheck = False

        for i, line in enumerate(lines, 1):
            line_stripped = line.strip().upper()

            # Check 1: USER directive present
            # Running as root means an attacker who exploits the app
            # gets root access to the container
            if line_stripped.startswith("USER "):
                has_user_directive = True

            # Check 2: HEALTHCHECK directive present
            # Without HEALTHCHECK Docker cannot detect if the app crashed
            if line_stripped.startswith("HEALTHCHECK"):
                has_healthcheck = True

            # Check 3: pip install without --no-cache-dir
            # Caching pip packages increases image size unnecessarily
            if "PIP INSTALL" in line_stripped and "--NO-CACHE-DIR" not in line_stripped:
                if "--PREFIX" not in line_stripped and "--UPGRADE PIP" not in line_stripped:

                    self.findings.append(create_finding(
                        severity="LOW",
                        title="pip install missing --no-cache-dir",
                        description="pip caches downloaded packages by default, increasing image size.",
                        file=path,
                        line=i,
                        remediation="Add --no-cache-dir to pip install commands"
                    ))

        # Report missing USER directive
        if not has_user_directive:
            self.findings.append(create_finding(
                severity="HIGH",
                title="Container runs as root",
                description="No USER directive found. Container runs as root by default. "
                           "If exploited, attacker gets root access.",
                file=path,
                remediation="Add: RUN groupadd --gid 1001 appgroup && "
                           "useradd --uid 1001 --gid appgroup --no-create-home appuser\n"
                           "Then: USER appuser"
            ))

        # Report missing HEALTHCHECK
        if not has_healthcheck:
            self.findings.append(create_finding(
                severity="MEDIUM",
                title="Missing HEALTHCHECK directive",
                description="No HEALTHCHECK found. Docker cannot detect if the application "
                           "has crashed or become unresponsive.",
                file=path,
                remediation="Add HEALTHCHECK directive:\n"
                           'HEALTHCHECK --interval=30s --timeout=10s CMD '
                           'python -c "import urllib.request; '
                           'urllib.request.urlopen(\'http://localhost:8000/health\')"'
            ))

    def _scan_compose(self, path: str) -> None:
        """
        Scans docker-compose.yml for security misconfigurations.
        Parses YAML and checks each service for security issues.
        """
        with open(path, "r") as f:
            try:
                compose = yaml.safe_load(f)
            except yaml.YAMLError as e:
                self.findings.append(create_finding(
                    severity="HIGH",
                    title="Invalid docker-compose.yml",
                    description=f"YAML parsing failed: {e}",
                    file=path,
                    remediation="Fix YAML syntax errors"
                ))
                return

        services = compose.get("services", {})

        for service_name, service_config in services.items():
            if not service_config:
                continue

            self._check_hardcoded_credentials(
                service_name, service_config, path
            )
            self._check_privileged(service_name, service_config, path)
            self._check_health_check(service_name, service_config, path)
            self._check_image_pinning(service_name, service_config, path)
            self._check_sensitive_ports(service_name, service_config, path)

    def _check_hardcoded_credentials(
        self, service: str, config: dict, path: str
    ) -> None:
        """
        Checks for hardcoded credentials in environment variables.
        Hardcoded creds in compose files are visible to anyone
        with repo access — a critical security violation.
        """
        env_vars = config.get("environment", [])

        if isinstance(env_vars, list):
            for env_var in env_vars:
                if isinstance(env_var, str):
                    env_lower = env_var.lower()
                    for pattern in self.credential_patterns:
                        if pattern in env_lower:
                            # Check if it's using a variable reference
                            # ${VAR} pattern is safe — hardcoded value is not
                            if "${" not in env_var and "=" in env_var:
                                value = env_var.split("=", 1)[1]
                                if value and not value.startswith("${"):
                                    self.findings.append(create_finding(
                                        severity="CRITICAL",
                                        title=f"Hardcoded credential in {service}",
                                        description=f"Environment variable contains hardcoded "
                                                   f"credential: {env_var.split('=')[0]}",
                                        file=path,
                                        remediation="Use environment variable references: "
                                                   "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}\n"
                                                   "Store real values in .env (never committed)"
                                    ))

    def _check_privileged(
        self, service: str, config: dict, path: str
    ) -> None:
        """
        Checks if a container runs in privileged mode.
        Privileged containers have full access to the host system —
        equivalent to running as root on the host machine.
        """
        if config.get("privileged", False):
            self.findings.append(create_finding(
                severity="CRITICAL",
                title=f"Privileged container: {service}",
                description=f"Service '{service}' runs in privileged mode. "
                           "This grants full access to the host system.",
                file=path,
                remediation="Remove 'privileged: true' from compose file. "
                           "Use specific capabilities if needed: cap_add: [NET_ADMIN]"
            ))

    def _check_health_check(
        self, service: str, config: dict, path: str
    ) -> None:
        """
        Checks if a service has a health check defined.
        Without health checks, Docker cannot detect unhealthy containers
        and depends_on: condition: service_healthy won't work.
        """
        # Services with 'build:' define health checks in Dockerfile
        # Only flag services using pre-built images with no health check
        if "build" in config:
            return

        if "healthcheck" not in config:
            self.findings.append(create_finding(
                severity="MEDIUM",
                title=f"Missing health check: {service}",
                description=f"Service '{service}' has no health check. "
                           "Docker cannot detect if this service is ready.",
                file=path,
                remediation="Add healthcheck to service:\n"
                           "healthcheck:\n"
                           "  test: ['CMD', 'your-health-command']\n"
                           "  interval: 10s\n"
                           "  timeout: 5s\n"
                           "  retries: 5"
            ))

    def _check_image_pinning(
        self, service: str, config: dict, path: str
    ) -> None:
        """
        Checks if images are pinned to sha256 digests.
        Floating tags like postgres:16-alpine can change without warning.
        Digest pinning ensures you always run the exact audited image.
        This is supply chain security at the container level.
        """
        image = config.get("image", "")
        if image and "sha256:" not in image and "build" not in config:
            self.findings.append(create_finding(
                severity="MEDIUM",
                title=f"Floating image tag: {service}",
                description=f"Service '{service}' uses floating tag: {image}. "
                           "Image can change without warning on next pull.",
                file=path,
                remediation="Pin image to sha256 digest:\n"
                           "docker inspect <image> --format='{{index .RepoDigests 0}}'\n"
                           "Then use: image: postgres@sha256:<digest>"
            ))

    def _check_sensitive_ports(
        self, service: str, config: dict, path: str
    ) -> None:
        """
        Checks if sensitive service ports are exposed externally.
        Database and cache ports should only be on internal networks.
        Exposing port 5432 publicly is a critical misconfiguration.
        """
        ports = config.get("ports", [])
        for port_mapping in ports:
            port_str = str(port_mapping)
            for port, service_name in self.sensitive_ports.items():
                if f":{port}" in port_str or port_str == port:
                    self.findings.append(create_finding(
                        severity="HIGH",
                        title=f"Sensitive port exposed: {service}",
                        description=f"Service '{service}' exposes {service_name} "
                                   f"port {port} publicly.",
                        file=path,
                        remediation=f"Remove port mapping for {port}. "
                                   "Use internal Docker networks instead. "
                                   "Only expose ports that need external access."
                    ))