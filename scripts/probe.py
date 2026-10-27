"""Disposable live protocol probe. Emits outcomes, never credentials or bodies."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


http = urllib.request.build_opener(NoRedirect)


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def emit(event, **facts):
    print(json.dumps({"event": event, "at": time.time(), **facts}), flush=True)


def call(url, token=None, form=None, binary=False):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with http.open(request, timeout=20) as response:
            status, raw = response.status, response.read(2_000_000)
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read(2_000_000)
    except Exception:
        raise RuntimeError("transport_failure") from None
    if binary:
        return status, raw
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        payload = None
    return status, payload


def publication(phase, origin, resource_path, token):
    if phase == "withdrawal-regrant":
        return
    match = re.fullmatch(r"/v1/extensions/(@[a-z0-9_-]+)/skills/([a-z0-9_-]+)/0\.0\.1",
                         urllib.parse.unquote(resource_path))
    require(match is not None, "publication_resource_must_be_exact_skill_version")
    owner, name = match.groups()
    source = base64.b64decode(os.environ.get("ACCEPTANCE_SKILL_SOURCE", ""), validate=True)
    require(bool(source) and hashlib.sha256(source).hexdigest() ==
            os.environ.get("ACCEPTANCE_SKILL_SHA256"), "publication_source_digest_mismatch")
    target = resource_path.rsplit("/", 1)[0] + "/0.0.2"
    require(call(origin + target, token)[0] == 404, "publication_version_already_exists")
    executable = Path(os.environ["RUNNER_TEMP"]) / "acceptance-cli/axm"
    require(executable.is_file(), "pinned_cli_missing")
    with tempfile.TemporaryDirectory(prefix="workload-publication-") as temporary:
        root = Path(temporary)
        payload = root / "source"
        payload.mkdir()
        (payload / "SKILL.md").write_bytes(source)
        (root / "axm.json").write_text(json.dumps({
            "defaultRegistry": "acceptance",
            "sources": [{"name": "acceptance", "type": "registry", "location": origin}],
        }))
        env = dict(os.environ, AXM_USER_HOME=str(root / "home"), AXM_TELEMETRY="0",
                   AXM_NO_UPDATE_CHECK="1", AXM_TRUSTED_PUBLISHING="1")
        env.pop("AXM_TOKEN", None)
        env.pop("AXM_TOKEN_FILE", None)

        def cli(arguments):
            completed = subprocess.run([str(executable), *arguments, "--json", "--non-interactive"],
                                       cwd=root, env=env, capture_output=True, text=True, timeout=120)
            if completed.returncode != 0:
                label = "lint" if arguments == ["lint"] else "publication"
                emit("cli_operation_refused", stage=label, exit_code=completed.returncode,
                     json_output=completed.stdout.lstrip().startswith("{"),
                     stderr_present=bool(completed.stderr))
                try:
                    failure = json.loads(completed.stdout)
                    code = failure.get("error", {}).get("code")
                    if code in ("issues", "usage", "not_found", "auth", "forbidden", "conflict",
                                "rate_limit", "network", "validation", "internal", "unavailable",
                                "quota", "auth_required", "auth_expired", "auth_denied", "timeout"):
                        emit("cli_error_category", code=code)
                except (ValueError, AttributeError):
                    pass
                for marker in ("Cannot find module", "ERR_MODULE_NOT_FOUND", "SyntaxError",
                               "TypeError", "ENOENT", "EACCES", "certificate", "OIDC", "audience"):
                    if marker in completed.stderr:
                        emit("cli_runtime_marker", marker=marker)
                raise RuntimeError("cli_operation_failed_output_withheld")
            document = json.loads(completed.stdout)
            require(document.get("ok") is True and isinstance(document.get("result"), dict),
                    "cli_result_envelope_invalid")
            return document["result"]

        cli(["lint"])
        arguments = ["publish", owner + "/skills/" + name, "--path", str(payload),
                     "--package-version", "0.0.2", "--visibility", "private", "--registry", origin]
        preview = cli([*arguments, "--preview"])
        require(preview.get("contract") == "publish-result-v3" and preview.get("mode") == "preview"
                and preview["publicationSet"]["status"] == "admitted"
                and len(preview["publicationSet"]["items"]) == 1,
                "publication_preview_not_admitted")
        outcomes = preview["execution"]["outcomes"]
        require(len(outcomes) == 1 and outcomes[0]["action"] == "publish",
                "publication_preview_not_single_new_version")
        integrity = outcomes[0]["archive"]["integrity"]
        emit("cli_publication_preview_passed", phase=phase, version="0.0.2")
        if phase == "baseline":
            return
        applied = cli(arguments)
        outcomes = applied["execution"]["outcomes"]
        require(applied.get("mode") == "apply" and applied["execution"]["status"] == "completed"
                and len(outcomes) == 1 and outcomes[0]["action"] == "publish"
                and outcomes[0]["status"] == "success"
                and outcomes[0]["archive"]["integrity"] == integrity,
                "publication_did_not_commit_exact_preview")
        status, metadata = call(origin + target, token)
        require(status == 200 and metadata.get("integrity") == integrity,
                "published_version_readback_failed")
        status, archive = call(origin + target + "/archive", token, binary=True)
        require(status == 200 and "sha512-" + base64.b64encode(hashlib.sha512(archive).digest()).decode()
                == integrity, "published_archive_integrity_failed")
        require(call(origin + target)[0] == 404 and call(origin + target + "/archive")[0] == 404,
                "published_private_version_exposed")
        emit("cli_publication_and_integrity_passed", phase=phase, version="0.0.2")


def run():
    origin = os.environ.get("ACCEPTANCE_REGISTRY_ORIGIN", "").rstrip("/")
    parsed = urllib.parse.urlsplit(origin)
    require(parsed.scheme == "https" and bool(parsed.hostname)
            and not parsed.username and not parsed.password
            and not parsed.path and not parsed.query and not parsed.fragment,
            "registry_origin_must_be_exact_https_origin")
    paths = [os.environ.get(key, "") for key in
             ("ACCEPTANCE_RESOURCE_PATH", "ACCEPTANCE_DENIED_PATH")]
    require(all(path.startswith("/") and not path.startswith("//") for path in paths)
            and paths[0] != paths[1], "two_distinct_relative_resource_paths_required")
    phase = os.environ.get("ACCEPTANCE_PHASE", "")
    require(phase in ("baseline", "after-departure", "withdrawal-regrant", "personal-boundaries"), "invalid_phase")
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    issuer_url = urllib.parse.urlsplit(request_url)
    require(issuer_url.scheme == "https" and bool(issuer_url.hostname)
            and issuer_url.hostname.endswith(".githubusercontent.com"), "unexpected_oidc_request_origin")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    require(bool(request_token), "missing_oidc_request_credential")

    def subject(audience):
        separator = "&" if "?" in request_url else "?"
        status, payload = call(request_url + separator + urllib.parse.urlencode({"audience": audience}), request_token)
        require(status == 200 and isinstance(payload, dict)
                and isinstance(payload.get("value"), str), "oidc_issuance_failed")
        return payload["value"]

    def exchange(jwt):
        return call(origin + "/v1/auth/token", form={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "subject_token": jwt, "audience": origin, "expires_in": "900",
        })

    def access(payload):
        require(isinstance(payload, dict) and isinstance(payload.get("access_token"), str)
                and payload.get("token_type") == "Bearer"
                and not payload.get("refresh_token"), "invalid_workload_token_response")
        lifetime = payload.get("expires_in")
        require(isinstance(lifetime, int) and 600 <= lifetime <= 900, "unexpected_workload_lifetime")
        return payload["access_token"], lifetime

    require(call(origin + paths[0])[0] == 404, "fixture_must_be_private")
    jwt = subject(origin)
    status, payload = exchange(jwt)
    require(status == 200, "initial_exchange_failed")
    token, lifetime = access(payload)
    issued = time.monotonic()
    require(call(origin + paths[0], token)[0] == 200, "granted_resource_refused")
    require(call(origin + paths[1], token)[0] in (401, 403, 404), "ungranted_resource_not_denied")
    if phase == "personal-boundaries":
        status, identity = call(origin + "/v1/auth/me", token)
        require(status == 200 and isinstance(identity, dict)
                and identity.get("token", {}).get("type") == "oidc"
                and identity.get("token", {}).get("authority") == "limited"
                and identity.get("token", {}).get("trustedPublisher") is not None,
                "personal_publisher_identity_not_limited_oidc")
        expected_handle = urllib.parse.unquote(paths[0]).split("/")[3]
        require(identity.get("user", {}).get("handle", "").lstrip("@") == expected_handle.lstrip("@"),
                "personal_publisher_owner_mismatch")
        emit("personal_publisher_identity_verified")
    else:
        require(call(origin + "/v1/auth/me", token)[0] == 401, "workload_admitted_as_human")
    status, payload = exchange(jwt)
    require(status == 400 and isinstance(payload, dict)
            and payload.get("error") == "invalid_grant", "subject_replay_not_refused")
    status, payload = exchange(subject(origin + "/wrong-audience"))
    require(status == 400 and isinstance(payload, dict)
            and payload.get("error") == "invalid_grant", "wrong_audience_not_refused")
    emit("protocol_observation_passed", phase=phase, lifetime_seconds=lifetime)
    if phase == "personal-boundaries":
        emit("ready_for_personal_publisher_disable")
        deadline = time.monotonic() + 300
        while True:
            status, _ = call(origin + paths[0], token)
            if status in (401, 403, 404):
                break
            require(status == 200, "unexpected_personal_revocation_response")
            require(time.monotonic() < deadline, "personal_revocation_not_observed")
            time.sleep(5)
        require(time.monotonic() - issued < lifetime - 60,
                "expiry_would_confound_personal_revocation")
        status, payload = exchange(subject(origin))
        require(status == 400 and isinstance(payload, dict)
                and payload.get("error") == "invalid_grant", "disabled_personal_publisher_exchanged")
        emit("personal_publisher_existing_and_fresh_credentials_refused")
        return
    publication(phase, origin, paths[0], token)
    if phase != "withdrawal-regrant":
        return

    emit("ready_for_external_grant_withdrawal")
    deadline = time.monotonic() + 180
    while True:
        status, _ = call(origin + paths[0], token)
        if status in (401, 403, 404):
            break
        require(status == 200, "unexpected_withdrawal_response")
        require(time.monotonic() < deadline, "withdrawal_not_observed_in_window")
        time.sleep(5)
    emit("existing_token_denied", status=status)
    emit("ready_for_external_regrant")
    deadline = time.monotonic() + 180
    while True:
        status, payload = exchange(subject(origin))
        if status == 200:
            replacement, _ = access(payload)
            if call(origin + paths[0], replacement)[0] == 200:
                break
        else:
            require(status == 400 and isinstance(payload, dict)
                    and payload.get("error") == "invalid_grant", "unexpected_regrant_exchange_response")
        require(time.monotonic() < deadline, "fresh_access_after_regrant_not_observed")
        time.sleep(5)
    require(time.monotonic() - issued < lifetime - 60, "old_token_expiry_would_confound_result")
    require(call(origin + paths[0], token)[0] in (401, 403, 404), "old_token_revived_after_regrant")
    emit("fresh_access_passed_old_token_still_denied")


if __name__ == "__main__":
    try:
        run()
    except RuntimeError as error:
        emit("probe_failed", reason=str(error))
        sys.exit(1)
    except Exception:
        emit("probe_failed", reason="unexpected_failure_details_withheld")
        sys.exit(1)
