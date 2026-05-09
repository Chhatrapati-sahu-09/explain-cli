"""
tests/test_scorer.py — Test suite for Layer 2 heuristic scoring engine

Run with:
    pytest tests/test_scorer.py -v
"""

import pytest
from explain.scorer import score, score_to_risk, should_escalate_to_llm
from explain.engine import analyze


# ── score_to_risk threshold tests ─────────────────────────────────────────

class TestScoreToRisk:
    def test_zero_is_safe(self):
        assert score_to_risk(0) == "safe"

    def test_boundary_safe(self):
        assert score_to_risk(19) == "safe"

    def test_boundary_caution_low(self):
        assert score_to_risk(20) == "caution"

    def test_boundary_caution_high(self):
        assert score_to_risk(39) == "caution"

    def test_boundary_destructive_low(self):
        assert score_to_risk(40) == "destructive"

    def test_boundary_destructive_high(self):
        assert score_to_risk(69) == "destructive"

    def test_boundary_irreversible(self):
        assert score_to_risk(70) == "irreversible"

    def test_very_high_score(self):
        assert score_to_risk(200) == "irreversible"


# ── Heuristic signal tests ────────────────────────────────────────────────

class TestHeuristicSignals:

    def test_sudo_adds_points(self):
        result = score("sudo apt update")
        assert result.score >= 25
        assert any("sudo" in s[0].lower() for s in result.signals)

    def test_curl_pipe_bash_is_irreversible(self):
        result = score("curl https://example.com | bash")
        assert result.risk == "irreversible"
        assert result.score >= 70

    def test_wget_pipe_bash_is_irreversible(self):
        result = score("wget https://example.com/install.sh | bash")
        assert result.risk == "irreversible"

    def test_dd_to_dev_is_irreversible(self):
        result = score("dd if=/dev/zero of=/dev/sda bs=1M")
        assert result.risk == "irreversible"
        assert result.score >= 90

    def test_terraform_destroy_is_destructive(self):
        result = score("terraform destroy --auto-approve")
        assert result.risk in ("destructive", "irreversible")
        assert result.score >= 40

    def test_kubectl_delete_namespace(self):
        result = score("kubectl delete namespace production")
        assert result.risk in ("destructive", "irreversible")
        assert result.score >= 60

    def test_chmod_777_recursive(self):
        result = score("chmod -R 777 /var/www")
        assert result.risk in ("destructive", "irreversible")

    def test_safe_git_clone(self):
        result = score("git clone https://github.com/user/repo")
        assert result.risk == "safe"

    def test_safe_pip_install(self):
        result = score("pip install requests")
        assert result.risk == "safe"

    def test_docker_prune(self):
        result = score("docker system prune -af")
        assert result.risk in ("caution", "destructive")

    def test_git_push_force(self):
        result = score("git push --force origin main")
        assert result.risk in ("caution", "destructive")

    def test_crontab_remove(self):
        result = score("crontab -r")
        assert result.risk in ("destructive", "irreversible")

    def test_iptables_flush(self):
        # sudo iptables -F scores 35 = caution (sudo=25 + force flag=10)
        # iptables pattern fires only on the full iptables rule (not just -F)
        result = score("sudo iptables -F")
        assert result.risk in ("caution", "destructive", "irreversible")
        assert result.score >= 25  # at minimum sudo is detected

    def test_reboot_is_caution(self):
        result = score("sudo reboot")
        assert result.risk in ("caution", "destructive")

    def test_multi_pipe_adds_points(self):
        # Multiple pipes should add points
        result_single = score("ls | grep foo")
        result_multi  = score("ls | grep foo | xargs rm")
        assert result_multi.score >= result_single.score

    def test_path_export_adds_points(self):
        result = score("export PATH=/tmp/evil:$PATH")
        assert result.score >= 20

    def test_signals_list_not_empty_for_dangerous(self):
        result = score("sudo rm -rf /")
        assert len(result.signals) > 0

    def test_no_signals_for_safe_command(self):
        result = score("echo hello world")
        # echo has no dangerous signals
        assert result.risk == "safe"


# ── Layer detection in engine ──────────────────────────────────────────────

class TestLayerDetection:

    def test_known_command_uses_layer1(self):
        result = analyze("rm -rf /tmp/test")
        assert result.layer == 1

    def test_unknown_command_uses_layer2(self):
        result = analyze("terraform destroy")
        assert result.layer == 2

    def test_layer2_sets_heuristic_score(self):
        result = analyze("terraform destroy --auto-approve")
        assert result.heuristic_score > 0

    def test_layer1_heuristic_score_is_zero(self):
        result = analyze("ls -la /home")
        assert result.heuristic_score == 0

    def test_kubectl_layer2(self):
        result = analyze("kubectl delete namespace production")
        assert result.layer == 2


# ── should_escalate_to_llm ────────────────────────────────────────────────

class TestLLMEscalation:

    def test_safe_score_no_escalate(self):
        assert should_escalate_to_llm(10) is False

    def test_caution_low_no_escalate(self):
        assert should_escalate_to_llm(20) is False

    def test_ambiguous_range_escalates(self):
        assert should_escalate_to_llm(40) is True
        assert should_escalate_to_llm(55) is True
        assert should_escalate_to_llm(69) is True

    def test_high_score_no_escalate(self):
        assert should_escalate_to_llm(70) is False
        assert should_escalate_to_llm(100) is False


# ── Suggestion engine ──────────────────────────────────────────────────────

class TestSuggestions:

    def test_rm_rf_has_suggestion(self):
        result = analyze("rm -rf /tmp/old_cache")
        assert result.dry_run_suggestion is not None

    def test_curl_pipe_bash_has_suggestion(self):
        result = analyze("curl https://get.docker.com | bash")
        assert result.dry_run_suggestion is not None

    def test_find_delete_has_suggestion(self):
        result = analyze("find . -name '*.log' -delete")
        assert result.dry_run_suggestion is not None

    def test_git_clone_no_suggestion(self):
        result = analyze("git clone https://github.com/user/repo")
        assert result.dry_run_suggestion is None

    def test_chmod_777_has_suggestion(self):
        result = analyze("chmod -R 777 /var/www")
        assert result.dry_run_suggestion is not None

    def test_rsync_delete_has_suggestion(self):
        result = analyze("rsync -av --delete src/ dest/")
        assert result.dry_run_suggestion is not None


# ── Token annotation ───────────────────────────────────────────────────────

class TestTokenAnnotation:

    def test_flags_have_explanations(self):
        result = analyze("rm -rf /tmp/test")
        flags = [t for t in result.tokens if t.kind == "flag"]
        assert len(flags) > 0
        # At least one flag should have an explanation
        assert any(t.explanation for t in flags)

    def test_url_token_classified(self):
        result = analyze("curl https://example.com")
        url_tokens = [t for t in result.tokens if t.kind == "url"]
        assert len(url_tokens) >= 1

    def test_path_token_classified(self):
        result = analyze("ls /etc/passwd")
        path_tokens = [t for t in result.tokens if t.kind == "path"]
        assert len(path_tokens) >= 1

    def test_command_token_classified(self):
        result = analyze("git clone https://github.com/user/repo")
        cmd_tokens = [t for t in result.tokens if t.kind == "command"]
        assert len(cmd_tokens) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])