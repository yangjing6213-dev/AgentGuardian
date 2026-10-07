from agentguardian.app import translate


def test_translates_primary_navigation_and_status_text() -> None:
    assert translate("审计范围", "en") == "Audit Scope"
    assert translate("关于作者", "en") == "About the Author"
    assert translate("审计完成：发现 3 项风险。", "en") == (
        "Audit complete: 3 finding(s) found."
    )
    assert translate("覆盖状态：覆盖受限；覆盖率 72%；原因：单个文件超过大小上限；本次结果不能证明系统、账户、提供商或端点安全。", "en") == (
        "Coverage: Limited coverage; 72%; reasons: A file exceeded the size limit; "
        "These results do not prove that the system, account, provider, or endpoint is secure."
    )


def test_dynamic_translations_preserve_user_paths_and_folder_names() -> None:
    path = r"C:\Users\恩禾\审计范围"
    assert translate(path, "en") == path
    assert translate(f"范围：1 个根目录（{path}）", "en") == (
        f"Scope: 1 root folder(s) ({path})"
    )


def test_translates_built_in_guidance_without_changing_identifiers() -> None:
    guidance = (
        "1. Confirm who operates the configured OpenAI API endpoint.\n"
        "\nVerification:\n"
        "Rerun the read-only audit and have a reviewer compare the new findings."
    )
    assert translate(guidance, "zh") == (
        "1. 确认当前配置的 OpenAI API 端点由谁运营。\n"
        "\n验证：\n"
        "重新执行只读审计，并由复核人比较新发现。"
    )
