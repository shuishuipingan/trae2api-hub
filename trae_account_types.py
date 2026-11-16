"""Account protocol classification shared by client and optional-client fallback."""

ENTERPRISE_UNSUPPORTED_MESSAGE = (
    "Trae Enterprise/SaaS 使用独立租户协议，当前仅支持个人版，未发送上游请求"
)


def is_enterprise_account(value):
    """Recognize explicit SaaS metadata, never infer a tenant from a bare token.

    Evidence: official desktop SaaS oauthService (Trae 3.6.4) uses scope=saas,
    loginScope and saasBootConfig, plus Data.UserInfo / Data.TenantInfoBase.
    Only named account/profile/extra and response wrappers are inspected; no
    arbitrary recursive search through unrelated user content is performed.
    """
    if not isinstance(value, dict):
        value = getattr(value, "__dict__", {})
    if not isinstance(value, dict):
        return False
    nodes = [value]
    for key in ("account", "profile", "extra", "UserInfo", "userInfo"):
        node = value.get(key)
        if isinstance(node, dict):
            nodes.append(node)
    for key in ("Data", "data", "Result", "result"):
        wrapper = value.get(key)
        if not isinstance(wrapper, dict):
            continue
        nodes.append(wrapper)
        if isinstance(wrapper.get("TenantInfoBase"), dict) and wrapper["TenantInfoBase"]:
            return True
        for inner in ("UserInfo", "userInfo", "account", "profile"):
            node = wrapper.get(inner)
            if isinstance(node, dict):
                nodes.append(node)
    for node in nodes:
        if str(node.get("realm") or "").strip().lower() in ("enterprise", "saas"):
            return True
        if any(str(node.get(key) or "").strip().lower() == "saas"
               for key in ("scope", "Scope", "loginScope")):
            return True
        config = node.get("saasBootConfig")
        if isinstance(config, dict) and config:
            return True
    return False


class EnterpriseAccountUnsupported(ValueError):
    code = "unsupported_enterprise_account"
    status = 400

    def __init__(self):
        super().__init__(ENTERPRISE_UNSUPPORTED_MESSAGE)


def ensure_personal_account(value):
    if is_enterprise_account(value):
        raise EnterpriseAccountUnsupported()
    return value
