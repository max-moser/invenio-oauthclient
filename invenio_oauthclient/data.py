from dataclasses import dataclass, field


@dataclass
class UserInfo:
    user: dict
    external_id: str
    external_method: str
    extra_data: dict = field(default_factory=dict)


@dataclass
class ServerMetadata:
    request_token_url: str
    request_token_params: dict
    access_token_url: str
    access_token_params: dict
    refresh_token_url: str
    refresh_token_params: dict
    authorize_url: str
    authorize_params: dict
    api_base_url: str
    client_kwargs: dict
