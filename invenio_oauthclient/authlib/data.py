from dataclasses import dataclass


@dataclass
class UserInfo:
    user: dict
    external_id: str
    external_method: str


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
