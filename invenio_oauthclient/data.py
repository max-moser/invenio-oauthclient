from collections import UserDict
from dataclasses import dataclass, field


@dataclass
class UserInfo:
    user: dict
    external_id: str
    external_method: str
    extra_data: dict = field(default_factory=dict)


@dataclass
class GroupInfo:
    id: str
    name: str
    description: str


@dataclass
class ServerMetadata:
    request_token_url: str = ""
    request_token_params: dict = field(default_factory=dict)
    access_token_url: str = ""
    access_token_params: dict = field(default_factory=dict)
    refresh_token_url: str = ""
    refresh_token_params: dict = field(default_factory=dict)
    authorize_url: str = ""
    authorize_params: dict = field(default_factory=dict)
    api_base_url: str = ""
    client_kwargs: dict = field(default_factory=dict)


class LazyDict(UserDict):
    def __init__(self, load_func):
        self._data = None
        self.load_func = load_func

    @property
    def data(self):
        if self._data is None:
            self._data = self.load_func()
        return self._data

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)

    def __len__(self):
        return len(self.data)
