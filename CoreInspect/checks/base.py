from abc import ABC, abstractmethod


class BaseCheck(ABC):
    name: str = "BaseCheck"

    def __init__(self, requester, reporter):
        self.req = requester
        self.reporter = reporter

    @abstractmethod
    def run_url(self, url: str):
        raise NotImplementedError

    def run_form(self, form: dict):
        # Optional override
        return