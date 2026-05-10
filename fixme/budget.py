from __future__ import annotations


class BudgetExceeded(Exception):
    pass


class TokenBudget:
    def __init__(self, max_tokens: int):
        self.max_tokens = max_tokens
        self.used = 0

    def charge(self, tokens_in: int, tokens_out: int) -> None:
        self.used += tokens_in + tokens_out
        if self.used > self.max_tokens:
            raise BudgetExceeded(f"Token budget exceeded: {self.used}/{self.max_tokens}")

    def remaining(self) -> int:
        return max(0, self.max_tokens - self.used)
