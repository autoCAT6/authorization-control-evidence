"""Third-party evaluation task; requires the prepared runtime package."""

from dioptra import pyplugs
from authorization_contract_runtime import evaluate


@pyplugs.register
def evaluate_authorization_contract() -> tuple[str, str, str]:
    return evaluate()
