import pytest

pytest_plugins = [
    "tests.unit.restapi.conftest",
    "tests.unit.restapi.v1.conftest",
]


@pytest.fixture(autouse=True)
def enable_route_authentication(flask_app):
    previous = flask_app.config["LOGIN_DISABLED"]
    flask_app.config["LOGIN_DISABLED"] = False
    yield
    flask_app.config["LOGIN_DISABLED"] = previous
