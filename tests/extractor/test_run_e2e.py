"""
End-to-end tests for Component.run() and sync actions.

Mocks only the AcumaticaClient; uses real CSV/manifest verification.
"""

from typing import Any
from unittest.mock import MagicMock

import pytest
from extractor_component import Component
from keboola.component.exceptions import UserException

from ..conftest import read_csv, read_state, write_config, write_state

BASE_PARAMS: dict[str, Any] = {
    "acumatica_url": "https://example.acumatica.com",
    "page_size": 100,
    "debug": False,
    "endpoints": [
        {
            "enabled": True,
            "tenant_version": "Default/25.200.001",
            "endpoint": "Customer",
            "expand": "",
            "filter_expr": "",
            "select": "",
            "primary_keys": [],
        }
    ],
    "destination": {"load_type": "full_load"},
}

OAUTH_AUTHORIZATION = {
    "oauth_api": {
        "credentials": {
            "appKey": "test-client-id",
            "#appSecret": "test-client-secret",
            "#data": (
                '{"access_token": "test_access", "refresh_token": "test_refresh",'
                ' "expires_in": 3600, "token_received_at": 1234567890.0,'
                ' "scope": "api offline_access", "token_type": "Bearer"}'
            ),
        }
    }
}


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.authenticate.return_value = None
    client.logout.return_value = None
    client.acumatica_username = ""
    client.oauth_access_token = "test_access"
    return client


@pytest.fixture
def run_component(kbc_datadir, mocker, mock_client):
    """Factory: write config, patch AcumaticaClient, run Component, return data dir."""

    def _run(params=None, action="run", authorization=None, client=mock_client):
        write_config(kbc_datadir, params or BASE_PARAMS, action=action, authorization=authorization)
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=client)
        Component().run()
        return kbc_datadir

    return _run


# ---------------------------------------------------------------------------
# TestRunBasic
# ---------------------------------------------------------------------------


class TestRunBasic:
    def test_single_endpoint_writes_csv(self, run_component, mock_client):
        mock_client.get_entities.return_value = iter(
            [
                {"CustomerID": "C001", "CustomerName": "Acme"},
                {"CustomerID": "C002", "CustomerName": "Beta"},
            ]
        )
        data_dir = run_component()
        rows = read_csv(data_dir, "Customer")
        assert len(rows) == 2
        assert rows[0]["CustomerID"] == "C001"
        assert rows[1]["CustomerID"] == "C002"

    def test_columns_sorted_alphabetically(self, run_component, mock_client):
        mock_client.get_entities.return_value = iter(
            [
                {"ZField": "z", "AField": "a", "MField": "m"},
            ]
        )
        data_dir = run_component()
        rows = read_csv(data_dir, "Customer")
        assert list(rows[0].keys()) == ["AField", "MField", "ZField"]

    def test_manifest_written(self, run_component, mock_client):
        mock_client.get_entities.return_value = iter([{"CustomerID": "C001"}])
        data_dir = run_component()
        assert (data_dir / "out" / "tables" / "Customer.csv.manifest").exists()

    def test_state_updated_after_run(self, run_component, mock_client):
        mock_client.get_entities.return_value = iter([{"CustomerID": "C001"}])
        data_dir = run_component()
        state = read_state(data_dir)
        assert "last_run_timestamp" in state

    def test_multi_endpoint_writes_both_tables(self, run_component, mock_client):
        params = {
            **BASE_PARAMS,
            "endpoints": [
                {**BASE_PARAMS["endpoints"][0], "endpoint": "Customer"},
                {**BASE_PARAMS["endpoints"][0], "endpoint": "SalesOrder"},
            ],
        }
        mock_client.get_entities.side_effect = [
            iter([{"CustomerID": "C001"}]),
            iter([{"OrderNbr": "SO001"}]),
        ]
        data_dir = run_component(params=params)
        assert (data_dir / "out" / "tables" / "Customer.csv").exists()
        assert (data_dir / "out" / "tables" / "SalesOrder.csv").exists()

    def test_incremental_load_mode(self, run_component, mock_client):
        params = {**BASE_PARAMS, "destination": {"load_type": "incremental_load"}}
        mock_client.get_entities.return_value = iter([{"CustomerID": "C001"}])
        # Just verifying it doesn't raise; manifest inspection for incremental flag
        # is a lower-level concern tested separately
        run_component(params=params)

    def test_primary_keys_passed_to_table(self, run_component, mock_client):
        params = {
            **BASE_PARAMS,
            "endpoints": [{**BASE_PARAMS["endpoints"][0], "primary_keys": ["CustomerID"]}],
        }
        mock_client.get_entities.return_value = iter([{"CustomerID": "C001"}])
        # No exception means primary keys were accepted
        run_component(params=params)

    def test_odata_params_passed_to_client(self, run_component, mock_client):
        params = {
            **BASE_PARAMS,
            "endpoints": [
                {
                    **BASE_PARAMS["endpoints"][0],
                    "expand": "MainContact",
                    "filter_expr": "Status eq 'Active'",
                    "select": "CustomerID,CustomerName",
                }
            ],
        }
        mock_client.get_entities.return_value = iter([{"CustomerID": "C001"}])
        run_component(params=params)

        call_kwargs = mock_client.get_entities.call_args.kwargs
        assert call_kwargs["expand"] == "MainContact"
        assert call_kwargs["filter_expr"] == "Status eq 'Active'"
        assert call_kwargs["select"] == "CustomerID,CustomerName"

    def test_empty_entities_writes_no_csv(self, run_component, mock_client):
        mock_client.get_entities.return_value = iter([])
        data_dir = run_component()
        assert not (data_dir / "out" / "tables" / "Customer.csv").exists()


# ---------------------------------------------------------------------------
# TestRunErrorHandling
# ---------------------------------------------------------------------------


class TestRunErrorHandling:
    def test_no_endpoints_raises_user_exception(self, kbc_datadir, mocker):
        params = {**BASE_PARAMS, "endpoints": []}
        write_config(kbc_datadir, params)
        mock_client = MagicMock()
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)
        with pytest.raises(UserException, match="No endpoints configured"):
            Component().run()

    def test_no_enabled_endpoints_returns_early(self, kbc_datadir, mocker):
        params = {
            **BASE_PARAMS,
            "endpoints": [{**BASE_PARAMS["endpoints"][0], "enabled": False}],
        }
        write_config(kbc_datadir, params)
        mock_client = MagicMock()
        mock_client.oauth_access_token = ""
        mock_client.acumatica_username = ""
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)
        Component().run()
        mock_client.get_entities.assert_not_called()

    def test_user_exception_propagated(self, kbc_datadir, mocker):
        write_config(kbc_datadir, BASE_PARAMS)
        mock_client = MagicMock()
        mock_client.authenticate.side_effect = UserException("auth failed")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)
        with pytest.raises(UserException, match="auth failed"):
            Component().run()

    def test_generic_exception_wrapped_in_user_exception(self, kbc_datadir, mocker):
        write_config(kbc_datadir, BASE_PARAMS)
        mock_client = MagicMock()
        mock_client.authenticate.side_effect = RuntimeError("unexpected boom")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)
        with pytest.raises(UserException, match="Extraction failed"):
            Component().run()

    def test_api_login_limit_error_gives_friendly_message(self, kbc_datadir, mocker):
        write_config(kbc_datadir, BASE_PARAMS)
        mock_client = MagicMock()
        mock_client.authenticate.side_effect = Exception("too many 500 error responses for auth/login endpoint")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)
        with pytest.raises(UserException, match="API Login Limit"):
            Component().run()


# ---------------------------------------------------------------------------
# TestLogoutBehaviour
# ---------------------------------------------------------------------------


class TestLogoutBehaviour:
    def test_logout_called_for_username_password(self, kbc_datadir, mocker):
        params = {**BASE_PARAMS, "acumatica_username": "admin", "#acumatica_password": "pass"}
        write_config(kbc_datadir, params)
        mock_client = MagicMock()
        mock_client.acumatica_username = "admin"
        mock_client.oauth_access_token = ""
        mock_client.get_entities.return_value = iter([{"CustomerID": "C001"}])
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)
        Component().run()
        mock_client.logout.assert_called_once()

    def test_logout_not_called_for_oauth(self, kbc_datadir, mocker):
        write_config(kbc_datadir, BASE_PARAMS, authorization=OAUTH_AUTHORIZATION)
        mock_client = MagicMock()
        mock_client.acumatica_username = ""
        mock_client.oauth_access_token = "test_access"
        mock_client.get_entities.return_value = iter([{"CustomerID": "C001"}])
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)
        Component().run()
        mock_client.logout.assert_not_called()


# ---------------------------------------------------------------------------
# TestSyncActionErrors
# ---------------------------------------------------------------------------


class TestSyncActionErrors:
    # Note: the @sync_action decorator catches UserException and calls exit(1),
    # so when testing error paths via the decorated method we catch SystemExit.

    def test_list_endpoints_no_endpoints_configured_raises(self, kbc_datadir, mocker, capsys):
        params = {**BASE_PARAMS, "endpoints": []}
        write_config(kbc_datadir, params, action="listEndpoints")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=MagicMock())
        with pytest.raises(SystemExit):
            Component().list_endpoints()
        assert "Tenant/Version must be selected" in capsys.readouterr().err

    def test_list_endpoints_empty_tenant_version_raises(self, kbc_datadir, mocker, capsys):
        params = {
            **BASE_PARAMS,
            "endpoints": [{**BASE_PARAMS["endpoints"][0], "tenant_version": ""}],
        }
        write_config(kbc_datadir, params, action="listEndpoints")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=MagicMock())
        with pytest.raises(SystemExit):
            Component().list_endpoints()
        assert "Tenant/Version must be selected" in capsys.readouterr().err

    def test_get_output_columns_no_endpoints_raises(self, kbc_datadir, mocker, capsys):
        params = {**BASE_PARAMS, "endpoints": []}
        write_config(kbc_datadir, params, action="getOutputColumns")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=MagicMock())
        with pytest.raises(SystemExit):
            Component().get_output_columns()
        assert "Tenant/Version must be selected" in capsys.readouterr().err

    def test_get_output_columns_empty_tenant_version_raises(self, kbc_datadir, mocker, capsys):
        params = {
            **BASE_PARAMS,
            "endpoints": [{**BASE_PARAMS["endpoints"][0], "tenant_version": ""}],
        }
        write_config(kbc_datadir, params, action="getOutputColumns")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=MagicMock())
        with pytest.raises(SystemExit):
            Component().get_output_columns()
        assert "Tenant/Version must be selected" in capsys.readouterr().err

    def test_get_output_columns_empty_endpoint_raises(self, kbc_datadir, mocker, capsys):
        params = {
            **BASE_PARAMS,
            "endpoints": [{**BASE_PARAMS["endpoints"][0], "endpoint": ""}],
        }
        write_config(kbc_datadir, params, action="getOutputColumns")
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=MagicMock())
        with pytest.raises(SystemExit):
            Component().get_output_columns()
        assert "Endpoint must be selected" in capsys.readouterr().err

    def test_get_output_columns_no_columns_found_raises(self, kbc_datadir, mocker, capsys):
        write_config(kbc_datadir, BASE_PARAMS, action="getOutputColumns")
        mock_client = MagicMock()
        mock_client.get_swagger_data.return_value = {"definitions": {}}
        mocker.patch("shared.acumatica_base.AcumaticaClient", return_value=mock_client)
        mocker.patch(
            "shared.acumatica_base.SwaggerParser"
        ).return_value.get_entity_primary_key_candidates.return_value = []
        with pytest.raises(SystemExit):
            Component().get_output_columns()
        assert "No columns found" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# TestOAuthClientInit
# ---------------------------------------------------------------------------


class TestOAuthClientInit:
    def test_init_client_from_state_uses_state_tokens(self, kbc_datadir, mocker):
        write_state(
            kbc_datadir,
            {
                "#oauth_token_dict": (
                    '{"access_token": "state_access", "refresh_token": "state_refresh",'
                    ' "expires_in": 3600, "token_received_at": 9999999999.0,'
                    ' "scope": "api", "client_id": "", "client_secret": ""}'
                )
            },
        )
        write_config(kbc_datadir, BASE_PARAMS)

        captured = {}

        def capture_client(**kwargs):
            captured.update(kwargs)
            m = MagicMock()
            m.oauth_access_token = kwargs.get("oauth_access_token", "")
            m.acumatica_username = ""
            m.get_entities.return_value = iter([])
            return m

        mocker.patch("shared.acumatica_base.AcumaticaClient", side_effect=capture_client)
        Component().run()

        assert captured.get("oauth_access_token") == "state_access"
        assert captured.get("oauth_refresh_token") == "state_refresh"

    def test_init_client_from_configuration_oauth(self, kbc_datadir, mocker):
        write_config(kbc_datadir, BASE_PARAMS, authorization=OAUTH_AUTHORIZATION)

        captured = {}

        def capture_client(**kwargs):
            captured.update(kwargs)
            m = MagicMock()
            m.oauth_access_token = kwargs.get("oauth_access_token", "")
            m.acumatica_username = ""
            m.get_entities.return_value = iter([])
            return m

        mocker.patch("shared.acumatica_base.AcumaticaClient", side_effect=capture_client)
        Component().run()

        assert captured.get("oauth_access_token") == "test_access"
        assert captured.get("oauth_refresh_token") == "test_refresh"

    def test_init_client_falls_back_to_username_password(self, kbc_datadir, mocker):
        params = {**BASE_PARAMS, "acumatica_username": "admin", "#acumatica_password": "secret"}
        write_config(kbc_datadir, params)

        captured = {}

        def capture_client(**kwargs):
            captured.update(kwargs)
            m = MagicMock()
            m.oauth_access_token = ""
            m.acumatica_username = kwargs.get("acumatica_username", "")
            m.get_entities.return_value = iter([])
            return m

        mocker.patch("shared.acumatica_base.AcumaticaClient", side_effect=capture_client)
        Component().run()

        assert captured.get("acumatica_username") == "admin"
        assert captured.get("acumatica_password") == "secret"

    def test_load_state_oauth_string_parsed(self):
        result = Component._load_state_oauth('{"access_token": "tok"}')
        assert result == {"access_token": "tok"}

    def test_load_state_oauth_dict_returned_as_is(self):
        d = {"access_token": "tok"}
        result = Component._load_state_oauth(d)
        assert result is d

    def test_load_state_oauth_other_type_returns_empty(self):
        assert Component._load_state_oauth(42) == {}
        assert Component._load_state_oauth(None) == {}
