"""
Tests for AcumaticaClient — authentication, token management, pagination, and endpoint discovery.

All HTTP calls are mocked; no real network requests are made.
"""

import time
from unittest.mock import MagicMock, patch

import pytest
import requests
from shared.acumatica_client import AcumaticaClient

BASE_URL = "https://example.acumatica.com"


@pytest.fixture
def client():
    """Bare client with no credentials — for unit-testing individual methods."""
    return AcumaticaClient(acumatica_url=BASE_URL)


@pytest.fixture
def oauth_client():
    """Client pre-loaded with valid OAuth tokens (not yet expired)."""
    return AcumaticaClient(
        acumatica_url=BASE_URL,
        oauth_access_token="access_abc123",
        oauth_refresh_token="refresh_xyz789",
        oauth_client_id="client-id",
        oauth_client_secret="client-secret",
        oauth_expires_in=3600,
        oauth_token_received_at=time.time(),  # just issued
    )


@pytest.fixture
def expired_oauth_client():
    """Client with an OAuth token that expired 10 minutes ago."""
    return AcumaticaClient(
        acumatica_url=BASE_URL,
        oauth_access_token="old_access",
        oauth_refresh_token="refresh_xyz789",
        oauth_client_id="client-id",
        oauth_client_secret="client-secret",
        oauth_expires_in=3600,
        oauth_token_received_at=time.time() - 4200,  # issued 70 minutes ago → expired
    )


@pytest.fixture
def password_client():
    """Client with username/password credentials."""
    return AcumaticaClient(
        acumatica_url=BASE_URL,
        acumatica_username="admin",
        acumatica_password="secret",
    )


# ---------------------------------------------------------------------------
# TestTokenExpiration
# ---------------------------------------------------------------------------


class TestTokenExpiration:
    def test_no_expiry_info_returns_false(self, client):
        # Neither expires_in nor token_received_at set
        assert client._is_token_expired() is False

    def test_missing_received_at_returns_false(self, client):
        client.oauth_expires_in = 3600
        client.oauth_token_received_at = 0.0
        assert client._is_token_expired() is False

    def test_valid_token_returns_false(self, client):
        client.oauth_expires_in = 3600
        client.oauth_token_received_at = time.time()  # just issued
        assert client._is_token_expired() is False

    def test_expired_token_returns_true(self, client):
        client.oauth_expires_in = 3600
        client.oauth_token_received_at = time.time() - 4200  # issued 70 min ago
        assert client._is_token_expired() is True

    def test_token_within_60s_buffer_returns_true(self, client):
        client.oauth_expires_in = 3600
        client.oauth_token_received_at = time.time() - 3550  # 50s left
        assert client._is_token_expired() is True

    def test_token_well_outside_buffer_returns_false(self, client):
        client.oauth_expires_in = 3600
        client.oauth_token_received_at = time.time() - 3400  # 200s left
        assert client._is_token_expired() is False


# ---------------------------------------------------------------------------
# TestAuthenticate
# ---------------------------------------------------------------------------


class TestAuthenticate:
    def test_oauth_valid_token_sets_headers_and_authenticated(self, oauth_client):
        oauth_client.authenticate()
        assert "Bearer access_abc123" in oauth_client.session.headers.get("Authorization", "")
        assert oauth_client._authenticated is True

    def test_oauth_expired_token_attempts_refresh(self, expired_oauth_client):
        with patch.object(expired_oauth_client, "_refresh_oauth_token") as mock_refresh:
            with patch.object(expired_oauth_client, "_setup_oauth_headers"):
                expired_oauth_client.authenticate()
                mock_refresh.assert_called_once()

    def test_oauth_refresh_failure_continues_with_existing_token(self, expired_oauth_client):
        with patch.object(expired_oauth_client, "_refresh_oauth_token", side_effect=ValueError("no creds")):
            with patch.object(expired_oauth_client, "_setup_oauth_headers") as mock_setup:
                expired_oauth_client.authenticate()
                # Should still call _setup_oauth_headers despite refresh failure
                mock_setup.assert_called_once()

    def test_username_password_calls_authenticate_method(self, password_client):
        with patch.object(password_client, "_authenticate_username_password") as mock_auth:
            password_client.authenticate()
            mock_auth.assert_called_once()

    def test_no_credentials_raises_value_error(self, client):
        with pytest.raises(ValueError, match="No valid authentication method"):
            client.authenticate()


# ---------------------------------------------------------------------------
# TestSetupOAuthHeaders
# ---------------------------------------------------------------------------


class TestSetupOAuthHeaders:
    def test_authorization_header_set(self, oauth_client):
        oauth_client._setup_oauth_headers()
        assert oauth_client.session.headers["Authorization"] == "Bearer access_abc123"

    def test_content_type_and_accept_set(self, oauth_client):
        oauth_client._setup_oauth_headers()
        assert oauth_client.session.headers["Accept"] == "application/json"
        assert oauth_client.session.headers["Content-Type"] == "application/json"

    def test_authenticated_flag_set(self, oauth_client):
        assert oauth_client._authenticated is False
        oauth_client._setup_oauth_headers()
        assert oauth_client._authenticated is True


# ---------------------------------------------------------------------------
# TestRefreshOAuthToken
# ---------------------------------------------------------------------------


class TestRefreshOAuthToken:
    def test_no_refresh_token_raises(self, client):
        client.oauth_client_id = "id"
        client.oauth_client_secret = "secret"
        with pytest.raises(ValueError, match="No refresh token"):
            client._refresh_oauth_token()

    def test_no_client_credentials_raises(self, client):
        client.oauth_refresh_token = "some_refresh"
        with pytest.raises(ValueError, match="Cannot refresh token without client credentials"):
            client._refresh_oauth_token()

    def test_successful_refresh_updates_access_token(self, oauth_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "expires_in": 3600,
        }

        with patch("requests.post", return_value=mock_response):
            oauth_client._refresh_oauth_token()

        assert oauth_client.oauth_access_token == "new_access_token"

    def test_successful_refresh_rotates_refresh_token(self, oauth_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access",
            "refresh_token": "new_refresh",
            "expires_in": 3600,
        }

        with patch("requests.post", return_value=mock_response):
            oauth_client._refresh_oauth_token()

        assert oauth_client.oauth_refresh_token == "new_refresh"

    def test_refresh_without_new_refresh_token_keeps_old(self, oauth_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access",
            "expires_in": 3600,
            # no refresh_token key
        }

        with patch("requests.post", return_value=mock_response):
            oauth_client._refresh_oauth_token()

        assert oauth_client.oauth_refresh_token == "refresh_xyz789"

    def test_successful_refresh_calls_callback(self, oauth_client):
        callback = MagicMock()
        oauth_client.on_token_refresh = callback

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "new_access", "expires_in": 3600}

        with patch("requests.post", return_value=mock_response):
            oauth_client._refresh_oauth_token()

        callback.assert_called_once()

    def test_successful_refresh_updates_scope(self, oauth_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access",
            "expires_in": 3600,
            "scope": "api offline_access",
        }

        with patch("requests.post", return_value=mock_response):
            oauth_client._refresh_oauth_token()

        assert oauth_client.oauth_scope == "api offline_access"

    def test_http_error_raises_value_error(self, oauth_client):
        http_err = requests.exceptions.HTTPError(
            response=MagicMock(text="bad request", json=MagicMock(return_value={}))
        )

        with patch("requests.post", side_effect=http_err):
            with pytest.raises(ValueError, match="Failed to refresh OAuth token"):
                oauth_client._refresh_oauth_token()

    def test_invalid_grant_raises_descriptive_error(self, oauth_client):
        mock_error_response = MagicMock()
        mock_error_response.text = '{"error": "invalid_grant"}'
        mock_error_response.json.return_value = {"error": "invalid_grant"}
        http_err = requests.exceptions.HTTPError(response=mock_error_response)

        with patch("requests.post", side_effect=http_err):
            with pytest.raises(ValueError, match="invalid or expired"):
                oauth_client._refresh_oauth_token()

    def test_refresh_updates_expiry_timestamp(self, oauth_client):
        before = time.time()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "new_access", "expires_in": 7200}

        with patch("requests.post", return_value=mock_response):
            oauth_client._refresh_oauth_token()

        assert oauth_client.oauth_expires_in == 7200
        assert oauth_client.oauth_token_received_at >= before


# ---------------------------------------------------------------------------
# TestAuthenticateUsernamePassword
# ---------------------------------------------------------------------------


class TestAuthenticateUsernamePassword:
    def test_successful_login_sets_authenticated(self, password_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None

        with patch.object(password_client.session, "post", return_value=mock_response):
            password_client._authenticate_username_password()

        assert password_client._authenticated is True

    def test_login_posts_to_correct_url(self, password_client):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None

        with patch.object(password_client.session, "post", return_value=mock_response) as mock_post:
            password_client._authenticate_username_password()

        mock_post.assert_called_once()
        url = mock_post.call_args.args[0]
        assert url == f"{BASE_URL}/entity/auth/login"

    def test_login_sends_credentials(self, password_client):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None

        with patch.object(password_client.session, "post", return_value=mock_response) as mock_post:
            password_client._authenticate_username_password()

        sent_json = mock_post.call_args.kwargs["json"]
        assert sent_json["name"] == "admin"
        assert sent_json["password"] == "secret"

    def test_http_error_propagated(self, password_client):
        with patch.object(
            password_client.session,
            "post",
            side_effect=requests.exceptions.ConnectionError("refused"),
        ):
            with pytest.raises(requests.exceptions.ConnectionError):
                password_client._authenticate_username_password()


# ---------------------------------------------------------------------------
# TestLogout
# ---------------------------------------------------------------------------


class TestLogout:
    def test_not_authenticated_is_noop(self, client):
        with patch.object(client.session, "post") as mock_post:
            client.logout()
            mock_post.assert_not_called()

    def test_logout_posts_to_correct_url(self, oauth_client):
        oauth_client._authenticated = True
        mock_response = MagicMock()

        with patch.object(oauth_client.session, "post", return_value=mock_response) as mock_post:
            oauth_client.logout()

        url = mock_post.call_args.args[0]
        assert url == f"{BASE_URL}/entity/auth/logout"

    def test_logout_clears_authenticated_flag(self, oauth_client):
        oauth_client._authenticated = True
        mock_response = MagicMock()

        with patch.object(oauth_client.session, "post", return_value=mock_response):
            oauth_client.logout()

        assert oauth_client._authenticated is False

    def test_logout_failure_only_warns(self, oauth_client, caplog):
        oauth_client._authenticated = True
        with patch.object(
            oauth_client.session,
            "post",
            side_effect=requests.exceptions.ConnectionError("gone"),
        ):
            # Should not raise
            oauth_client.logout()


# ---------------------------------------------------------------------------
# TestGetEntities
# ---------------------------------------------------------------------------


def _make_page(entities, *, status=200):
    """Helper: build a mock response returning a list of entities."""
    mock = MagicMock()
    mock.status_code = status
    mock.json.return_value = entities
    mock.raise_for_status.return_value = None
    return mock


class TestGetEntities:
    def test_not_authenticated_raises(self, client):
        with pytest.raises(RuntimeError, match="Not authenticated"):
            list(client.get_entities("Default/25.200.001", "Customer", top=10))

    def test_single_page_returns_all_entities(self, oauth_client):
        oauth_client._authenticated = True
        entities = [{"CustomerID": "C001"}, {"CustomerID": "C002"}]

        with patch.object(oauth_client.session, "get", return_value=_make_page(entities)):
            result = list(oauth_client.get_entities("Default/25.200.001", "Customer", top=10))

        assert result == entities

    def test_pagination_fetches_all_pages(self, oauth_client):
        oauth_client._authenticated = True
        page1 = [{"id": i} for i in range(3)]
        page2 = [{"id": i} for i in range(3, 5)]  # < top → last page

        with patch.object(oauth_client.session, "get", side_effect=[_make_page(page1), _make_page(page2)]):
            result = list(oauth_client.get_entities("Default/25.200.001", "Customer", top=3))

        assert len(result) == 5

    def test_empty_response_stops_pagination(self, oauth_client):
        oauth_client._authenticated = True

        with patch.object(oauth_client.session, "get", return_value=_make_page([])):
            result = list(oauth_client.get_entities("Default/25.200.001", "Customer", top=10))

        assert result == []

    def test_list_response_format(self, oauth_client):
        oauth_client._authenticated = True

        with patch.object(oauth_client.session, "get", return_value=_make_page([{"id": 1}])):
            result = list(oauth_client.get_entities("Default/25.200.001", "Customer", top=10))

        assert result == [{"id": 1}]

    def test_dict_with_value_key_response_format(self, oauth_client):
        oauth_client._authenticated = True
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"value": [{"id": 1}]}

        with patch.object(oauth_client.session, "get", return_value=mock_resp):
            result = list(oauth_client.get_entities("Default/25.200.001", "Customer", top=10))

        assert result == [{"id": 1}]

    def test_single_dict_response_format(self, oauth_client):
        oauth_client._authenticated = True
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"id": 1, "name": "Test"}

        with patch.object(oauth_client.session, "get", return_value=mock_resp):
            result = list(oauth_client.get_entities("Default/25.200.001", "Customer", top=10))

        assert result == [{"id": 1, "name": "Test"}]

    def test_expand_param_passed(self, oauth_client):
        oauth_client._authenticated = True

        with patch.object(oauth_client.session, "get", return_value=_make_page([])) as mock_get:
            list(oauth_client.get_entities("Default/25.200.001", "Customer", expand="MainContact", top=10))

        params = mock_get.call_args.kwargs["params"]
        assert params["$expand"] == "MainContact"

    def test_filter_param_passed(self, oauth_client):
        oauth_client._authenticated = True

        with patch.object(oauth_client.session, "get", return_value=_make_page([])) as mock_get:
            list(oauth_client.get_entities("Default/25.200.001", "Customer", filter_expr="Status eq 'Active'", top=10))

        params = mock_get.call_args.kwargs["params"]
        assert params["$filter"] == "Status eq 'Active'"

    def test_select_param_passed(self, oauth_client):
        oauth_client._authenticated = True

        with patch.object(oauth_client.session, "get", return_value=_make_page([])) as mock_get:
            list(oauth_client.get_entities("Default/25.200.001", "Customer", select="CustomerID,Name", top=10))

        params = mock_get.call_args.kwargs["params"]
        assert params["$select"] == "CustomerID,Name"

    def test_no_optional_params_not_sent(self, oauth_client):
        oauth_client._authenticated = True

        with patch.object(oauth_client.session, "get", return_value=_make_page([])) as mock_get:
            list(oauth_client.get_entities("Default/25.200.001", "Customer", top=10))

        params = mock_get.call_args.kwargs["params"]
        assert "$expand" not in params
        assert "$filter" not in params
        assert "$select" not in params

    def test_401_triggers_refresh_and_retry(self, oauth_client):
        oauth_client._authenticated = True

        resp_401 = MagicMock()
        resp_401.status_code = 401
        resp_401.raise_for_status.return_value = None

        resp_ok = _make_page([{"id": 1}])

        with patch.object(oauth_client.session, "get", side_effect=[resp_401, resp_ok]):
            with patch.object(oauth_client, "_refresh_oauth_token"):
                result = list(oauth_client.get_entities("Default/25.200.001", "Customer", top=10))

        assert result == [{"id": 1}]

    def test_request_exception_propagated(self, oauth_client):
        oauth_client._authenticated = True

        with patch.object(
            oauth_client.session,
            "get",
            side_effect=requests.exceptions.ConnectionError("refused"),
        ):
            with pytest.raises(requests.exceptions.ConnectionError):
                list(oauth_client.get_entities("Default/25.200.001", "Customer", top=10))

    def test_correct_url_constructed(self, oauth_client):
        oauth_client._authenticated = True

        with patch.object(oauth_client.session, "get", return_value=_make_page([])) as mock_get:
            list(oauth_client.get_entities("Default/25.200.001", "Customer", top=10))

        url = mock_get.call_args.args[0]
        assert url == f"{BASE_URL}/entity/Default/25.200.001/Customer"


# ---------------------------------------------------------------------------
# TestContextManager
# ---------------------------------------------------------------------------


class TestContextManager:
    def test_enter_calls_authenticate(self, password_client):
        with patch.object(password_client, "authenticate") as mock_auth:
            with patch.object(password_client, "logout"):
                with password_client:
                    mock_auth.assert_called_once()

    def test_exit_calls_logout(self, password_client):
        with patch.object(password_client, "authenticate"):
            with patch.object(password_client, "logout") as mock_logout:
                with password_client:
                    pass
                mock_logout.assert_called_once()

    def test_exit_calls_logout_even_on_exception(self, password_client):
        with patch.object(password_client, "authenticate"):
            with patch.object(password_client, "logout") as mock_logout:
                with pytest.raises(RuntimeError):
                    with password_client:
                        raise RuntimeError("boom")
                mock_logout.assert_called_once()


# ---------------------------------------------------------------------------
# TestGetTenantVersions
# ---------------------------------------------------------------------------


class TestGetTenantVersions:
    def _mock_entity_response(self, endpoints):
        mock = MagicMock()
        mock.raise_for_status.return_value = None
        mock.json.return_value = {"endpoints": endpoints}
        return mock

    def test_parses_tenant_and_version(self, client):
        mock_resp = self._mock_entity_response([{"name": "Default", "version": "25.200.001"}])
        with patch("requests.get", return_value=mock_resp):
            result = client.get_tenant_versions()
        assert result == [{"label": "Default/25.200.001", "value": "Default/25.200.001"}]

    def test_deduplicates_entries(self, client):
        mock_resp = self._mock_entity_response(
            [
                {"name": "Default", "version": "25.200.001"},
                {"name": "Default", "version": "25.200.001"},
            ]
        )
        with patch("requests.get", return_value=mock_resp):
            result = client.get_tenant_versions()
        assert len(result) == 1

    def test_sorted_tenant_asc_version_desc(self, client):
        mock_resp = self._mock_entity_response(
            [
                {"name": "Default", "version": "24.200.001"},
                {"name": "Default", "version": "25.200.001"},
                {"name": "Alpha", "version": "25.200.001"},
            ]
        )
        with patch("requests.get", return_value=mock_resp):
            result = client.get_tenant_versions()
        labels = [r["label"] for r in result]
        # Alpha before Default (asc), within Default: 25 before 24 (desc)
        assert labels[0] == "Alpha/25.200.001"
        assert labels[1] == "Default/25.200.001"
        assert labels[2] == "Default/24.200.001"

    def test_missing_tenant_or_version_skipped(self, client):
        mock_resp = self._mock_entity_response(
            [
                {"name": "Default"},  # no version
                {"version": "25.200.001"},  # no name
                {"name": "Good", "version": "1.0.0"},
            ]
        )
        with patch("requests.get", return_value=mock_resp):
            result = client.get_tenant_versions()
        assert len(result) == 1
        assert result[0]["label"] == "Good/1.0.0"

    def test_empty_endpoints_returns_empty(self, client):
        mock_resp = self._mock_entity_response([])
        with patch("requests.get", return_value=mock_resp):
            result = client.get_tenant_versions()
        assert result == []


# ---------------------------------------------------------------------------
# TestGetEndpoints
# ---------------------------------------------------------------------------


class TestGetEndpoints:
    def _make_swagger(self, paths):
        return {"paths": paths}

    def test_collection_get_endpoints_included(self, client):
        swagger = self._make_swagger({"/Customer": {"get": {}}, "/SalesOrder": {"get": {}}})
        with patch.object(client, "get_swagger_data", return_value=swagger):
            result = client.get_endpoints("Default/25.200.001")
        labels = [r["label"] for r in result]
        assert "Customer" in labels
        assert "SalesOrder" in labels

    def test_parameterized_paths_excluded(self, client):
        swagger = self._make_swagger({"/Customer/{id}": {"get": {}}})
        with patch.object(client, "get_swagger_data", return_value=swagger):
            result = client.get_endpoints("Default/25.200.001")
        assert result == []

    def test_non_get_methods_excluded(self, client):
        swagger = self._make_swagger({"/Customer": {"put": {}}, "/Invoice": {"get": {}}})
        with patch.object(client, "get_swagger_data", return_value=swagger):
            result = client.get_endpoints("Default/25.200.001")
        labels = [r["label"] for r in result]
        assert "Customer" not in labels
        assert "Invoice" in labels

    def test_dollar_prefixed_paths_excluded(self, client):
        swagger = self._make_swagger({"/$metadata": {"get": {}}, "/Customer": {"get": {}}})
        with patch.object(client, "get_swagger_data", return_value=swagger):
            result = client.get_endpoints("Default/25.200.001")
        labels = [r["label"] for r in result]
        assert "$metadata" not in labels
        assert "Customer" in labels

    def test_result_sorted_alphabetically(self, client):
        swagger = self._make_swagger({"/Vendor": {"get": {}}, "/Customer": {"get": {}}, "/Invoice": {"get": {}}})
        with patch.object(client, "get_swagger_data", return_value=swagger):
            result = client.get_endpoints("Default/25.200.001")
        labels = [r["label"] for r in result]
        assert labels == sorted(labels)

    def test_result_has_label_and_value(self, client):
        swagger = self._make_swagger({"/Customer": {"get": {}}})
        with patch.object(client, "get_swagger_data", return_value=swagger):
            result = client.get_endpoints("Default/25.200.001")
        assert result[0] == {"label": "Customer", "value": "Customer"}
