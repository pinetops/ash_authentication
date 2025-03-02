defmodule AshAuthentication.Strategy.OAuth2.Plug do
  @moduledoc """
  Handlers for incoming OAuth2 HTTP requests.
  """

  alias Ash.Error.Framework.AssumptionFailed
  alias AshAuthentication.{Errors, Info, Strategy, Strategy.OAuth2}
  alias Assent.HTTPAdapter.Finch
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]
  import Plug.Conn

  @raw_config_attrs [
    :auth_method,
    :client_authentication_method,
    :id_token_signed_response_alg,
    :id_token_ttl_seconds,
    :openid_configuration_uri
  ]

  @doc """
  Perform the request phase of OAuth2.

  Builds a redirection URL based on the provider configuration and redirects the
  user to that endpoint.

  If the request is coming from a subdomain, it will be redirected to the base domain.
  """
  @spec request(Conn.t(), OAuth2.t()) :: Conn.t()
  # sobelow_skip ["XSS.SendResp"]
  def request(conn, strategy) do
    # Check if we need to redirect from subdomain to base domain
    case should_redirect_to_base_domain?(conn, strategy) do
      {:redirect, base_url, full_domain} ->
        # Preserve query parameters in the redirect and add domain parameter
        query_params =
          conn.query_params
          |> Map.put("domain", full_domain)
          |> URI.encode_query()

        redirect_url = "#{base_url}#{conn.request_path}?#{query_params}"

        conn
        |> put_resp_header("location", redirect_url)
        |> send_resp(:found, "Redirecting to base domain")

      :no_redirect ->
        # Store the subdomain in the session if domain parameter is present
        conn =
          case conn.params["domain"] do
            nil ->
              conn

            domain when is_binary(domain) ->
              if domain do
                with {:ok, session_key} <- session_key(strategy) do
                  put_session(conn, "#{session_key}_redirect_domain", domain)
                else
                  _ -> conn
                end
              else
                conn
              end

            _ ->
              conn
          end

        with {:ok, config} <- config_for(strategy),
             {:ok, config} <- maybe_add_nonce(config, strategy),
             {:ok, session_key} <- session_key(strategy),
             {:ok, %{session_params: session_params, url: url}} <-
               strategy.assent_strategy.authorize_url(config) do
          conn
          |> put_session(session_key, session_params)
          |> put_resp_header("location", url)
          |> send_resp(:found, "Redirecting to #{strategy.name}")
        else
          {:error, reason} -> store_authentication_result(conn, {:error, reason})
        end
    end
  end

  # Determines if we should redirect from a subdomain to the base domain
  defp should_redirect_to_base_domain?(conn, strategy) do
    host = conn.host

    # Get tenant_base_domain from strategy if provided
    case fetch_tenant_base_domain(strategy) do
      {:ok, tenant_base_domain} ->
        # If the current host is not the tenant base domain, redirect
        if host != tenant_base_domain do
          base_url = build_url_from_host(conn, tenant_base_domain)
          {:redirect, base_url, host}
        else
          :no_redirect
        end

      :error ->
        :no_redirect
    end
  end

  # Fetches the tenant_base_domain from strategy
  defp fetch_tenant_base_domain(strategy) do
    with %OAuth2{} <- strategy,
         {:ok, domain} when is_binary(domain) and domain != "" <-
           fetch_secret(strategy, :tenant_base_domain) do
      {:ok, domain}
    else
      _ -> :error
    end
  end

  # Builds a URL from connection and host
  defp build_url_from_host(conn, host) do
    scheme = conn.scheme |> to_string()
    port_part = if conn.port in [80, 443], do: "", else: ":#{conn.port}"
    "#{scheme}://#{host}#{port_part}"
  end

  @doc """
  Perform the callback phase of OAuth2.

  Responds to a user being redirected back from the remote authentication
  provider, and validates the passed options, ultimately registering or
  signing-in a user if the authentication was successful.

  If the authentication was initiated from a subdomain, it will redirect back
  to that subdomain after successful authentication.
  """
  @spec callback(Conn.t(), OAuth2.t()) :: Conn.t()
  def callback(conn, strategy) do
    with {:ok, session_key} <- session_key(strategy),
         {:ok, config} <- config_for(strategy),
         session_params when is_map(session_params) <- get_session(conn, session_key),
         conn <- delete_session(conn, session_key),
         config <- Keyword.put(config, :session_params, session_params),
         {:ok, %{user: user, token: token}} <-
           strategy.assent_strategy.callback(config, conn.params),
         action_opts <- action_opts(conn),
         {:ok, user} <-
           register_or_sign_in_user(
             strategy,
             %{user_info: user, oauth_tokens: token},
             action_opts
           ) do
      # Store the authentication result in the conn
      conn = store_authentication_result(conn, {:ok, user})

      # Check if we need to redirect back to a subdomain
      case get_session(conn, "#{session_key}_redirect_domain") do
        nil ->
          # No subdomain redirect needed
          conn

        redirect_domain when is_binary(redirect_domain) ->
          # Store any necessary data in the session for retrieval after redirect
          # This could include user ID, tokens, or other authentication data
          conn =
            conn
            |> put_session("authenticated_user_id", user.id)
            |> put_session(
              "authentication_timestamp",
              DateTime.utc_now() |> DateTime.to_iso8601()
            )
            |> delete_session("#{session_key}_redirect_domain")

          # Build the redirect URL to the original subdomain
          scheme = conn.scheme |> to_string()
          port_part = if conn.port in [80, 443], do: "", else: ":#{conn.port}"
          redirect_url = "#{scheme}://#{redirect_domain}#{port_part}#{conn.request_path}"

          # Redirect back to the original subdomain
          conn
          |> put_resp_header("location", redirect_url)
          |> send_resp(:found, "Redirecting to #{redirect_domain}")
      end
    else
      nil ->
        store_authentication_result(conn, {:error, nil})

      {:error, reason} ->
        store_authentication_result(conn, {:error, reason})
    end
  end

  defp action_opts(conn) do
    [actor: get_actor(conn), tenant: get_tenant(conn), context: get_context(conn) || %{}]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end

  defp config_for(strategy) do
    config =
      strategy
      |> Map.take(@raw_config_attrs)

    with {:ok, config} <- add_secret_value(config, strategy, :base_url),
         {:ok, config} <- add_secret_value(config, strategy, :authorize_url, !!strategy.base_url),
         {:ok, config} <- add_secret_value(config, strategy, :client_id, !!strategy.base_url),
         {:ok, config} <- add_secret_value(config, strategy, :client_secret, !!strategy.base_url),
         {:ok, config} <- add_secret_value(config, strategy, :token_url, !!strategy.base_url),
         {:ok, config} <-
           add_secret_value(config, strategy, :code_verifier, !!strategy.code_verifier),
         {:ok, config} <-
           add_secret_value(
             config,
             strategy,
             :authorization_params,
             !!strategy.authorization_params
           ),
         {:ok, config} <-
           add_secret_value(
             config,
             strategy,
             :openid_configuration,
             !strategy.openid_configuration
           ),
         {:ok, config} <-
           add_secret_value(
             config,
             strategy,
             :team_id,
             strategy.assent_strategy != Assent.Strategy.Apple
           ),
         {:ok, config} <-
           add_secret_value(
             config,
             strategy,
             :private_key_id,
             strategy.assent_strategy != Assent.Strategy.Apple
           ),
         {:ok, config} <-
           add_secret_value(
             config,
             strategy,
             :private_key_path,
             strategy.assent_strategy != Assent.Strategy.Apple
           ),
         {:ok, config} <-
           add_secret_value(config, strategy, :trusted_audiences, true),
         {:ok, config} <- add_http_adapter(config),
         {:ok, config} <-
           add_secret_value(
             config,
             strategy,
             :user_url,
             !!strategy.authorize_url || !!strategy.base_url
           ),
         {:ok, redirect_uri} <- build_redirect_uri(strategy),
         {:ok, jwt_algorithm} <-
           Info.authentication_tokens_signing_algorithm(strategy.resource) do
      config =
        config
        |> Map.put(:jwt_algorithm, jwt_algorithm)
        |> Map.put(:redirect_uri, redirect_uri)
        |> Map.update(:client_authentication_method, nil, &to_string/1)
        |> Enum.reject(&is_nil(elem(&1, 1)))

      {:ok, config}
    end
  end

  defp register_or_sign_in_user(strategy, params, opts) when strategy.registration_enabled?,
    do: Strategy.action(strategy, :register, params, opts)

  defp register_or_sign_in_user(strategy, params, opts),
    do: Strategy.action(strategy, :sign_in, params, opts)

  # We need to temporarily store some information about the request in the
  # session so that we can verify that there hasn't been a CSRF-related attack.
  defp session_key(strategy) do
    case Info.authentication_subject_name(strategy.resource) do
      {:ok, subject_name} ->
        {:ok, "#{subject_name}/#{strategy.name}"}

      :error ->
        {:error,
         AssumptionFailed.exception(
           message: "Resource `#{inspect(strategy.resource)}` has no subject name"
         )}
    end
  end

  # With OpenID Connect we can pass a "nonce" value into the assent strategy
  # which is an additional way to ensure that the callback matches the request.
  defp maybe_add_nonce(config, strategy) do
    case fetch_secret(strategy, :nonce) do
      {:ok, value} when is_binary(value) and byte_size(value) > 0 ->
        {:ok, Keyword.put(config, :nonce, value)}

      {:ok, false} ->
        {:ok, config}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp add_secret_value(config, strategy, secret_name, allow_nil? \\ false) do
    case fetch_secret(strategy, secret_name) do
      {:ok, nil} when allow_nil? ->
        {:ok, config}

      {:ok, nil} ->
        path = [:authentication, :strategies, strategy.name, secret_name]
        {:error, Errors.MissingSecret.exception(path: path, resource: strategy.resource)}

      {:ok, value} when is_binary(value) and byte_size(value) > 0 ->
        {:ok, Map.put(config, secret_name, value)}

      {:ok, list} when is_list(list) ->
        {:ok, Map.put(config, secret_name, list)}

      {:ok, map} when is_map(map) ->
        {:ok, Map.put(config, secret_name, map)}

      {:ok, boolean} when is_boolean(boolean) ->
        {:ok, Map.put(config, secret_name, boolean)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_secret(strategy, secret_name) do
    path = [:authentication, :strategies, strategy.name, secret_name]

    with {:ok, {secret_module, secret_opts}} <- Map.fetch(strategy, secret_name),
         {:ok, secret} when is_binary(secret) and byte_size(secret) > 0 <-
           secret_module.secret_for(path, strategy.resource, secret_opts) do
      {:ok, secret}
    else
      {:ok, secret} ->
        {:ok, secret}

      _ ->
        {:error, Errors.MissingSecret.exception(path: path, resource: strategy.resource)}
    end
  end

  defp build_redirect_uri(strategy) do
    with {:ok, subject_name} <- Info.authentication_subject_name(strategy.resource),
         {:ok, redirect_uri} <- fetch_secret(strategy, :redirect_uri),
         {:ok, uri} <- URI.new(redirect_uri) do
      suffix = Path.join([to_string(subject_name), to_string(strategy.name), "callback"])
      # Don't append the path if the secret ends with the path already
      path =
        if String.ends_with?(uri.path, suffix) do
          uri.path
        else
          Path.join([uri.path || "/", suffix])
        end

      {:ok, to_string(%URI{uri | path: path})}
    else
      :error ->
        {:error,
         AssumptionFailed.exception(
           message: "Resource `#{inspect(strategy.resource)}` has no subject name"
         )}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp add_http_adapter(config) do
    http_adapter =
      Application.get_env(
        :ash_authentication,
        :http_adapter,
        {Finch, supervisor: AshAuthentication.Finch}
      )

    {:ok, Map.put(config, :http_adapter, http_adapter)}
  end
end
