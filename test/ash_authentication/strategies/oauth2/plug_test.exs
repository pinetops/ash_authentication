defmodule AshAuthentication.Strategy.OAuth2.PlugTest do
  @moduledoc false
  # Changed to async: false for Mimic
  use DataCase, async: false
  import Plug.Conn
  import Plug.Test

  # Setup Mimic for the modules we want to mock
  use Mimic

  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}

  def follow_redirect(conn, pipeline, opts \\ []) do
    callback = Keyword.get(opts, :callback)

    if conn.status == 302 do
      # Extract redirect location
      {"location", location} = Enum.find(conn.resp_headers, &(elem(&1, 0) == "location"))
      uri = URI.parse(location)

      # Extract query params
      query_params = URI.decode_query(uri.query || "")

      # Create a new conn to the redirect location
      new_conn =
        :get
        |> conn(uri.path, query_params)
        |> Map.put(:host, uri.host || conn.host)
        |> Map.put(:port, uri.port || conn.port)

      # Copy cookies from original conn
      cookies = conn.cookies

      new_conn =
        Enum.reduce(cookies, new_conn, fn {key, value}, acc ->
          put_resp_cookie(acc, key, value)
        end)

      # Copy session data
      session = conn.private[:plug_session] || %{}

      # Initialize the session before copying data
      new_conn = init_test_session(new_conn, %{})

      new_conn =
        Enum.reduce(session, new_conn, fn {key, value}, acc ->
          put_session(acc, key, value)
        end)

      # Process through pipeline
      new_conn = pipeline.call(new_conn, [])

      # Apply callback if provided
      if callback, do: callback.(new_conn), else: new_conn
    else
      conn
    end
  end

  describe "request/2" do
    import Mimic

    setup :verify_on_exit!

    test "it builds the redirect url and redirects the user, then handles the callback" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      assert conn =
               :get
               |> conn("/", %{})
               |> Map.put(:host, "myapp.com")
               |> SessionPipeline.call([])
               |> Plug.request(strategy)

      assert conn.status == 302
      assert {"location", location} = Enum.find(conn.resp_headers, &(elem(&1, 0) == "location"))
      assert String.starts_with?(location, "https://example.com/authorize?")
      session = get_session(conn, "user/oauth2")
      assert session.state =~ ~r/.+/

      # Extract state from the redirect URL for the callback
      uri = URI.parse(location)
      query_params = URI.decode_query(uri.query || "")
      state = query_params["state"]

      # Mock the Assent callback function to return a successful result
      expect(Assent.Strategy.OAuth2, :callback, fn _config,
                                                   %{
                                                     "code" => "test_auth_code",
                                                     "state" => ^state
                                                   } ->
        {:ok,
         %{
           user: %{
             "sub" => "12345",
             "name" => "Test User",
             "email" => "test@example.com"
           },
           token: %{
             "access_token" => "mock_access_token",
             "token_type" => "bearer",
             "expires_in" => 3600
           }
         }}
      end)

      # Simulate the OAuth provider redirecting back to our callback endpoint
      # with an authorization code and the state parameter
      callback_conn =
        :get
        |> conn("/auth/oauth2/callback", %{"code" => "test_auth_code", "state" => state})
        |> Map.put(:host, "myapp.com")
        # Initialize the session
        |> init_test_session(%{})
        |> put_session("user/oauth2", session)
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # Verify the callback response
      # The OAuth2.Plug.callback function stores the authentication result in conn.private
      # but doesn't set a redirect status - that would be handled by a router
      assert {:ok, user} = callback_conn.private.authentication_result
      assert user.username == %Ash.CiString{string: "test@example.com"}
    end

    test "it redirects from subdomain.myapp.com to myapp.com with subdomain as query param" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      # Create a connection with a subdomain host
      subdomain_conn =
        :get
        |> conn("/", %{})
        |> Map.put(:host, "tenant.myapp.com")
        |> Map.put(:port, 4000)
        |> SessionPipeline.call([])
        |> Plug.request(strategy)

      # Verify subdomain redirect
      assert subdomain_conn.status == 302

      {"location", location} =
        Enum.find(subdomain_conn.resp_headers, &(elem(&1, 0) == "location"))

      uri = URI.parse(location)
      assert uri.host == "myapp.com"
      assert uri.port == 4000

      # Check that the subdomain was added as a query parameter
      query_params = URI.decode_query(uri.query || "")
      assert Map.has_key?(query_params, "domain")
      assert query_params["domain"] == "tenant.myapp.com"

      # Follow the redirect to the base domain
      base_domain_conn =
        follow_redirect(subdomain_conn, SessionPipeline, callback: &Plug.request(&1, strategy))

      # Check that this redirects to the OAuth provider
      assert base_domain_conn.status == 302

      {"location", oauth_location} =
        Enum.find(base_domain_conn.resp_headers, &(elem(&1, 0) == "location"))

      assert String.starts_with?(oauth_location, "https://example.com/authorize?")

      # Check that the session contains the OAuth state
      session = get_session(base_domain_conn, "user/oauth2")
      assert session.state =~ ~r/.+/

      # Check that the subdomain was stored in the session for the callback
      assert get_session(base_domain_conn, "user/oauth2_redirect_domain") == "tenant.myapp.com"

      # Extract state from the redirect URL for the callback
      uri = URI.parse(oauth_location)
      query_params = URI.decode_query(uri.query || "")
      state = query_params["state"]

      # Mock the Assent callback function to return a successful result
      expect(Assent.Strategy.OAuth2, :callback, fn _config,
                                                   %{
                                                     "code" => "test_auth_code",
                                                     "state" => ^state
                                                   } ->
        {:ok,
         %{
           user: %{
             "sub" => "12345",
             "name" => "Test User",
             "email" => "test@example.com"
           },
           token: %{
             "access_token" => "mock_access_token",
             "token_type" => "bearer",
             "expires_in" => 3600
           }
         }}
      end)

      callback_conn =
        :get
        |> conn("/auth/oauth2/callback", %{"code" => "test_auth_code", "state" => state})
        |> Map.put(:host, "myapp.com")
        # Initialize the session
        |> init_test_session(%{})
        |> put_session("user/oauth2", session)
        |> put_session("user/oauth2_redirect_domain", "tenant.myapp.com")
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # Verify the callback response
      # The callback should set a redirect to the original subdomain
      assert callback_conn.status == 302

      {"location", redirect_location} =
        Enum.find(callback_conn.resp_headers, &(elem(&1, 0) == "location"))

      redirect_uri = URI.parse(redirect_location)
      assert redirect_uri.host == "tenant.myapp.com"

      # Follow the redirect back to the tenant subdomain
      tenant_conn = follow_redirect(callback_conn, SessionPipeline)

      # Verify we're now on the tenant subdomain
      assert tenant_conn.host == "tenant.myapp.com"

      # Verify that the authentication result was properly transferred
      # Check for the authenticated user ID in the session
      assert get_session(tenant_conn, "authenticated_user_id") != nil

      # Check for the authentication timestamp
      assert get_session(tenant_conn, "authentication_timestamp") != nil

      # Verify that the authentication result is stored in the connection
      assert {:ok, user} = callback_conn.private.authentication_result
      assert user.username == %Ash.CiString{string: "test@example.com"}
    end
  end
end
