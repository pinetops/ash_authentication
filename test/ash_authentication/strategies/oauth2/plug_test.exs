defmodule AshAuthentication.Strategy.OAuth2.PlugTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Conn
  import Plug.Test

  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}

  describe "request/2" do
    test "it builds the redirect url and redirects the user" do
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
    end

    test "it redirects from subdomain.myapp.com to myapp.com with subdomain as query param" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      # Create a connection with a subdomain host
      assert conn =
               :get
               |> conn("/", %{})
               |> Map.put(:host, "tenant.myapp.com")
               |> Map.put(:port, 4000)
               |> SessionPipeline.call([])
               |> Plug.request(strategy)

      assert conn.status == 302
      assert {"location", location} = Enum.find(conn.resp_headers, &(elem(&1, 0) == "location"))

      # Check that the location is now pointing to myapp.com (not subdomain)
      uri = URI.parse(location)
      assert uri.host == "myapp.com"
      assert uri.port == 4000

      # Check that the subdomain was added as a query parameter
      query_params = URI.decode_query(uri.query || "")
      assert Map.has_key?(query_params, "domain")
      assert query_params["domain"] == "tenant.myapp.com"

      # Check that the subdomain was stored in the session for the callback
      assert get_session(conn, "user/oauth2_redirect_subdomain") == "tenant"
    end
  end
end
