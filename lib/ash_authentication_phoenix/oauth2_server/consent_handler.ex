# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Phoenix.Oauth2Server.ConsentHandler do
  @moduledoc """
  Extension boundary for application-specific OAuth consent requirements.

  The consent router continues to own validated and sealed OAuth request data,
  session rotation, error redirects, and authorization-code issuance. A handler
  may require consent beyond the stored scope grant, add safe presentation
  assigns, and persist application-specific grant data alongside the OAuth
  consent by calling the public authorization-server API.

  Request parameter maps can contain untrusted browser input and protocol
  credentials. Handlers must validate application fields independently and must
  never return raw request values in presentation assigns.
  """

  alias AshAuthentication.Oauth2Server.Authorize

  @typedoc "Validated authorization request produced by `Authorize.validate_request/3`."
  @type validated :: Authorize.validated()

  @typedoc "Options propagated by the router, currently containing an optional tenant."
  @type opts :: keyword()

  @doc """
  Decides whether an existing grant is sufficient to skip the consent screen.

  Applications that add a narrower grant dimension should combine that check
  with `Authorize.consented?/5`, rather than replacing the OAuth scope check.
  """
  @callback consented?(module(), Ash.Resource.record(), validated(), opts()) :: boolean()

  @doc """
  Returns safe application assigns for the consent view.

  The router merges these beneath its validated core assigns, so a handler
  cannot replace the form action, sealed consent request, client identity,
  redirect URI, scope, state, resource, or CSRF token.
  """
  @callback prepare(module(), Ash.Resource.record(), validated(), map(), opts()) ::
              {:ok, map()} | {:error, map()}

  @doc """
  Persists consent after the user approves the sealed request.

  Successful handlers return `{:ok, value}` and the router issues the
  authorization code. A validation failure returns `{:error, safe_assigns}`;
  the same sealed request is rendered again with status 422 and no code is
  issued. The handler owns any transaction needed to make the OAuth consent and
  application-specific grants atomic.
  """
  @callback grant(module(), Ash.Resource.record(), validated(), map(), opts()) ::
              {:ok, term()} | {:error, map()}
end
