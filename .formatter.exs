# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/team-alembic/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

spark_locals_without_parens = [
  consumed_grace: 1,
  expunge_expired_action_name: 1,
  expunge_interval: 1,
  revoked_grace: 1,
  rotated_grace: 1
]

# The dev app and its dependencies exist only in the dev environment.
{dev_deps, dev_inputs} =
  if Mix.env() == :dev,
    do: {[:ash_ai, :ash_graphql], ["dev/**/*.{ex,exs}"]},
    else: {[], []}

[
  import_deps: [:ash, :ash_authentication, :phoenix] ++ dev_deps,
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"] ++ dev_inputs,
  locals_without_parens: spark_locals_without_parens,
  export: [
    locals_without_parens: spark_locals_without_parens
  ]
]
