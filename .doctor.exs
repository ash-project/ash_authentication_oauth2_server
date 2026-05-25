# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/team-alembic/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

%Doctor.Config{
  ignore_modules: [
    ~r/^Inspect\./,
    ~r/.Plug$/,
    ~r/^Example/,
    ~r/^Oauth2ServerTest/,
    AshAuthentication.Oauth2Server
  ],
  ignore_paths: [],
  min_module_doc_coverage: 40,
  min_module_spec_coverage: 0,
  min_overall_doc_coverage: 50,
  min_overall_spec_coverage: 0,
  min_overall_moduledoc_coverage: 100,
  exception_moduledoc_required: true,
  raise: false,
  reporter: Doctor.Reporters.Full,
  struct_type_spec_required: true,
  umbrella: false
}
