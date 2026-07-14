# SPDX-License-Identifier: GPL-2.0-or-later

if 'ia64-softmmu' not in target_dirs
  subdir_done()
endif

ia64_app_builder = files('apps/build-test-app.sh')
ia64_app_linker_script = files('apps/ia64-test-app.lds')
ia64_app_header = files('apps/ia64-test.h')
ia64_app_sh = find_program('sh')
ia64_functional_test_apps = []

foreach app : ['smoke', 'services', 'tables', 'exitbs', 'storage', 'input']
  app_source = files('apps/' + app + '-app.c')
  app_depend_files = [
    ia64_app_builder,
    ia64_app_linker_script,
    ia64_app_header,
  ]
  if app == 'tables'
    app_depend_files += files('apps/services-app.c')
  endif
  app_target = custom_target(
    'ia64-functional-' + app + '-app',
    output: app + '-app.efi',
    input: app_source,
    depend_files: app_depend_files,
    command: [
      ia64_app_sh,
      ia64_app_builder,
      '@OUTPUT@',
      '@INPUT@',
      ia64_app_linker_script,
    ],
    build_by_default: false,
  )
  ia64_functional_test_apps += app_target
endforeach

alias_target('ia64-functional-apps', ia64_functional_test_apps)

# tests/functional/meson.build adds this target-specific list to the common
# functional-test dependencies.  Keep the applications out of the default
# build, but ensure that both firmware and applications exist before any
# IA-64 functional test starts.
test_ia64_system_deps = ia64_functional_test_apps + [ia64_firmware_bin]

tests_ia64_system_quick = [
  'host',
  'smoke',
  'services',
  'tables',
]

tests_ia64_system_thorough = [
  'storage',
  'input',
]

test_ia64_timeouts = {
  'host': 30,
  'smoke': 120,
  'services': 90,
  'tables': 90,
  'storage': 300,
  'input': 120,
}
