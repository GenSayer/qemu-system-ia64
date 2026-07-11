
testblock = declare_dependency(dependencies: [block], sources: 'iothread.c')

tests = {
  'check-block-qdict': [],
  'check-qdict': [],
  'check-qnum': [],
  'check-qstring': [],
  'check-qlist': [],
  'check-qnull': [],
  'check-qobject': [],
  'check-qjson': [],
  'check-json-parser': [],
  'check-qlit': [],
  'test-error-report': [],
  'test-qobject-output-visitor': [testqapi],
  'test-clone-visitor': [testqapi],
  'test-qobject-input-visitor': [testqapi],
  'test-forward-visitor': [testqapi],
  'test-string-input-visitor': [testqapi],
  'test-string-output-visitor': [testqapi],
  'test-visitor-serialization': [testqapi],
  'test-bitmap': [],
  'test-resv-mem': [],
  # all code tested by test-x86-topo is inside topology.h
  'test-x86-topo': [],
  'test-cutils': [],
  'test-div128': [],
  'test-shift128': [],
  'test-mul64': [],
  # all code tested by test-int128 is inside int128.h
  'test-int128': [],
  'rcutorture': [],
  'test-rcu-list': [],
  'test-rcu-simpleq': [],
  'test-rcu-tailq': [],
  'test-rcu-slist': [],
  'test-qdist': [],
  'test-qht': [],
  'test-qtree': [],
  'test-bitops': [],
  'test-bitcnt': [],
  'test-qgraph': ['../qtest/libqos/qgraph.c'],
  'check-qom-interface': [qom],
  'check-qom-proplist': [qom],
  'test-qemu-opts': [],
  'test-keyval': [testqapi],
  'test-logging': [],
  'test-qapi-util': [],
  'test-interval-tree': [],
  'test-fifo': [],
}

if have_system or have_tools
  tests += {
    'test-qmp-event': [testqapi],
  }

  if seccomp.found()
    tests += {'test-seccomp': ['../../system/qemu-seccomp.c', seccomp]}
  endif
endif

if have_block
  tests += {
    'test-coroutine': [testblock],
    'test-aio': [testblock],
    'test-aio-multithread': [testblock],
    'test-throttle': [testblock],
    'test-thread-pool': [testblock],
    'test-hbitmap': [testblock],
    'test-bdrv-drain': [testblock],
    'test-bdrv-graph-mod': [testblock],
    'test-blockjob': [testblock],
    'test-blockjob-txn': [testblock],
    'test-block-backend': [testblock],
    'test-block-iothread': [testblock],
    'test-write-threshold': [testblock],
    'test-crypto-hash': [crypto],
    'test-crypto-hmac': [crypto],
    'test-crypto-cipher': [crypto],
    'test-crypto-akcipher': [crypto],
    'test-crypto-secret': [crypto, keyutils],
    'test-crypto-der': [crypto],
    'test-authz-simple': [authz],
    'test-authz-list': [authz],
    'test-authz-listfile': [authz],
    'test-io-task': [testblock],
    'test-io-channel-socket': ['socket-helpers.c', 'io-channel-helpers.c', io],
    'test-io-channel-file': ['io-channel-helpers.c', io],
    'test-io-channel-command': ['io-channel-helpers.c', io],
    'test-io-channel-buffer': ['io-channel-helpers.c', io],
    'test-io-channel-null': [io],
    'test-crypto-ivgen': [io],
    'test-crypto-afsplit': [io],
    'test-crypto-block': [io],
    'test-timed-average': [],
    'test-uuid': [],
  }
  if gnutls.found() and \
     tasn1.found() and \
     host_os != 'windows'
    tests += {
      'test-crypto-tlscredsx509': ['crypto-tls-x509-helpers.c',
                                   tasn1, crypto, gnutls],
      'test-crypto-tlssession': ['crypto-tls-x509-helpers.c', 'crypto-tls-psk-helpers.c',
                                 tasn1, crypto, gnutls],
      'test-io-channel-tls': ['io-channel-helpers.c', 'crypto-tls-x509-helpers.c',
                              tasn1, io, crypto, gnutls]}
  endif
  if pam.found()
    tests += {'test-authz-pam': [authz]}
  endif
  if host_os != 'windows'
    tests += {
      'test-image-locking': [testblock],
      'test-nested-aio-poll': [],
    }
  endif
  if config_host_data.get('CONFIG_REPLICATION')
    tests += {'test-replication': [testblock]}
  endif
  tests += {'test-crypto-pbkdf': [io]}
endif

if have_system
  tests += {
    'ptimer-test': ['ptimer-test-stubs.c', meson.project_source_root() / 'hw/core/ptimer.c'],
    'test-iov': [],
    'test-opts-visitor': [testqapi],
    'test-xs-node': [qom],
    'test-virtio-dmabuf': [meson.project_source_root() / 'hw/display/virtio-dmabuf.c'],
    'test-qmp-cmds': [testqapi],
    'test-xbzrle': [migration],
    'test-util-sockets': ['socket-helpers.c'],
    'test-base64': [],
    'test-bufferiszero': [],
    'test-smp-parse': [qom, meson.project_source_root() / 'hw/core/machine-smp.c'],
    'test-vmstate': [migration, io],
    'test-yank': ['socket-helpers.c', qom, io, chardev]
  }
  if config_host_data.get('CONFIG_INOTIFY1')
    tests += {'test-util-filemonitor': []}
  endif

  # Some tests: test-char, test-qdev-global-props, and test-qga,
  # are not runnable under TSan due to a known issue.
  # https://github.com/google/sanitizers/issues/1116
  if not get_option('tsan')
    if host_os != 'windows'
        tests += {
          'test-char': ['socket-helpers.c', qom, io, chardev]
        }
    endif

    tests += {
      'test-qdev-global-props': [qom, hwcore]
    }
  endif
  tests += {'test-qdev': [qom, hwcore]}
endif

if have_ga and host_os == 'linux'
  tests += {'test-qga': ['../qtest/libqmp.c']}
  test_deps += {'test-qga': qga}
endif

test_env = environment()
test_env.set('G_TEST_SRCDIR', meson.current_source_dir())
test_env.set('G_TEST_BUILDDIR', meson.current_build_dir())

slow_tests = {
  'test-aio-multithread' : 120,
  'test-bufferiszero': 60,
  'test-crypto-block' : 300,
  'test-crypto-tlscredsx509': 90,
  'test-crypto-tlssession': 90,
  'test-replication': 60,
}

foreach test_name, extra: tests
  src = [test_name + '.c']
  deps = [qemuutil]
  if extra.length() > 0
    # use a sourceset to quickly separate sources and deps
    test_ss = ss.source_set()
    test_ss.add(extra)
    src += test_ss.all_sources()
    deps += test_ss.all_dependencies()
  endif
  exe = executable(test_name, src, genh, dependencies: deps)

  test(test_name, exe,
       depends: test_deps.get(test_name, []),
       env: test_env,
       args: ['--tap', '-k'],
       protocol: 'tap',
       timeout: slow_tests.get(test_name, 30),
       priority: slow_tests.get(test_name, 30),
       suite: ['unit'])
endforeach

if 'ia64-softmmu' in target_dirs
  ia64_decoder_test = executable(
    'test-ia64-decoder',
    [
      'test-ia64-decoder.c',
      meson.project_source_root() / 'target/ia64/decoder.c',
    ],
    include_directories: include_directories('../..'))

  test('test-ia64-decoder', ia64_decoder_test,
       args: ['--tap', '-k'],
       protocol: 'tap',
       timeout: 30,
       suite: ['unit', 'ia64'])

  test('test-ia64-standard-goldens',
       python,
       args: [
         files('test-ia64-standard-goldens.py'),
         meson.project_source_root(),
       ],
       protocol: 'tap',
       timeout: 30,
       suite: ['unit', 'ia64'])

  test('test-ia64-standard-execution',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-standard-execution.py'),
         meson.project_source_root(),
         meson.project_build_root() / 'qemu-system-ia64',
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 600,
       suite: ['unit', 'ia64'])

  test('test-ia64-qemu-tcg',
       python,
       depends: emulators['qemu-system-ia64'],
       args: [
         files('test-ia64-qemu-tcg.py'),
         meson.project_build_root() / 'qemu-system-ia64',
       ],
       protocol: 'tap',
       timeout: 90,
       suite: ['unit', 'ia64'])

  test('test-ia64-qemu-tcg-2',
       python,
       depends: emulators['qemu-system-ia64'],
       args: [
         files('test-ia64-qemu-tcg-2.py'),
         meson.project_build_root() / 'qemu-system-ia64',
       ],
       protocol: 'tap',
       timeout: 600,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-smoke',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-fw-smoke.py'),
         meson.project_build_root() / 'qemu-system-ia64',
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 20,
       suite: ['unit', 'ia64'])

  test('test-ia64-device-inventory',
       python,
       depends: emulators['qemu-system-ia64'],
       args: [
         files('test-ia64-device-inventory.py'),
         meson.project_build_root() / 'qemu-system-ia64',
       ],
       protocol: 'tap',
       timeout: 20,
       suite: ['unit', 'ia64'])

  test('test-ia64-nvram',
       python,
       depends: emulators['qemu-system-ia64'],
       args: [
         files('test-ia64-nvram.py'),
         meson.project_build_root() / 'qemu-system-ia64',
       ],
       protocol: 'tap',
       timeout: 20,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-uefi-services',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-fw-uefi-services.py'),
         meson.project_build_root() / 'qemu-system-ia64',
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 25,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-no-fake-tcg',
       python,
       depends: ia64_firmware_bin,
       args: [
         files('test-ia64-fw-no-fake-tcg.py'),
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 25,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-platform-tables',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-fw-platform-tables.py'),
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 25,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-boot-path',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-fw-boot-path.py'),
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 25,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-ata-block',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-fw-ata-block.py'),
         meson.project_build_root() / 'qemu-system-ia64',
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 20,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-storage',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-fw-storage.py'),
         meson.project_source_root(),
         meson.project_build_root() / 'qemu-system-ia64',
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 75,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-usb-keyboard',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-fw-usb-keyboard.py'),
         meson.project_source_root(),
         meson.project_build_root() / 'qemu-system-ia64',
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 45,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-cdrom-boot-path',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-fw-cdrom-boot-path.py'),
         meson.project_build_root() / 'qemu-system-ia64',
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 20,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-udf-cdrom',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-fw-udf-cdrom.py'),
         meson.project_build_root() / 'qemu-system-ia64',
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 20,
       suite: ['unit', 'ia64'])

  test('test-ia64-os-boot-smoke',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-os-boot-smoke.py'),
         meson.project_build_root() / 'qemu-system-ia64',
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       protocol: 'tap',
       timeout: 30,
       suite: ['unit', 'ia64'])

  test('test-ia64-fw-icount',
       python,
       depends: [emulators['qemu-system-ia64'], ia64_firmware_bin],
       args: [
         files('test-ia64-os-boot-smoke.py'),
         meson.project_build_root() / 'qemu-system-ia64',
         meson.project_build_root() / 'roms/ia64-firmware/ia64-firmware.bin',
       ],
       env: [
         'IA64_BOOT_SMOKE_EXTRA_ARGS=-icount shift=3',
         'IA64_BOOT_SMOKE_MEMORY=128M',
         'IA64_BOOT_SMOKE_SECONDS=15',
         'IA64_BOOT_SMOKE_SIGNATURES=Firmware ready. Attempting disk boot...',
       ],
       protocol: 'tap',
       timeout: 30,
       suite: ['unit', 'ia64'])
endif
