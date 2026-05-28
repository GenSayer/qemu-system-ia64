IA-64 standard-derived golden tests
===================================

The IA-64 standard-derived golden tests check the externally visible
architectural and firmware contracts listed in ``docs/ia64/*.csv``.  The CSV
files are an inventory of implemented items.  They are not an oracle for
expected behavior, and their ``source_refs`` fields must not be used to derive
golden results.  Golden expectations are derived from the applicable IA-64,
PAL, SAL, EFI, UEFI, and ACPI specifications, while the tests themselves use
only repository-local metadata and generated test programs.

The tests are split into two layers:

``tests/unit/test-ia64-standard-goldens.py``
  Checks that every CSV row is covered by the standard-derived catalog and that
  the repository-local standard-derived metadata is present.

``tests/unit/test-ia64-standard-execution.py``
  Runs executable golden tests against ``qemu-system-ia64`` and the IA-64
  firmware image.  It imports the hand-encoded IA-64 programs in
  ``tests/unit/test-ia64-qemu-tcg.py`` and
  ``tests/unit/test-ia64-qemu-tcg-2.py``, runs the PAL golden programs, boots
  the firmware for SAL/EFI/ACPI service contracts, and validates ACPI, EFI
  configuration, and SAL tables from guest memory.

Adding an IA-64 instruction
---------------------------

1. Read the relevant instruction page in the IA-64 SDM.  Use the SDM encoding,
   slot-unit restrictions, predicate behavior,
   architectural pseudocode, exceptions, and side effects as the source of
   truth.

2. Add or update the inventory row in
   ``docs/ia64/implemented-instructions.csv``.  Choose the narrowest existing
   ``category``.  Add a new category only when the instruction is not covered
   by the existing architectural groups.

3. Add an executable golden program to one of the IA-64 QEMU TCG test files:

   * use ``tests/unit/test-ia64-qemu-tcg.py`` for ordinary instruction decode,
     execution, branch, integer, predicate, memory, floating-point, and simple
     exception behavior;
   * use ``tests/unit/test-ia64-qemu-tcg-2.py`` when the test needs PAL entry,
     translation, interruption, NaT, advanced-load, or other system-state
     helpers already defined there.

   Encode the instruction from the SDM bit fields.  Do not copy encodings,
   constants, or expected values from ``target/ia64/``.  The program should
   establish input architectural state, execute the instruction, and assert the
   complete visible result through register state, memory state, interruption
   state, PAL return registers, or firmware-visible state.

4. Cover more than the nominal path when the standard defines distinct
   behavior.  Common cases are false predicates, writes to immutable registers,
   sign extension, immediate boundary values, slot restrictions, reserved
   encodings, NaT consumption or propagation, alignment faults, TLB or
   translation side effects, ordering completers, FPSR status flags, and
   floating-point special values.

5. Bind the new execution test in
   ``test_csv_rows_are_bound_to_execution()`` in
   ``tests/unit/test-ia64-standard-execution.py``.  If the instruction uses an
   existing category, add the new test name to that category when it covers a
   new behavior class.  If a new category was added to the CSV, add that
   category with at least one executable test name.

Adding a PAL function
---------------------

1. Read the PAL specification.  Derive the function ID, accepted argument
   ranges, return status values, result registers, required side effects, and
   reserved-argument behavior from the PAL document.

2. Add or update the row in ``docs/ia64/implemented-pal.csv``.

3. Add a ``pal_*`` executable golden in
   ``tests/unit/test-ia64-qemu-tcg-2.py``.  For static PAL calls, set ``gr28``
   to the PAL function ID and ``gr29`` through ``gr31`` to the PAL arguments.
   For stacked PAL calls, make a normal stacked call with ``gr28`` and ``in0``
   both holding the PAL function ID and ``in1`` through ``in3`` holding the
   arguments.  Enter the PAL procedure and assert ``gr8`` through ``gr11`` and
   any architectural side effects.  Add separate cases for invalid arguments,
   reserved arguments, unsupported functions, and boundary values whenever the
   PAL specification distinguishes them.

4. Make sure the CSV row maps to the new ``pal_*`` test in
   ``test_csv_rows_are_bound_to_execution()``.  Prefer a direct name match such
   as ``PAL_CACHE_INFO`` to ``pal_cache_info_*``.  Add an explicit mapping only
   when the standard behavior is intentionally covered by a broader PAL test.

Adding SAL, EFI, or ACPI functionality
--------------------------------------

SAL, EFI, and ACPI rows are validated through the IA-64 firmware boot contract
and through binary table checks, not through translator-only injected bundles.

For a new SAL function:

1. Read the SAL specification and add the inventory row in
   ``docs/ia64/implemented-sal.csv``.

2. Add a firmware-visible contract check that exercises the SAL call with
   standard arguments and all required error paths.  The check must print a
   stable success token only after validating return status, result registers,
   and side effects.

3. Add that token to ``test_sal_efi_firmware_boot_contract()`` in
   ``tests/unit/test-ia64-standard-execution.py``.

For a new EFI service or protocol:

1. Read the UEFI or EFI specification and add the inventory row in
   ``docs/ia64/implemented-efi.csv``.

2. Add a firmware boot test for the service or protocol.  Check the documented
   table position, argument validation, return status, and side effects on the
   handle database, event queue, memory map, variables, console, block I/O,
   PCI I/O, or runtime mapping state.

3. Add the firmware success token to
   ``test_sal_efi_firmware_boot_contract()``.  If the service changes runtime
   table layout or EFI configuration tables, also extend
   ``test_acpi_efi_sal_binary_tables()``.

For a new ACPI table or ACPI-visible field:

1. Read ACPI 2.0 and the IA-64 ACPI supplement and add the inventory row in
   ``docs/ia64/implemented-acpi.csv``.

2. Extend ``test_acpi_efi_sal_binary_tables()`` to read the relevant runtime
   symbol from the firmware image and validate the binary table.  At minimum,
   check signature, length, revision, checksum, required pointers, required
   descriptor order, IA-64 specific fields, address-space descriptors, flags,
   and reserved fields that the standard requires to be zero.

3. Add or update the firmware boot success token when the new ACPI contract is
   also announced by firmware output.

Updating the coverage catalog
-----------------------------

Whenever a CSV file gains or loses rows, update
``tests/unit/test-ia64-standard-goldens.py``:

* update ``EXPECTED_COUNTS``;
* add any small repository-local standard-derived metadata file to
  ``STANDARD_FILES``;
* add category, area, or function assertions when the new row introduces a new
  standard behavior class;
* keep expected behavior anchored to the applicable public specifications.  Do
  not cite ``target/``, ``hw/``, ``roms/``, or existing tests as the authority
  for expected behavior.

Then update ``tests/unit/test-ia64-standard-execution.py``:

* add or map executable tests for new IA-64 or PAL rows;
* update the fixed SAL, EFI, or ACPI row counts;
* extend firmware boot-token checks or binary table validation for new SAL,
  EFI, or ACPI rows.

Running the tests
-----------------

After adding or changing an IA-64 standard-derived test, run the focused tests
from the build tree:

.. code-block:: console

  $ meson test -C build test-ia64-standard-goldens
  $ meson test -C build test-ia64-standard-execution

For faster iteration on the execution harness, run it directly:

.. code-block:: console

  $ PYTHONUNBUFFERED=1 python3 tests/unit/test-ia64-standard-execution.py \
      "$PWD" build/qemu-system-ia64 \
      build/roms/ia64-firmware/ia64-firmware.bin

The execution test is expected to run many QEMU instances and may take several
minutes.  A new CSV row is not complete until both standard-derived tests pass.
