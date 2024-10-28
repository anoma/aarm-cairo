defmodule NifTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "cairo_encryption_test" do
    # encryption circuit test
    {:ok, program} = File.read("./native/cairo_vm/encryption.json")
    {:ok, input} = File.read("./native/cairo_vm/encryption_input.json")

    {_output, trace, memory, vm_public_input} =
      Cairo.cairo_vm_runner(
        program,
        input
      )

    # Prove and verify
    {proof, public_input} = Cairo.prove(trace, memory, vm_public_input)
    assert true = Cairo.verify(proof, public_input)

    felt_bytes_0 = :binary.bin_to_list(<<0::256>>)
    felt_bytes_1 = :binary.bin_to_list(<<1::256>>)

    pk = Cairo.get_public_key(felt_bytes_1)
    sk = felt_bytes_1
    nonce = felt_bytes_1

    expected_plaintext =
      [felt_bytes_1, felt_bytes_0, felt_bytes_1] ++
        List.duplicate(felt_bytes_0, 7)

    # out-of-circuit encryption
    expected_cipher = Cairo.encrypt(expected_plaintext, pk, sk, nonce)

    assert Cairo.get_output(public_input) == expected_cipher

    # decryption
    plaintext = Cairo.decrypt(expected_cipher, felt_bytes_1)

    assert plaintext == expected_plaintext
  end
end
