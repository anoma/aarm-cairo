defmodule NifTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "cairo_encryption_test" do
    # encryption circuit test
    {:ok, program} = File.read("./juvix/encryption.json")
    {:ok, input} = File.read("./juvix/encryption_input.json")

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
    plaintext = Cairo.decrypt(expected_cipher, sk)

    assert plaintext == expected_plaintext

    # decryption: wrong sk
    assert {:error, "Invalid DH key"} =
             Cairo.decrypt(expected_cipher, felt_bytes_0)
  end

  test "cairo_encryption_invalid_input_test" do
    felt_bytes = List.duplicate(1, 32)
    plaintext = List.duplicate(felt_bytes, 10)
    pk = Cairo.get_public_key(felt_bytes)
    invalid_pk = List.duplicate(1, 64)
    sk = felt_bytes
    nonce = felt_bytes

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.encrypt([[]], pk, sk, nonce)

    assert {:error, "Invalid Point"} = Cairo.encrypt(plaintext, [], sk, nonce)

    assert {:error, "Invalid Point"} =
             Cairo.encrypt(plaintext, invalid_pk, sk, nonce)

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.encrypt(plaintext, pk, [], nonce)

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.encrypt(plaintext, pk, sk, [])

    cipher = List.duplicate(felt_bytes, 14)

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.decrypt([[]], sk)

    assert {:error, "The length of ciphertext is not correct"} =
             Cairo.decrypt([felt_bytes], sk)

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.decrypt(cipher, [])
  end
end
