defmodule BindingSignatureTest do
  use ExUnit.Case

  doctest Cairo.CairoProver

  test "cairo_binding_signature_test" do
    priv_key_1 = Cairo.random_felt()
    priv_key_2 = Cairo.random_felt()

    pub_keys =
      [priv_key_1, priv_key_2]
      |> Enum.map(fn x -> Cairo.get_public_key(x) end)

    msg = [Cairo.random_felt(), Cairo.random_felt()]

    # Sign and verify
    signature = (priv_key_1 ++ priv_key_2) |> Cairo.sign(msg)
    assert true = Cairo.sig_verify(pub_keys, msg, signature)

    # Wrong pub_key
    wrong_pub_key = Cairo.get_public_key(priv_key_1)
    refute Cairo.sig_verify([wrong_pub_key], msg, signature)

    # Wrong msg
    refute Cairo.sig_verify(pub_keys, [List.duplicate(1, 32)], signature)

    # Wrong signature
    refute Cairo.sig_verify(pub_keys, msg, List.duplicate(1, 64))
  end

  test "cairo_binding_signature_invalid_input_test" do
    priv_key_1 = Cairo.random_felt()
    priv_key_2 = Cairo.random_felt()

    pub_keys =
      [priv_key_1, priv_key_2]
      |> Enum.map(fn x -> Cairo.get_public_key(x) end)

    msg = [Cairo.random_felt(), Cairo.random_felt()]

    assert {:error, "Invalid inputs"} = Cairo.sign([], msg)

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.sign(priv_key_1, [[]])

    assert {:error, "Invalid inputs"} = Cairo.sign([1, 2], msg)

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.sign(priv_key_1, [[1, 2]])

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.get_public_key([])

    signature = (priv_key_1 ++ priv_key_2) |> Cairo.sign(msg)
    assert {:error, "Invalid Point"} = Cairo.sig_verify([[]], msg, signature)

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.sig_verify(pub_keys, [[]], signature)

    assert {:error, "Invalid signature: 64 bytes needed"} =
             Cairo.sig_verify(pub_keys, msg, [])

    assert {:error, "Invalid Point"} = Cairo.sig_verify([[1]], msg, signature)

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.sig_verify(pub_keys, [[1]], signature)

    assert {:error, "Invalid signature: 64 bytes needed"} =
             Cairo.sig_verify(pub_keys, msg, [1])
  end
end
