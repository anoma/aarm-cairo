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
  end
end
