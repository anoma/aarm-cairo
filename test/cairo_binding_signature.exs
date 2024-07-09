defmodule BindingSignatureTest do
  use ExUnit.Case

  doctest Cairo.CairoProver

  test "cairo_binding_signature_test" do
    priv_keys = [Cairo.random_felt(), Cairo.random_felt()]
    pub_keys = priv_keys |> Enum.map(fn x -> Cairo.get_public_key(x) end)
    msg = [Cairo.random_felt(), Cairo.random_felt()]

    # Sign and verify
    signature = Cairo.sign(priv_keys, msg)
    assert true = Cairo.sig_verify(pub_keys, msg, signature)
  end
end
