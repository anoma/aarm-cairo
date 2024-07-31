defmodule Cairo.CairoProver do
  use Rustler,
    otp_app: :cairo,
    crate: :cairo_prover

  @moduledoc """
  Provides NIF functions for Cairo proof generation, verification, and related cryptographic operations.
  """

  @typedoc "Result type for NIF functions that can return errors"
  @type nif_result(t) :: {:ok, t} | {:error, term()}

  @spec cairo_prove(list(byte()), list(byte()), list(byte())) :: nif_result({list(byte()), list(byte())})
  def cairo_prove(_trace, _memory, _public_input), do: error()

  @spec cairo_verify(list(byte()), list(byte())) :: nif_result(boolean())
  def cairo_verify(_proof, _pubinput), do: error()

  @spec cairo_get_output(list(byte())) :: nif_result(list(list(byte())))
  def cairo_get_output(_public_input), do: error()

  @spec cairo_binding_sig_sign(list(list(byte())), list(list(byte()))) :: nif_result(list(byte()))
  def cairo_binding_sig_sign(_private_key_segments, _messages), do: error()

  @spec cairo_binding_sig_verify(list(list(byte())), list(list(byte())), list(byte())) :: nif_result(boolean())
  def cairo_binding_sig_verify(_pub_key_segments, _messages, _signature), do: error()

  @spec cairo_random_felt() :: nif_result(list(byte()))
  def cairo_random_felt(), do: error()

  @spec cairo_get_binding_sig_public_key(list(byte())) :: nif_result(list(byte()))
  def cairo_get_binding_sig_public_key(_priv_key), do: error()

  @spec poseidon_single(list(byte())) :: nif_result(list(byte()))
  def poseidon_single(_input), do: error()

  @spec poseidon(list(byte()), list(byte())) :: nif_result(list(byte()))
  def poseidon(_x, _y), do: error()

  @spec poseidon_many(list(list(byte()))) :: nif_result(list(byte()))
  def poseidon_many(_inputs), do: error()

  @spec program_hash(list(byte())) :: nif_result(list(byte()))
  def program_hash(_public_inputs), do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)
end

defmodule Cairo.CairoVM do
  use Rustler,
    otp_app: :cairo,
    crate: :cairo_vm

  @moduledoc """
  Documentation for `CairoVM`.
  """
  @typedoc "Result type for NIF functions that can return errors"
  @type nif_result(t) :: {:ok, t} | {:error, term()}
  
  # When loading a NIF module, dummy clauses for all NIF function are required.
  # NIF dummies usually just error out when called when the NIF is not loaded, as that should never normally happen.
  @spec cairo_vm_runner(binary(), binary()) ::
          nif_result({binary(), list(byte()), list(byte()), binary()})
  def cairo_vm_runner(_program_content, _program_inputs),
    do: :erlang.nif_error(:nif_not_loaded)
end
