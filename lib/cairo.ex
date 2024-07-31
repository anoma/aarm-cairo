defmodule Cairo do
  @moduledoc """
  Documentation for `Cairo`.
  """

  @doc """
  Hello world.

  ## Examples

      iex> Cairo.hello()
      :world

  """
  def hello do
    :world
  end

  @spec cairo_vm_runner(binary(), binary()) ::
  {:ok, {binary(), [byte()], [byte()], binary()}}  | {:error, term()}
  defdelegate cairo_vm_runner(program_content, program_input),
    to: Cairo.CairoVM,
    as: :cairo_vm_runner

  @spec prove(list(byte()), list(byte()), binary()) ::
    {:ok, {list(byte()), list(byte())}} | {:error, term()}
  defdelegate prove(trace, memory, public_input),
    to: Cairo.CairoProver,
    as: :cairo_prove

  @spec verify(list(byte()), list(byte())) ::
    {:ok, {boolean()}} | {:error, term()}
  defdelegate verify(proof, pub_input),
    to: Cairo.CairoProver,
    as: :cairo_verify

  @spec get_output(list(byte())) ::
    {:ok, {any()}} | {:error, term()}
  defdelegate get_output(pub_input),
    to: Cairo.CairoProver,
    as: :cairo_get_output

  @spec sign(list(list(byte())), list(list(byte()))) ::
    {:ok, {list(byte())}} | {:error, term()}
  defdelegate sign(private_key_segments, messages),
    to: Cairo.CairoProver,
    as: :cairo_binding_sig_sign

  @spec sig_verify(list(list(byte())), list(list(byte())), list(byte())) ::
  {:ok, {boolean()}} | {:error, term()}
  defdelegate sig_verify(pub_key_segments, messages, signature),
    to: Cairo.CairoProver,
    as: :cairo_binding_sig_verify

  @spec random_felt() ::
    {:ok, {list(byte())}} | {:error, term()}
  defdelegate random_felt(),
    to: Cairo.CairoProver,
    as: :cairo_random_felt

  @spec get_public_key(list(byte())) ::
    {:ok, {list(byte())}} | {:error, term()}
  defdelegate get_public_key(priv_key),
    to: Cairo.CairoProver,
    as: :cairo_get_binding_sig_public_key

  @spec poseidon_single(list(byte())) ::
    {:ok, {list(byte())}} | {:error, term()}
  defdelegate poseidon_single(input),
    to: Cairo.CairoProver,
    as: :poseidon_single

  @spec poseidon(list(byte()), list(byte())) ::
    {:ok, {list(byte())}} | {:error, term()}
  defdelegate poseidon(x, y),
    to: Cairo.CairoProver,
    as: :poseidon

  @spec poseidon_many(list(list(byte()))) ::
    {:ok, {list(byte())}} | {:error, term()}
  defdelegate poseidon_many(inputs),
    to: Cairo.CairoProver,
    as: :poseidon_many

  @spec get_program_hash(list(byte())) ::
    {:ok, {list(byte())}} | {:error, term()}
  defdelegate get_program_hash(pub_input),
    to: Cairo.CairoProver,
    as: :program_hash
end
