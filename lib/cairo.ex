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
          {binary(), [byte()], [byte()], [byte()]} | {:error, term()}
  defdelegate cairo_vm_runner(program_content, program_input),
    to: Cairo.CairoVM,
    as: :cairo_vm_runner

  @spec prove([byte()], [byte()], [byte()]) ::
          {[byte()], [byte()]} | {:error, term()}
  defdelegate prove(trace, memory, public_input),
    to: Cairo.CairoProver,
    as: :cairo_prove

  @spec verify(list(byte()), list(byte())) ::
          boolean() | {:error, term()}
  defdelegate verify(proof, pub_input),
    to: Cairo.CairoProver,
    as: :cairo_verify

  @spec get_output(list(byte())) ::
          any() | {:error, term()}
  defdelegate get_output(pub_input),
    to: Cairo.CairoProver,
    as: :cairo_get_output

  @spec sign(list(byte()), list(list(byte()))) ::
          list(byte()) | {:error, term()}
  defdelegate sign(private_key_segments, messages),
    to: Cairo.CairoProver,
    as: :cairo_binding_sig_sign

  @spec sig_verify(list(list(byte())), list(list(byte())), list(byte())) ::
          boolean() | {:error, term()}
  defdelegate sig_verify(pub_key_segments, messages, signature),
    to: Cairo.CairoProver,
    as: :cairo_binding_sig_verify

  @spec random_felt() ::
          list(byte()) | {:error, term()}
  defdelegate random_felt(),
    to: Cairo.CairoProver,
    as: :cairo_random_felt

  @spec get_public_key(list(byte())) ::
          list(byte()) | {:error, term()}
  defdelegate get_public_key(priv_key),
    to: Cairo.CairoProver,
    as: :cairo_get_binding_sig_public_key

  @spec poseidon_single(list(byte())) ::
          list(byte()) | {:error, term()}
  defdelegate poseidon_single(input),
    to: Cairo.CairoProver,
    as: :poseidon_single

  @spec poseidon(list(byte()), list(byte())) ::
          list(byte()) | {:error, term()}
  defdelegate poseidon(x, y),
    to: Cairo.CairoProver,
    as: :poseidon

  @spec poseidon_many(list(list(byte()))) ::
          list(byte()) | {:error, term()}
  defdelegate poseidon_many(inputs),
    to: Cairo.CairoProver,
    as: :poseidon_many

  @spec get_program_hash(list(byte())) ::
          list(byte()) | {:error, term()}
  defdelegate get_program_hash(pub_input),
    to: Cairo.CairoProver,
    as: :program_hash

  @spec felt_to_string(list(byte())) :: binary()
  defdelegate felt_to_string(felt),
    to: Cairo.CairoProver,
    as: :cairo_felt_to_string

  @spec generate_compliance_input_json(
          list(byte()),
          list(byte()),
          list(list(byte())),
          integer(),
          list(byte()),
          list(byte()),
          list(byte())
        ) ::
          binary()
  defdelegate generate_compliance_input_json(
                input_resource,
                output_resource,
                path,
                position,
                input_nf_key,
                eph_root,
                rcv
              ),
              to: Cairo.CairoProver,
              as: :cairo_generate_compliance_input_json
end
