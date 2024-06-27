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
          {binary(), [byte()], [byte()], binary()}
  defdelegate cairo_vm_runner(program_content, program_input),
    to: Cairo.CairoVM,
    as: :cairo_vm_runner

  @spec prove(list(byte()), list(byte()), binary()) ::
          {list(byte()), list(byte())}
  defdelegate prove(trace, memory, public_input),
    to: Cairo.CairoProver,
    as: :cairo_prove

  @spec verify(list(byte()), list(byte())) :: boolean()
  defdelegate verify(proof, pub_input),
    to: Cairo.CairoProver,
    as: :cairo_verify
end
