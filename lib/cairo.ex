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

  @spec prove(list(byte()), list(byte())) :: {list(byte()), list(byte())}
  defdelegate prove(trace, memory), to: Cairo.Cairo0, as: :cairo_prove

  @spec verify(list(byte()), list(byte())) :: boolean()
  defdelegate verify(proof, pub_input), to: Cairo.Cairo0, as: :cairo_verify
end
