defmodule Cairo.Cairo0 do
  use Rustler,
    otp_app: :cairo,
    crate: :cairo

  @moduledoc """
  Documentation for `Cairo`.
  """

  # When loading a NIF module, dummy clauses for all NIF function are required.
  # NIF dummies usually just error out when called when the NIF is not loaded, as that should never normally happen.
  @spec cairo0_run_and_prove(binary()) :: {list(byte()), list(byte())}
  @spec cairo_prove(list(byte()), list(byte())) ::
          {list(byte()), list(byte())}
  @spec cairo_verify(list(byte()), list(byte())) :: boolean()

  def cairo0_run_and_prove(_program), do: :erlang.nif_error(:nif_not_loaded)
  def cairo_prove(_trace, _memory), do: :erlang.nif_error(:nif_not_loaded)
  def cairo_verify(_proof, _pub_input), do: :erlang.nif_error(:nif_not_loaded)
end

defmodule Cairo.Cairo1 do
  use Rustler,
    otp_app: :cairo,
    crate: :cairo1

  @moduledoc """
  Documentation for `Cairo1`.
  """

  # When loading a NIF module, dummy clauses for all NIF function are required.
  # NIF dummies usually just error out when called when the NIF is not loaded, as that should never normally happen.
  @spec cairo_vm_runner(binary(), binary()) :: {list(byte()), list(byte())}

  def cairo_vm_runner(_program_content, _program_inputs),
    do: :erlang.nif_error(:nif_not_loaded)
end
