defmodule Cairo.Cairo0 do
  use Rustler,
    otp_app: :cairo,
    crate: :cairo

  @moduledoc """
  Documentation for `Cairo`.
  """

  # When loading a NIF module, dummy clauses for all NIF function are required.
  # NIF dummies usually just error out when called when the NIF is not loaded, as that should never normally happen.
  def cairo0_run_and_prove(_arg1), do: :erlang.nif_error(:nif_not_loaded)
  def cairo_verify(_arg1, _arg2), do: :erlang.nif_error(:nif_not_loaded)
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
  def cairo1_vm_runner(_arg1, _arg2), do: :erlang.nif_error(:nif_not_loaded)
end
