defmodule NifTest do
  use ExUnit.Case

  doctest Cairo.Cairo0
  doctest Cairo.Cairo1

  alias Cairo.Cairo0
  alias Cairo.Cairo1

  test "cairo0_api_test" do
    {:ok, program} = File.read("./native/cairo/fibonacci_5.json")
    {proof, public_input} = Cairo0.cairo0_run_and_prove(program)
    assert true = Cairo0.cairo_verify(proof, public_input)
  end

  test "cairo1_api_test" do
    {trace, memory} =
      Cairo1.cairo1_vm_runner(
        "./native/cairo1/sierra_program",
        "2 [1 2 3 4] 0 [9 8]"
      )

    # Prove and verify
    {proof, public_input} = Cairo0.cairo_prove(trace, memory)
    assert true = Cairo0.cairo_verify(proof, public_input)
  end
end
