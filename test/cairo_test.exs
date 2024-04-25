defmodule NifTest do
  use ExUnit.Case

  doctest Cairo.Cairo0
  doctest Cairo.Cairo1

  alias Cairo.Cairo0
  alias Cairo.Cairo1

  test "cairo0_api_test" do
    {:ok, program} = File.read("./native/cairo/fibonacci_5.json")
    {proof, public_input} = Cairo0.cairo0_run_and_prove(program)
    assert true = Cairo.verify(proof, public_input)
  end

  test "cairo1_api_test" do
    {:ok, program} = File.read("./native/cairo1/cairo.json")
    {:ok, input} = File.read("./native/cairo1/cairo_input.json")

    {output, trace, memory} =
      Cairo1.cairo_vm_runner(
        program,
        input
      )

    assert "17\n" = output

    # Prove and verify
    {proof, public_input} = Cairo.prove(trace, memory)
    assert true = Cairo.verify(proof, public_input)
  end
end
