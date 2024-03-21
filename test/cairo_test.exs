defmodule NifTest do
  use ExUnit.Case
  doctest Cairo.Cairo0
  alias Cairo.Cairo0

  test "cairo_api_test" do
    {:ok, program} = File.read("./native/cairo/fibonacci_5.json")
    {proof, public_input} = Cairo0.cairo_run_and_prove(program)
    assert true = Cairo0.cairo_verify(proof, public_input)
  end
end
