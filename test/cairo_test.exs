defmodule NifTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "cairo_api_test" do
    {:ok, program} = File.read("./native/cairo_vm/cairo.json")
    {:ok, input} = File.read("./native/cairo_vm/cairo_input.json")

    {output, trace, memory, vm_public_input} =
      Cairo.cairo_vm_runner(
        program,
        input
      )

    assert "17\n" = output

    # Prove and verify
    {proof, public_input} = Cairo.prove(trace, memory, vm_public_input)
    assert true = Cairo.verify(proof, public_input)

    # Get program hash
    _program_hash =
      Cairo.get_program_hash(public_input) |> Cairo.felt_to_string()

    # IO.inspect(program_hash)
  end
end
