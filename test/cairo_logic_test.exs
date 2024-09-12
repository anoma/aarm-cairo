defmodule CairoResourceLogicTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "resource_logic_circuit" do
    {:ok, program} =
      File.read("./native/cairo_vm/trivial_resource_logic.json")

    {:ok, input} =
      File.read("./native/cairo_vm/trivial_resource_logic_input.json")

    {_output, trace, memory, public_inputs} =
      Cairo.cairo_vm_runner(
        program,
        input
      )

    # Prove and verify
    {proof, public_input} = Cairo.prove(trace, memory, public_inputs)
    assert true = Cairo.verify(proof, public_input)

    _output = Cairo.get_output(public_input)

    # Get program hash
    _program_hash =
      Cairo.get_program_hash(public_input)

    # IO.inspect(program_hash)
    # IO.inspect(program_hash |> Cairo.felt_to_string())
  end
end
