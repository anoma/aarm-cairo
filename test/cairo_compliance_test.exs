defmodule CairoComplianceTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "compliance_circuit" do
    {:ok, program} = File.read("./native/cairo_vm/compliance.json")
    {:ok, input} = File.read("./native/cairo_vm/compliance_input.json")

    {_output, trace, memory, public_inputs} =
      Cairo.cairo_vm_runner(
        program,
        input
      )

    # Prove and verify
    {proof, public_input} = Cairo.prove(trace, memory, public_inputs)
    assert true = Cairo.verify(proof, public_input)

    Cairo.get_compliance_output(public_input)

    # Get program hash
    _program_hash =
      Cairo.get_program_hash(public_input) |> Cairo.felt_to_string()

    # IO.inspect(program_hash)
  end
end
