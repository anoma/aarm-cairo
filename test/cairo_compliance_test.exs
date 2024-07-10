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
  end
end
