defmodule CairoComplianceTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "compliance_circuit" do
    {:ok, program} = Cairo.load_compliance_circuit()
    {:ok, input} = File.read("./native/cairo_vm/compliance_input.json")

    {_output, trace, memory, public_inputs} =
      Cairo.cairo_vm_runner(
        program,
        input
      )

    # Prove and verify
    {proof, public_input} = Cairo.prove(trace, memory, public_inputs)
    assert true = Cairo.verify(proof, public_input)
  end
end
