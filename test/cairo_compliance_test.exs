defmodule CairoComplianceTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "compliance_circuit" do
    {:ok, program} = File.read("./native/cairo_vm/compliance.json")
    # {:ok, input} = File.read("./native/cairo_vm/compliance_input.json")
    input_resource = List.duplicate(1, 225)
    output_resource = List.duplicate(2, 225)
    path = List.duplicate(Cairo.random_felt(), 32)
    input_nf_key = Cairo.random_felt()
    eph_root = Cairo.random_felt()
    rcv = Cairo.random_felt()

    input =
      Cairo.generate_compliance_input_json(
        input_resource,
        output_resource,
        path,
        0,
        input_nf_key,
        eph_root,
        rcv
      )

    {_output, trace, memory, public_inputs} =
      Cairo.cairo_vm_runner(
        program,
        input
      )

    # Prove and verify
    {proof, public_input} = Cairo.prove(trace, memory, public_inputs)
    assert true = Cairo.verify(proof, public_input)

    Cairo.get_output(public_input)

    # Get program hash
    _program_hash =
      Cairo.get_program_hash(public_input) |> Cairo.felt_to_string()

    # IO.inspect(program_hash)
  end
end
