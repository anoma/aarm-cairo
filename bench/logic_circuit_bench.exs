{:ok, program} = File.read("./native/cairo_vm/trivial_resource_logic.json")

{:ok, input} =
  File.read("./native/cairo_vm/trivial_resource_logic_input.json")

{_output, trace, memory, public_inputs} =
  Cairo.cairo_vm_runner(
    program,
    input
  )

# Prove and verify
{proof, public_input} = Cairo.prove(trace, memory, public_inputs)
# Cairo.verify(proof, public_input)

Benchee.run(
  %{
    "logic circuit: run cairo vm" => fn ->
      Cairo.cairo_vm_runner(program, input)
    end
  },
  warmup: 1,
  time: 10
)

Benchee.run(
  %{
    "logic circuit: prover" => fn ->
      Cairo.prove(trace, memory, public_inputs)
    end
  },
  warmup: 1,
  time: 10
)

Benchee.run(
  %{
    "logic circuit: verifier" => fn ->
      Cairo.verify(proof, public_input)
    end
  },
  warmup: 1,
  time: 10
)
