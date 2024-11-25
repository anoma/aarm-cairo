{:ok, program} = File.read("./juvix/compliance.json")
{:ok, input} = File.read("./juvix/compliance_input.json")

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
    "compliance circuit: run cairo vm" => fn ->
      Cairo.cairo_vm_runner(program, input)
    end
  },
  warmup: 1,
  time: 10
)

Benchee.run(
  %{
    "compliance circuit: prover" => fn ->
      Cairo.prove(trace, memory, public_inputs)
    end
  },
  warmup: 1,
  time: 10
)

Benchee.run(
  %{
    "compliance circuit: verifier" => fn ->
      Cairo.verify(proof, public_input)
    end
  },
  warmup: 1,
  time: 10
)
